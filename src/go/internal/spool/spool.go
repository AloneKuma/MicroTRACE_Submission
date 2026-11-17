// Package spool is the shipper's bounded, crash-safe store of records not yet
// acknowledged by the receiver (spec/kafka/ship-contract.md). One Lane holds
// one lane's records in sequence order. Sequences are assigned here, before
// anything can drop a record.
//
// On disk: <dir>/log holds records [seq u64][len u32][crc32c u32][data], and
// <dir>/meta.json holds the discard point and next sequence. A torn or corrupt
// tail found on reopen is cut off.
package spool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const headerSize = 16

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Meta is what the spool keeps about a record besides its bytes.
type Meta struct {
	Source int32
	// Event time in Unix nanoseconds; 0 means unknown.
	TimeNs int64
}

// Entry is one stored record.
type Entry struct {
	Seq  uint64
	Data []byte
	Meta
}

// Range is a run of sequences dropped by the spool, with the sources of the
// dropped records and the earliest and latest known event time among them
// (0 when no dropped record had one).
type Range struct {
	First, Last  uint64
	Sources      []int32
	FromNs, ToNs int64
}

// Add widens r's time range to include ns (0 is ignored).
func (r *Range) Add(ns int64) {
	if ns == 0 {
		return
	}
	if r.FromNs == 0 || ns < r.FromNs {
		r.FromNs = ns
	}
	if ns > r.ToNs {
		r.ToNs = ns
	}
}

type entry struct {
	Entry
	fileSize int64
}

type meta struct {
	Discarded uint64 `json:"discarded"`
	Next      uint64 `json:"next"`
}

// Lane is one lane's spool. Safe for concurrent use.
type Lane struct {
	mu        sync.Mutex
	dir       string
	f         *os.File
	entries   []entry
	bytes     int64
	max       int64
	next      uint64
	discarded uint64
	synced    uint64
	fileSize  int64
	deadBytes int64
	meta      func(data []byte) (Meta, error)
}

// Open opens or creates the spool in dir, holding at most maxBytes of record
// data. meta extracts a record's source and event time when the spool is
// reopened; nil means they are unknown after a restart.
func Open(dir string, maxBytes int64, metaOf func(data []byte) (Meta, error)) (*Lane, error) {
	if maxBytes <= 0 {
		return nil, errors.New("maxBytes must be positive")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Lane{dir: dir, max: maxBytes, next: 1, meta: metaOf}
	if raw, err := os.ReadFile(filepath.Join(dir, "meta.json")); err == nil {
		var m meta
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("meta.json: %w", err)
		}
		l.discarded, l.next = m.Discarded, m.Next
		if l.next == 0 {
			l.next = 1
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := l.load(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	l.synced = l.next - 1
	return l, nil
}

// load reads the log, keeps unacknowledged records and cuts a bad tail.
func (l *Lane) load() error {
	path := filepath.Join(l.dir, "log")
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	var good int64
	var last uint64
	hdr := make([]byte, headerSize)
	for {
		if _, err := io.ReadFull(f, hdr); err != nil {
			break
		}
		seq := binary.BigEndian.Uint64(hdr[0:8])
		n := binary.BigEndian.Uint32(hdr[8:12])
		sum := binary.BigEndian.Uint32(hdr[12:16])
		data := make([]byte, n)
		if _, err := io.ReadFull(f, data); err != nil {
			break
		}
		if crc32.Checksum(append(append([]byte{}, hdr[0:12]...), data...), castagnoli) != sum {
			break
		}
		if last != 0 && seq != last+1 {
			break
		}
		size := int64(headerSize) + int64(n)
		if seq <= l.discarded {
			l.deadBytes += size
		} else {
			var m Meta
			if l.meta != nil {
				m, _ = l.meta(data)
			}
			l.entries = append(l.entries, entry{Entry{Seq: seq, Data: data, Meta: m}, size})
			l.bytes += int64(n)
		}
		good += size
		last = seq
	}
	l.fileSize = good
	if last+1 > l.next {
		l.next = last + 1
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() != good {
		if err := os.Truncate(path, good); err != nil {
			return err
		}
	}
	return nil
}

// Append stores one record. build receives the assigned sequence and returns
// the record bytes and its metadata. If the spool is full, the oldest
// unacknowledged records are dropped and returned as a Range.
func (l *Lane) Append(build func(seq uint64) ([]byte, Meta, error)) (uint64, *Range, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	seq := l.next
	data, m, err := build(seq)
	if err != nil {
		return 0, nil, err
	}
	n := int64(len(data))
	if n > l.max {
		return 0, nil, fmt.Errorf("record of %d bytes exceeds spool size %d", n, l.max)
	}
	var dropped *Range
	for l.bytes+n > l.max && len(l.entries) > 0 {
		e := l.entries[0]
		if dropped == nil {
			dropped = &Range{First: e.Seq}
		}
		dropped.Last = e.Seq
		dropped.Sources = addSource(dropped.Sources, e.Source)
		dropped.Add(e.TimeNs)
		l.removeFirst()
		l.discarded = e.Seq
	}
	rec := make([]byte, headerSize+len(data))
	binary.BigEndian.PutUint64(rec[0:8], seq)
	binary.BigEndian.PutUint32(rec[8:12], uint32(len(data)))
	copy(rec[headerSize:], data)
	binary.BigEndian.PutUint32(rec[12:16], crc32.Checksum(append(append([]byte{}, rec[0:12]...), data...), castagnoli))
	if _, err := l.f.Write(rec); err != nil {
		return 0, nil, err
	}
	l.fileSize += int64(len(rec))
	l.entries = append(l.entries, entry{Entry{Seq: seq, Data: data, Meta: m}, int64(len(rec))})
	l.bytes += n
	l.next++
	return seq, dropped, nil
}

// Sync makes every appended record durable and records the discard point.
// Only synced records are returned by Read.
func (l *Lane) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.synced = l.next - 1
	if err := l.writeMeta(); err != nil {
		return err
	}
	if l.deadBytes > 8<<20 && l.deadBytes*2 > l.fileSize {
		return l.compact()
	}
	return nil
}

// Read returns up to max synced records starting at seq from.
func (l *Lane) Read(from uint64, max int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 || from > l.synced {
		return nil
	}
	first := l.entries[0].Seq
	if from < first {
		from = first
	}
	i := int(from - first)
	var out []Entry
	for ; i < len(l.entries) && len(out) < max && l.entries[i].Seq <= l.synced; i++ {
		out = append(out, l.entries[i].Entry)
	}
	return out
}

// First is the lowest sequence still held, or Next when the spool is empty.
func (l *Lane) First() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return l.next
	}
	return l.entries[0].Seq
}

// Next is the sequence the next Append will assign.
func (l *Lane) Next() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.next
}

// Synced is the highest sequence made durable by Sync.
func (l *Lane) Synced() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.synced
}

// TruncateThrough removes every record with sequence <= seq (acknowledged).
func (l *Lane) TruncateThrough(seq uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for len(l.entries) > 0 && l.entries[0].Seq <= seq {
		l.removeFirst()
	}
	if seq > l.discarded {
		l.discarded = seq
	}
}

// Bytes is the record data currently held.
func (l *Lane) Bytes() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bytes
}

// Close syncs and closes the spool.
func (l *Lane) Close() error {
	if err := l.Sync(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

func (l *Lane) removeFirst() {
	e := l.entries[0]
	l.entries = l.entries[1:]
	l.bytes -= int64(len(e.Data))
	l.deadBytes += e.fileSize
}

func (l *Lane) writeMeta() error {
	raw, _ := json.Marshal(meta{Discarded: l.discarded, Next: l.next})
	return atomicWrite(filepath.Join(l.dir, "meta.json"), raw)
}

// compact rewrites the log with only the records still held.
func (l *Lane) compact() error {
	tmp := filepath.Join(l.dir, "log.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	var size int64
	for _, e := range l.entries {
		rec := make([]byte, headerSize+len(e.Data))
		binary.BigEndian.PutUint64(rec[0:8], e.Seq)
		binary.BigEndian.PutUint32(rec[8:12], uint32(len(e.Data)))
		copy(rec[headerSize:], e.Data)
		binary.BigEndian.PutUint32(rec[12:16], crc32.Checksum(append(append([]byte{}, rec[0:12]...), e.Data...), castagnoli))
		if _, err := f.Write(rec); err != nil {
			f.Close()
			return err
		}
		size += int64(len(rec))
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	// Windows cannot rename over an open file: close the old log first there
	// (Exp. 3 local dry run only; Linux keeps the old order).
	if runtime.GOOS == "windows" {
		l.f.Close()
	}
	if err := os.Rename(tmp, filepath.Join(l.dir, "log")); err != nil {
		return err
	}
	if err := syncDir(l.dir); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		l.f.Close()
	}
	nf, err := os.OpenFile(filepath.Join(l.dir, "log"), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	l.f, l.fileSize, l.deadBytes = nf, size, 0
	return nil
}

func addSource(list []int32, s int32) []int32 {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// atomicWrite replaces path with data durably (write, fsync, rename, fsync dir).
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	// Windows refuses to flush a directory handle ("Access is denied"); there
	// the rename is already durable in the NTFS journal. Only the Exp. 3 local
	// dry run ships from Windows; Linux behaviour is unchanged.
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
