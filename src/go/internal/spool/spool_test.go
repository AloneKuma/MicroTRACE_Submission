package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func appendN(t *testing.T, l *Lane, n int, size int, src int32) []uint64 {
	t.Helper()
	var seqs []uint64
	for i := 0; i < n; i++ {
		seq, _, err := l.Append(func(seq uint64) ([]byte, Meta, error) {
			b := make([]byte, size)
			copy(b, fmt.Sprintf("rec-%d", seq))
			return b, Meta{Source: src, TimeNs: int64(seq) * 1e9}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, seq)
	}
	return seqs
}

func TestSequencesStartAtOneAndAreContiguous(t *testing.T) {
	l, err := Open(t.TempDir(), 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	seqs := appendN(t, l, 5, 10, 1)
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("seq %d = %d", i, s)
		}
	}
}

func TestReadReturnsOnlySynced(t *testing.T) {
	l, _ := Open(t.TempDir(), 1<<20, nil)
	appendN(t, l, 3, 10, 1)
	if got := l.Read(1, 10); len(got) != 0 {
		t.Fatalf("read %d unsynced records", len(got))
	}
	if err := l.Sync(); err != nil {
		t.Fatal(err)
	}
	got := l.Read(2, 10)
	if len(got) != 2 || got[0].Seq != 2 || got[1].Seq != 3 {
		t.Fatalf("got %+v", got)
	}
}

func TestTruncateAndReopenKeepsOnlyUnacked(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 1<<20, nil)
	appendN(t, l, 10, 10, 1)
	l.TruncateThrough(4)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l2, err := Open(dir, 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l2.First() != 5 || l2.Next() != 11 {
		t.Fatalf("first %d next %d", l2.First(), l2.Next())
	}
	got := l2.Read(1, 100)
	if len(got) != 6 || got[0].Seq != 5 || string(got[0].Data[:5]) != "rec-5" {
		t.Fatalf("got %d records, first %+v", len(got), got[0])
	}
	seq, _, _ := l2.Append(func(seq uint64) ([]byte, Meta, error) { return []byte("x"), Meta{Source: 1}, nil })
	if seq != 11 {
		t.Fatalf("next seq after reopen = %d", seq)
	}
}

func TestTornTailIsCut(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 1<<20, nil)
	appendN(t, l, 3, 10, 1)
	l.Close()
	f, _ := os.OpenFile(filepath.Join(dir, "log"), os.O_WRONLY|os.O_APPEND, 0o600)
	f.Write([]byte{0, 0, 0, 0, 0, 0, 0, 4, 0, 0}) // half a header
	f.Close()
	l2, err := Open(dir, 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Next() != 4 || len(l2.Read(1, 10)) != 3 {
		t.Fatalf("next %d", l2.Next())
	}
}

func TestOverflowDropsOldestAndReportsExactRange(t *testing.T) {
	l, _ := Open(t.TempDir(), 100, nil) // room for 10 records of 10 bytes
	appendN(t, l, 10, 10, 1)
	var dropped []*Range
	for i := 0; i < 3; i++ {
		_, r, err := l.Append(func(seq uint64) ([]byte, Meta, error) { return make([]byte, 10), Meta{Source: 2}, nil })
		if err != nil {
			t.Fatal(err)
		}
		dropped = append(dropped, r)
	}
	for i, r := range dropped {
		want := uint64(i + 1)
		if r == nil || r.First != want || r.Last != want || len(r.Sources) != 1 || r.Sources[0] != 1 ||
			r.FromNs != int64(want)*1e9 || r.ToNs != int64(want)*1e9 {
			t.Fatalf("drop %d = %+v", i, r)
		}
	}
	if l.First() != 4 || l.Bytes() != 100 {
		t.Fatalf("first %d bytes %d", l.First(), l.Bytes())
	}
}

func TestOversizedRecordRejected(t *testing.T) {
	l, _ := Open(t.TempDir(), 10, nil)
	if _, _, err := l.Append(func(uint64) ([]byte, Meta, error) { return make([]byte, 11), Meta{Source: 1}, nil }); err == nil {
		t.Fatal("oversized record accepted")
	}
}

func TestSourceDecoderOnReopen(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 1<<20, nil)
	appendN(t, l, 2, 10, 3)
	l.Close()
	l2, _ := Open(dir, 1<<20, func([]byte) (Meta, error) { return Meta{Source: 7, TimeNs: 42}, nil })
	if got := l2.Read(1, 10); got[0].Source != 7 || got[0].TimeNs != 42 {
		t.Fatalf("meta %+v", got[0].Meta)
	}
}

func TestDroppedRangeSpansEventTimes(t *testing.T) {
	l, _ := Open(t.TempDir(), 30, nil) // room for 3 records of 10 bytes
	times := []int64{5e9, 0, 2e9}      // 0: record without an event time
	for _, ns := range times {
		ns := ns
		if _, _, err := l.Append(func(uint64) ([]byte, Meta, error) { return make([]byte, 10), Meta{Source: 1, TimeNs: ns}, nil }); err != nil {
			t.Fatal(err)
		}
	}
	_, r, err := l.Append(func(uint64) ([]byte, Meta, error) { return make([]byte, 30), Meta{Source: 1}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if r == nil || r.First != 1 || r.Last != 3 || r.FromNs != 2e9 || r.ToNs != 5e9 {
		t.Fatalf("dropped %+v", r)
	}
}
