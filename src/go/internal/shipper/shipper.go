// Package shipper is the node side of the shipping contract
// (spec/kafka/ship-contract.md): it sequences records, keeps them in a
// bounded on-disk spool until the receiver acknowledges them, and reports any
// it could not deliver.
package shipper

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/spool"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/wire"
)

// Transit sees every batch after sequencing and before it is sent, and
// returns the messages to send in its place, in sequence order (none drops
// it). The fault injector (internal/faults) plugs in here.
type Transit interface {
	Batch(lane pb.Lane, b *pb.Batch) []*pb.NodeMessage
}

// Config configures a Shipper.
type Config struct {
	NodeID, BootID, Instance string
	Addr                     string
	TLS                      *tls.Config
	SpoolDir                 string
	SpoolMaxBytes            int64
	// BatchMax caps items per NORMAL batch; PRIORITY batches hold one item.
	BatchMax int
	// Linger is how long a NORMAL lane waits to fill a batch.
	Linger time.Duration
	// Window caps unacknowledged items in flight per lane.
	Window int
	// Retransmit resends a lane from its last ack when no ack or nack has
	// arrived for this long while items are in flight. Must exceed the
	// receiver's Kafka write timeout.
	Retransmit time.Duration
	Transit    Transit
	Logf       func(string, ...any)
}

// RejectedError means the receiver refused the stream; retrying cannot help.
type RejectedError struct{ Reason string }

func (r *RejectedError) Error() string { return "rejected by receiver: " + r.Reason }

// GapReport is one range reported to the receiver as not delivered.
type GapReport struct {
	First   uint64      `json:"first"`
	Last    uint64      `json:"last"`
	Sources []pb.Source `json:"sources"`
	Detail  string      `json:"detail"`
}

// LaneStats summarises one lane.
type LaneStats struct {
	Appended     uint64      `json:"appended"`
	NextSeq      uint64      `json:"next_seq"`
	AckedThrough uint64      `json:"acked_through"`
	Gaps         []GapReport `json:"gaps"`
}

type lane struct {
	id           pb.Lane
	sp           *spool.Lane
	cursor       uint64
	acked        uint64
	dropped      []spool.Range
	wm           *timestamppb.Timestamp
	wmDirty      bool
	appended     uint64
	reports      []GapReport
	pendingSince time.Time
	lastProgress time.Time
}

// Shipper sends records for one (node, boot).
type Shipper struct {
	cfg       Config
	mu        sync.Mutex
	lanes     map[pb.Lane]*lane
	inputDone bool
	wake      chan struct{}
}

// New opens the spools under SpoolDir/<boot_id>/<lane>.
func New(cfg Config) (*Shipper, error) {
	if !wire.ValidID(cfg.NodeID) || !wire.ValidID(cfg.BootID) {
		return nil, errors.New("invalid node or boot ID")
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.BatchMax <= 0 {
		cfg.BatchMax = 500
	}
	if cfg.Window <= 0 {
		cfg.Window = 4096
	}
	if cfg.Retransmit <= 0 {
		cfg.Retransmit = 30 * time.Second
	}
	if cfg.SpoolMaxBytes <= 0 {
		cfg.SpoolMaxBytes = 256 << 20
	}
	s := &Shipper{cfg: cfg, lanes: map[pb.Lane]*lane{}, wake: make(chan struct{}, 1)}
	for _, l := range wire.Lanes {
		sp, err := spool.Open(filepath.Join(cfg.SpoolDir, cfg.BootID, l.String()), cfg.SpoolMaxBytes, itemMeta)
		if err != nil {
			return nil, err
		}
		s.lanes[l] = &lane{id: l, sp: sp, cursor: sp.First(), acked: sp.First() - 1}
	}
	return s, nil
}

func itemMeta(data []byte) (spool.Meta, error) {
	var it pb.ShipItem
	if err := proto.Unmarshal(data, &it); err != nil {
		return spool.Meta{}, err
	}
	return metaOf(&it), nil
}

// metaOf is what the spool keeps about an item: its source and event time.
func metaOf(it *pb.ShipItem) spool.Meta {
	return spool.Meta{Source: int32(wire.RecordSource(it.GetEnvelope())),
		TimeNs: wire.TimeNs(wire.EventTime(it.GetEnvelope()))}
}

func (s *Shipper) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Submit sequences and spools one item. Call Sync to make it sendable.
func (s *Shipper) Submit(laneID pb.Lane, it *pb.ShipItem) error {
	l, ok := s.lanes[laneID]
	if !ok {
		return fmt.Errorf("invalid lane %v", laneID)
	}
	_, dropped, err := l.sp.Append(func(seq uint64) ([]byte, spool.Meta, error) {
		it.Seq = seq
		b, err := wire.MarshalItem(it)
		return b, metaOf(it), err
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	l.appended++
	if dropped != nil {
		if n := len(l.dropped); n > 0 && l.dropped[n-1].Last+1 == dropped.First {
			l.dropped[n-1].Last = dropped.Last
			for _, src := range dropped.Sources {
				l.dropped[n-1].Sources = addSource(l.dropped[n-1].Sources, src)
			}
			l.dropped[n-1].Add(dropped.FromNs)
			l.dropped[n-1].Add(dropped.ToNs)
		} else {
			l.dropped = append(l.dropped, *dropped)
		}
	}
	s.mu.Unlock()
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

// SetWatermark declares that no later item on the lane has an earlier event time.
func (s *Shipper) SetWatermark(laneID pb.Lane, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.lanes[laneID]; ok {
		l.wm, l.wmDirty = timestamppb.New(t), true
	}
	s.signal()
}

// Sync makes every submitted item durable and sendable.
func (s *Shipper) Sync() error {
	for _, l := range wire.Lanes {
		if err := s.lanes[l].sp.Sync(); err != nil {
			return err
		}
	}
	s.signal()
	return nil
}

// CloseInput marks the end of input; in drain mode Run returns once
// everything is acknowledged or reported.
func (s *Shipper) CloseInput() error {
	err := s.Sync()
	s.mu.Lock()
	s.inputDone = true
	s.mu.Unlock()
	s.signal()
	return err
}

// Close closes the spools.
func (s *Shipper) Close() error {
	var first error
	for _, l := range wire.Lanes {
		if err := s.lanes[l].sp.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Stats returns a snapshot per lane.
func (s *Shipper) Stats() map[string]LaneStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]LaneStats{}
	for _, l := range wire.Lanes {
		ln := s.lanes[l]
		out[l.String()] = LaneStats{Appended: ln.appended, NextSeq: ln.sp.Next(),
			AckedThrough: ln.acked, Gaps: append([]GapReport(nil), ln.reports...)}
	}
	return out
}

func (s *Shipper) drained() bool {
	if !s.inputDone {
		return false
	}
	for _, l := range s.lanes {
		next := l.sp.Next()
		if l.sp.Synced() != next-1 || l.acked < next-1 || l.wmDirty {
			return false
		}
	}
	return true
}

// Run connects and sends until ctx ends, or, with drain set, until input is
// closed and every item is acknowledged or reported. It reconnects after
// failures and returns at once on a RejectedError.
func (s *Shipper) Run(ctx context.Context, drain bool) error {
	backoff := 100 * time.Millisecond
	for {
		welcomed, err := s.session(ctx, drain)
		if err == nil {
			return nil
		}
		var rj *RejectedError
		if errors.As(err, &rj) || ctx.Err() != nil {
			return err
		}
		if welcomed {
			backoff = 100 * time.Millisecond
		}
		s.cfg.Logf("shipper %s: %v; reconnecting in %s", s.cfg.NodeID, err, backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
	}
}

func (s *Shipper) session(ctx context.Context, drain bool) (bool, error) {
	conn, err := grpc.NewClient(s.cfg.Addr,
		grpc.WithTransportCredentials(credentials.NewTLS(s.cfg.TLS)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 10 * time.Second, Timeout: 5 * time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := pb.NewIngestClient(conn).Ship(sctx)
	if err != nil {
		return false, err
	}
	hello := &pb.Hello{NodeId: s.cfg.NodeID, BootId: s.cfg.BootID, AgentInstance: s.cfg.Instance, SchemaVersion: wire.SchemaVersion}
	if err := stream.Send(&pb.NodeMessage{Msg: &pb.NodeMessage_Hello{Hello: hello}}); err != nil {
		return false, err
	}
	first, err := stream.Recv()
	if err != nil {
		return false, err
	}
	if rj := first.GetReject(); rj != nil {
		return false, &RejectedError{rj.Reason}
	}
	w := first.GetWelcome()
	if w == nil {
		return false, errors.New("expected Welcome")
	}
	if err := s.applyWelcome(w); err != nil {
		return false, err
	}

	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if rj := m.GetReject(); rj != nil {
				recvErr <- &RejectedError{rj.Reason}
				return
			}
			s.applyReply(m)
		}
	}()

	for {
		s.mu.Lock()
		done := drain && s.drained()
		s.mu.Unlock()
		if done {
			_ = stream.CloseSend()
			return true, nil
		}
		sent, err := s.sendSome(stream)
		if err != nil {
			return true, err
		}
		if sent {
			select {
			case err := <-recvErr:
				return true, err
			default:
			}
			continue
		}
		select {
		case err := <-recvErr:
			return true, err
		case <-ctx.Done():
			return true, ctx.Err()
		case <-s.wake:
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (s *Shipper) applyWelcome(w *pb.Welcome) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pos := range w.Positions {
		l, ok := s.lanes[pos.Lane]
		if !ok {
			continue
		}
		e := pos.NextExpectedSeq
		if e == 0 {
			e = 1
		}
		if e > l.sp.Next() {
			return &RejectedError{fmt.Sprintf("receiver expects %s seq %d but the spool only reached %d; spool lost?", pos.Lane, e, l.sp.Next()-1)}
		}
		if e-1 > l.acked {
			l.acked = e - 1
		}
		l.sp.TruncateThrough(e - 1)
		l.cursor, l.lastProgress = e, time.Now()
		l.wmDirty = l.wm != nil
	}
	return nil
}

func (s *Shipper) applyReply(m *pb.ReceiverMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r := m.Msg.(type) {
	case *pb.ReceiverMessage_Ack:
		if l, ok := s.lanes[r.Ack.Lane]; ok {
			l.lastProgress = time.Now()
			if r.Ack.AckedThrough > l.acked {
				l.acked = r.Ack.AckedThrough
				l.sp.TruncateThrough(l.acked)
			}
		}
	case *pb.ReceiverMessage_Nack:
		if l, ok := s.lanes[r.Nack.Lane]; ok {
			l.lastProgress = time.Now()
			if r.Nack.FromSeq-1 > l.acked {
				l.acked = r.Nack.FromSeq - 1
				l.sp.TruncateThrough(l.acked)
			}
			l.cursor = r.Nack.FromSeq
			s.cfg.Logf("shipper %s %s: nack from %d: %s", s.cfg.NodeID, r.Nack.Lane, r.Nack.FromSeq, r.Nack.Reason)
		}
	}
	s.signal()
}

// sendSome sends at most one message; it reports whether it sent anything.
func (s *Shipper) sendSome(stream pb.Ingest_ShipClient) (bool, error) {
	for _, id := range wire.Lanes {
		msg := s.nextMessage(id)
		if msg == nil {
			continue
		}
		if b := msg.GetBatch(); b != nil && s.cfg.Transit != nil {
			for _, m := range s.cfg.Transit.Batch(id, b) {
				if err := stream.Send(m); err != nil {
					return true, err
				}
			}
			return true, nil
		}
		return true, stream.Send(msg)
	}
	return false, nil
}

// nextMessage picks the lane's next message: a gap notice for records no
// longer in the spool, a batch, or a watermark.
func (s *Shipper) nextMessage(id pb.Lane) *pb.NodeMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.lanes[id]
	if first := l.sp.First(); l.cursor < first {
		g := s.gapNotice(l, l.cursor, first-1)
		l.cursor = first
		return &pb.NodeMessage{Msg: &pb.NodeMessage_GapNotice{GapNotice: g}}
	}
	inflight := int64(l.cursor) - int64(l.acked) - 1
	if inflight > 0 && time.Since(l.lastProgress) > s.cfg.Retransmit {
		s.cfg.Logf("shipper %s %s: no ack for %s, resending from %d", s.cfg.NodeID, id, s.cfg.Retransmit, l.acked+1)
		l.cursor, inflight, l.lastProgress = l.acked+1, 0, time.Now()
	}
	room := int64(s.cfg.Window) - inflight
	max := s.cfg.BatchMax
	if id == pb.Lane_PRIORITY {
		max = 1
	}
	if int64(max) > room {
		max = int(room)
	}
	if max > 0 {
		entries := l.sp.Read(l.cursor, max)
		if len(entries) > 0 {
			if id == pb.Lane_NORMAL && len(entries) < s.cfg.BatchMax && !s.inputDone && s.cfg.Linger > 0 {
				if l.pendingSince.IsZero() {
					l.pendingSince = time.Now()
				}
				if time.Since(l.pendingSince) < s.cfg.Linger {
					return nil
				}
			}
			l.pendingSince = time.Time{}
			items := make([]*pb.ShipItem, 0, len(entries))
			for _, e := range entries {
				it := &pb.ShipItem{}
				if err := proto.Unmarshal(e.Data, it); err != nil {
					s.cfg.Logf("shipper: unreadable spool record %d: %v", e.Seq, err)
					return nil
				}
				items = append(items, it)
			}
			sum, err := wire.HashItems(items)
			if err != nil {
				s.cfg.Logf("shipper: hash: %v", err)
				return nil
			}
			hdr := &pb.BatchHeader{NodeId: s.cfg.NodeID, BootId: s.cfg.BootID, AgentInstance: s.cfg.Instance,
				Lane: id, FirstSeq: entries[0].Seq, Count: uint32(len(items)), SchemaVersion: wire.SchemaVersion,
				Compression: "none", PayloadSha256: sum, LowWatermark: l.wm}
			if inflight <= 0 {
				l.lastProgress = time.Now()
			}
			l.cursor = entries[len(entries)-1].Seq + 1
			l.wmDirty = false
			return &pb.NodeMessage{Msg: &pb.NodeMessage_Batch{Batch: &pb.Batch{Header: hdr, Items: items}}}
		}
	}
	if l.wmDirty && l.cursor >= l.sp.Next() {
		l.wmDirty = false
		return &pb.NodeMessage{Msg: &pb.NodeMessage_Watermark{Watermark: &pb.Watermark{Lane: id, LowWatermark: l.wm}}}
	}
	return nil
}

// gapNotice reports first..last as not deliverable, with the sources of the
// records the spool dropped in that range.
func (s *Shipper) gapNotice(l *lane, first, last uint64) *pb.GapNotice {
	var srcs []int32
	var covered uint64
	var span spool.Range // time span of the dropped records in first..last
	keep := l.dropped[:0]
	for _, r := range l.dropped {
		lo, hi := max(r.First, first), min(r.Last, last)
		if lo <= hi {
			covered += hi - lo + 1
			for _, x := range r.Sources {
				srcs = addSource(srcs, x)
			}
			span.Add(r.FromNs)
			span.Add(r.ToNs)
		}
		if r.Last > last {
			keep = append(keep, r)
		}
	}
	l.dropped = keep
	detail := "spool overflow"
	if covered < last-first+1 {
		detail = "not in spool (dropped before a restart or lost)"
	}
	sort.Slice(srcs, func(i, j int) bool { return srcs[i] < srcs[j] })
	g := &pb.GapNotice{Lane: l.id, FirstSeq: first, LastSeq: last, Reason: pb.GapReason_DROPPED_BEFORE, Detail: detail}
	// Times only when the shipper held every record of the range; otherwise
	// the receiver fills them from its lane state (ship-contract.md, "Gap times").
	if covered == last-first+1 && span.FromNs != 0 {
		g.From, g.To = timestamppb.New(time.Unix(0, span.FromNs)), timestamppb.New(time.Unix(0, span.ToNs))
	}
	rep := GapReport{First: first, Last: last, Detail: detail}
	for _, x := range srcs {
		g.Sources = append(g.Sources, pb.Source(x))
		rep.Sources = append(rep.Sources, pb.Source(x))
	}
	l.reports = append(l.reports, rep)
	s.cfg.Logf("shipper %s %s: reporting seq %d-%d as not delivered (%s)", s.cfg.NodeID, l.id, first, last, detail)
	return g
}
