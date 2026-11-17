// Package receiver is the ingest receiver of the shipping contract
// (spec/kafka/ship-contract.md): the only writer of shipped records to Kafka.
package receiver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/failpoint"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/mtkey"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/wire"
)

// ProducerID names the receiver on the envelopes it writes itself.
const ProducerID = "ingest-receiver"

// Config configures a Server.
type Config struct {
	Instance        string
	ProducerVersion string
	RunID           string
	// Allowed topics for shipped items; heartbeats go to those with HEARTBEAT.
	Allowed map[string]*TopicSpec
	// Spec of source.completeness.v0.
	Completeness *TopicSpec
	// Partition count per allowed topic.
	Partitions     map[string]int32
	StateDir       string
	HeartbeatEvery time.Duration
	MaxIdle        time.Duration
	ProduceTimeout time.Duration
	Logf           func(string, ...any)
}

// Server implements the Ingest service.
type Server struct {
	pb.UnimplementedIngestServer
	cfg   Config
	data  Producer
	hb    Producer
	store stateStore

	mu      sync.Mutex
	streams map[string]*nodeStream
	hbSeq   uint64
	lastLW  time.Time
}

type nodeStream struct {
	node, boot string
	proc       sync.Mutex // serializes message handling across stream take-overs

	// guarded by Server.mu
	next      map[pb.Lane]uint64
	lastET    map[pb.Lane]int64       // latest accepted event time (Unix ns)
	pending   map[pb.Lane]*pendingGap // gaps waiting for their end time
	idleOpen  bool                    // an open-ended SOURCE_IDLE gap awaits its end
	idleFrom  int64                   // its start (Unix ns event time; 0 = unknown)
	wm        map[pb.Lane]*timestamppb.Timestamp
	used      map[pb.Lane]bool
	lastSeen  time.Time
	connected bool
	idle      bool
	cancel    context.CancelFunc
	gen       uint64
	ver       uint64 // bumped by every change to next

	commitMu sync.Mutex
	savedVer uint64 // guarded by commitMu
}

// New returns a Server writing data records through data and heartbeats
// through hb (a producer that honours record partitions).
func New(cfg Config, data, hb Producer) *Server {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.ProduceTimeout == 0 {
		cfg.ProduceTimeout = 15 * time.Second
	}
	return &Server{cfg: cfg, data: data, hb: hb, store: stateStore{cfg.StateDir},
		streams: map[string]*nodeStream{}, lastLW: time.Unix(0, 0)}
}

type rejectError struct{ reason string }

func (r rejectError) Error() string { return r.reason }

func peerNode(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.PeerCertificates) == 0 {
		return "", errors.New("no verified client certificate")
	}
	return ti.State.PeerCertificates[0].Subject.CommonName, nil
}

func reject(stream pb.Ingest_ShipServer, reason string) error {
	_ = stream.Send(&pb.ReceiverMessage{Msg: &pb.ReceiverMessage_Reject{Reject: &pb.Reject{Reason: reason}}})
	return status.Error(codes.PermissionDenied, reason)
}

// Ship handles one shipper stream.
func (s *Server) Ship(stream pb.Ingest_ShipServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	certNode, err := peerNode(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	switch {
	case hello == nil:
		return reject(stream, "first message must be Hello")
	case hello.NodeId != certNode:
		return reject(stream, fmt.Sprintf("node_id %q does not match certificate %q", hello.NodeId, certNode))
	case !wire.ValidID(hello.NodeId) || !wire.ValidID(hello.BootId):
		return reject(stream, "invalid node_id or boot_id")
	case hello.SchemaVersion != wire.SchemaVersion:
		return reject(stream, fmt.Sprintf("unsupported schema_version %q", hello.SchemaVersion))
	}
	ns, gen, err := s.attach(hello.NodeId, hello.BootId, cancel)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	defer s.detach(ns, gen)

	ns.proc.Lock()
	w := &pb.Welcome{}
	s.mu.Lock()
	for _, l := range wire.Lanes {
		w.Positions = append(w.Positions, &pb.LanePosition{Lane: l, NextExpectedSeq: ns.next[l]})
	}
	s.mu.Unlock()
	ns.proc.Unlock()
	if err := stream.Send(&pb.ReceiverMessage{Msg: &pb.ReceiverMessage_Welcome{Welcome: w}}); err != nil {
		return err
	}

	rep := newReplier(stream, func() error { return s.commit(ns) })
	go rep.run()
	defer rep.stop()
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return rep.stop()
		}
		if err != nil {
			return err
		}
		ns.proc.Lock()
		if ctx.Err() != nil {
			ns.proc.Unlock()
			return status.Error(codes.Aborted, "replaced by a newer stream")
		}
		reply, herr := s.handle(ctx, ns, msg)
		ns.proc.Unlock()
		var rj rejectError
		if errors.As(herr, &rj) {
			rep.stop()
			return reject(stream, rj.reason)
		}
		if herr != nil {
			return status.Error(codes.Internal, herr.Error())
		}
		if reply != nil {
			if err := rep.push(reply); err != nil {
				return status.Error(codes.Internal, err.Error())
			}
		}
	}
}

// replier sends a stream's replies in order. Before sending a batch of
// queued replies it commits the stream's positions once (group commit), so an
// ack never precedes the durable state it reports.
type replier struct {
	stream pb.Ingest_ShipServer
	commit func() error
	mu     sync.Mutex
	queue  []*pb.ReceiverMessage
	err    error
	wake   chan struct{}
	quit   chan struct{}
	done   chan struct{}
	once   sync.Once
}

func newReplier(stream pb.Ingest_ShipServer, commit func() error) *replier {
	return &replier{stream: stream, commit: commit, wake: make(chan struct{}, 1),
		quit: make(chan struct{}), done: make(chan struct{})}
}

func (r *replier) push(m *pb.ReceiverMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.queue = append(r.queue, m)
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

func (r *replier) flush() error {
	r.mu.Lock()
	q := r.queue
	r.queue = nil
	r.mu.Unlock()
	if len(q) == 0 {
		return nil
	}
	if err := r.commit(); err != nil {
		return fmt.Errorf("state write failed: %w", err)
	}
	// Exp. 5 part A: the state is stored, the acks are not sent; the
	// shipper resends and the receiver must acknowledge without rewriting.
	failpoint.Hit("receiver.after_store_before_ack", func() map[string]any {
		return map[string]any{"replies": len(q), "acks": countAcks(q)}
	}, func() bool { return countAcks(q) > 0 })
	for _, m := range q {
		if err := r.stream.Send(m); err != nil {
			return err
		}
	}
	return nil
}

func (r *replier) run() {
	defer close(r.done)
	for {
		select {
		case <-r.wake:
		case <-r.quit:
			if err := r.flush(); err != nil {
				r.setErr(err)
			}
			return
		}
		if err := r.flush(); err != nil {
			r.setErr(err)
			return
		}
	}
}

func (r *replier) setErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
	}
}

// stop flushes what is queued, ends the replier and returns its error.
func (r *replier) stop() error {
	r.once.Do(func() { close(r.quit) })
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func key(node, boot string) string { return node + "\x00" + boot }

// attach finds or loads the stream state and makes this stream its owner,
// cancelling any older stream for the same (node, boot).
func (s *Server) attach(node, boot string, cancel context.CancelFunc) (*nodeStream, uint64, error) {
	s.mu.Lock()
	ns, ok := s.streams[key(node, boot)]
	s.mu.Unlock()
	if !ok {
		st, err := s.store.load(node, boot)
		if err != nil {
			return nil, 0, err
		}
		s.mu.Lock()
		if ns, ok = s.streams[key(node, boot)]; !ok {
			ns = &nodeStream{node: node, boot: boot, next: st.next, lastET: st.lastET, pending: st.pending,
				idleOpen: st.idleOpen, idleFrom: st.idleFrom,
				wm: map[pb.Lane]*timestamppb.Timestamp{}, used: map[pb.Lane]bool{}}
			s.streams[key(node, boot)] = ns
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ns.cancel != nil {
		ns.cancel()
	}
	ns.gen++
	ns.cancel, ns.connected, ns.idle = cancel, true, false
	ns.lastSeen = time.Now()
	return ns, ns.gen, nil
}

func (s *Server) detach(ns *nodeStream, gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ns.gen == gen {
		ns.connected, ns.cancel = false, nil
		ns.lastSeen = time.Now()
	}
}

func ack(l pb.Lane, through uint64) *pb.ReceiverMessage {
	return &pb.ReceiverMessage{Msg: &pb.ReceiverMessage_Ack{Ack: &pb.Ack{Lane: l, AckedThrough: through}}}
}

func countAcks(q []*pb.ReceiverMessage) int {
	n := 0
	for _, m := range q {
		if m.GetAck() != nil {
			n++
		}
	}
	return n
}

func nack(l pb.Lane, from uint64, reason string) *pb.ReceiverMessage {
	return &pb.ReceiverMessage{Msg: &pb.ReceiverMessage_Nack{Nack: &pb.Nack{Lane: l, FromSeq: from, Reason: reason}}}
}

func (s *Server) touch(ns *nodeStream, l pb.Lane, wm *timestamppb.Timestamp) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns.lastSeen, ns.idle = time.Now(), false
	ns.used[l] = true
	if wm != nil && (ns.wm[l] == nil || wm.AsTime().After(ns.wm[l].AsTime())) {
		ns.wm[l] = wm
	}
}

func (s *Server) nextSeq(ns *nodeStream, l pb.Lane) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ns.next[l]
}

// advance moves the lane's next expected sequence to n in memory. The
// replier makes it durable (commit) before sending any ack that depends on it.
func (s *Server) advance(ns *nodeStream, l pb.Lane, n uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns.next[l] = n
	ns.ver++
	return nil
}

// accepted records a written batch: the next sequence, the latest event
// time, and whether it closed the lane's pending gap.
func (s *Server) accepted(ns *nodeStream, l pb.Lane, n uint64, maxET int64, closed, idleClosed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns.next[l] = n
	if idleClosed {
		ns.idleOpen, ns.idleFrom = false, 0
	}
	if maxET > ns.lastET[l] {
		ns.lastET[l] = maxET
	}
	if closed {
		delete(ns.pending, l)
	}
	ns.ver++
}

// pendingFor returns a copy of the lane's pending gap, or nil.
func (s *Server) pendingFor(ns *nodeStream, l pb.Lane) *pendingGap {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := ns.pending[l]; g != nil {
		c := *g
		c.Sources = slices.Clone(g.Sources)
		return &c
	}
	return nil
}

func (s *Server) idleState(ns *nodeStream) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ns.idleFrom, ns.idleOpen
}

// idleRecord is a SOURCE_IDLE gap for the node in event time: from the
// node's last accepted event time (unset if unknown) to to (unset: open).
func (s *Server) idleRecord(ns *nodeStream, fromNs int64, to *timestamppb.Timestamp, detail string) (*kgo.Record, error) {
	var from *timestamppb.Timestamp
	if fromNs != 0 {
		from = timestamppb.New(time.Unix(0, fromNs))
	}
	scope := fmt.Sprintf("node=%s/boot=%s", ns.node, ns.boot)
	return s.completeness(pb.Source_SOURCE_UNSPECIFIED, scope, from, to,
		&pb.Gap{Reason: pb.GapReason_SOURCE_IDLE, Scope: "transport", Detail: detail, From: from, To: to})
}

// holdGap stores (or extends) the lane's pending gap and moves the expected
// sequence past it; commit makes both durable before the ack is sent.
func (s *Server) holdGap(ns *nodeStream, l pb.Lane, first, last uint64, reason pb.GapReason, detail string, sources []pb.Source, scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := ns.pending[l]
	if g == nil {
		g = &pendingGap{First: first, Reason: reason, Detail: detail, FromNs: ns.lastET[l], Scope: scope}
		ns.pending[l] = g
	} else {
		if detail != "" && !strings.Contains(g.Detail, detail) {
			g.Detail = strings.TrimPrefix(g.Detail+"; "+detail, "; ")
		}
		g.Scope = mergeScope(g.Scope, scope)
	}
	g.Last = last
	for _, src := range sources {
		if !slices.Contains(g.Sources, src) {
			g.Sources = append(g.Sources, src)
		}
	}
	slices.Sort(g.Sources)
	ns.next[l] = last + 1
	ns.ver++
}

// gapRecords builds one SourceCompleteness record per source of g, ending at
// to (nil: open-ended).
func (s *Server) gapRecords(ns *nodeStream, l pb.Lane, g *pendingGap, to *timestamppb.Timestamp) ([]*kgo.Record, error) {
	var from *timestamppb.Timestamp
	if g.FromNs != 0 {
		from = timestamppb.New(time.Unix(0, g.FromNs))
	}
	scope := wire.Scope(ns.node, ns.boot, l)
	detail := fmt.Sprintf("transport seq %d-%d not delivered", g.First, g.Last)
	if g.Detail != "" {
		detail += ": " + g.Detail
	}
	var recs []*kgo.Record
	for _, src := range g.Sources {
		gscope := "transport"
		if g.Scope != "" {
			gscope += "/" + g.Scope // the lost items' keys (scoped loss); the GO reads "keys="
		}
		rec, err := s.completeness(src, scope, from, to, &pb.Gap{Reason: g.Reason, Scope: gscope,
			Detail: detail, From: from, To: to})
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// commit durably stores the stream's current positions, if they changed since
// the last commit. Concurrent commits for one stream are serialized and never
// write an older snapshot over a newer one.
func (s *Server) commit(ns *nodeStream) error {
	ns.commitMu.Lock()
	defer ns.commitMu.Unlock()
	s.mu.Lock()
	ver := ns.ver
	st := newStreamState()
	for k, v := range ns.next {
		st.next[k] = v
	}
	for k, v := range ns.lastET {
		st.lastET[k] = v
	}
	for k, v := range ns.pending {
		g := *v
		g.Sources = slices.Clone(v.Sources)
		st.pending[k] = &g
	}
	st.idleOpen, st.idleFrom = ns.idleOpen, ns.idleFrom
	s.mu.Unlock()
	if ver <= ns.savedVer {
		return nil
	}
	if err := s.store.save(ns.node, ns.boot, st); err != nil {
		return err
	}
	ns.savedVer = ver
	return nil
}

func (s *Server) handle(ctx context.Context, ns *nodeStream, msg *pb.NodeMessage) (*pb.ReceiverMessage, error) {
	switch m := msg.Msg.(type) {
	case *pb.NodeMessage_Batch:
		return s.handleBatch(ctx, ns, m.Batch)
	case *pb.NodeMessage_GapNotice:
		return s.handleGap(ctx, ns, m.GapNotice)
	case *pb.NodeMessage_Watermark:
		if !wire.ValidLane(m.Watermark.Lane) {
			return nil, rejectError{"invalid lane"}
		}
		s.touch(ns, m.Watermark.Lane, m.Watermark.LowWatermark)
		return nil, nil
	case *pb.NodeMessage_Hello:
		return nil, rejectError{"Hello sent twice"}
	default:
		return nil, rejectError{"empty message"}
	}
}

func (s *Server) handleBatch(ctx context.Context, ns *nodeStream, b *pb.Batch) (*pb.ReceiverMessage, error) {
	h := b.GetHeader()
	switch {
	case h == nil:
		return nil, rejectError{"batch without header"}
	case h.NodeId != ns.node || h.BootId != ns.boot:
		return nil, rejectError{"batch header identity differs from Hello"}
	case !wire.ValidLane(h.Lane):
		return nil, rejectError{"invalid lane"}
	case len(b.Items) == 0 || int(h.Count) != len(b.Items):
		return nil, rejectError{"count does not match items"}
	case h.FirstSeq == 0:
		return nil, rejectError{"sequences start at 1"}
	}
	for i, it := range b.Items {
		if it.Seq != h.FirstSeq+uint64(i) {
			return nil, rejectError{fmt.Sprintf("item %d has seq %d, want %d", i, it.Seq, h.FirstSeq+uint64(i))}
		}
	}
	sum, err := wire.HashItems(b.Items)
	if err != nil {
		return nil, err
	}
	if sum != h.PayloadSha256 {
		return nil, rejectError{"payload_sha256 mismatch"}
	}
	s.touch(ns, h.Lane, h.LowWatermark)

	next := s.nextSeq(ns, h.Lane)
	last := h.FirstSeq + uint64(len(b.Items)) - 1
	if last < next {
		return ack(h.Lane, next-1), nil
	}
	if h.FirstSeq > next {
		return nack(h.Lane, next, fmt.Sprintf("expected seq %d, got %d", next, h.FirstSeq)), nil
	}
	var recs []*kgo.Record
	var firstET *timestamppb.Timestamp
	var maxET int64
	for _, it := range b.Items {
		if it.Seq < next {
			continue
		}
		rec, err := s.record(it)
		if err != nil {
			return nil, rejectError{fmt.Sprintf("seq %d: %v", it.Seq, err)}
		}
		recs = append(recs, rec)
		if et, ok := wire.EventTime(it.Envelope); ok {
			if firstET == nil {
				firstET = timestamppb.New(et)
			}
			maxET = max(maxET, et.UnixNano())
		}
	}
	// The next accepted item ends a pending gap at its event time (open-ended
	// when no accepted item in the batch carries one).
	pg := s.pendingFor(ns, h.Lane)
	closed := pg != nil && len(recs) > 0
	if closed {
		gr, err := s.gapRecords(ns, h.Lane, pg, firstET)
		if err != nil {
			return nil, err
		}
		recs = append(recs, gr...)
	}
	// The first timed item after an idle period ends it: a bounded
	// SOURCE_IDLE record with the same start closes the open-ended one.
	idleFrom, idleOpen := s.idleState(ns)
	idleClosed := idleOpen && firstET != nil
	if idleClosed {
		rec, err := s.idleRecord(ns, idleFrom, firstET, "idle interval ended by the next item")
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	pctx, cancel := context.WithTimeout(ctx, s.cfg.ProduceTimeout)
	defer cancel()
	open := func() map[string]any {
		return map[string]any{"node": ns.node, "lane": h.Lane.String(), "records": len(recs), "first_seq": next,
			"last_seq": last}
	}
	if err := s.produce(pctx, recs, open); err != nil {
		s.cfg.Logf("node %s lane %s: kafka write failed, nack from %d: %v", ns.node, h.Lane, next, err)
		return nack(h.Lane, next, "kafka: "+err.Error()), nil
	}
	// Exp. 5 part A: Kafka holds the batch, the next expected sequence is
	// not stored, the shipper has no ack; a restart must not lose or
	// duplicate the batch's records.
	failpoint.Hit("receiver.after_kafka_ack_before_seq_store", open, nil)
	s.accepted(ns, h.Lane, last+1, maxET, closed, idleClosed)
	return ack(h.Lane, last), nil
}

// produce writes recs and waits for Kafka. With receiver.mid_batch armed
// it writes them in two halves and the failpoint lies between, so a crash
// leaves part of the batch in Kafka.
func (s *Server) produce(ctx context.Context, recs []*kgo.Record, open func() map[string]any) error {
	if failpoint.Armed() != "receiver.mid_batch" || len(recs) < 2 {
		return s.data.Produce(ctx, recs)
	}
	half := len(recs) / 2
	if err := s.data.Produce(ctx, recs[:half]); err != nil {
		return err
	}
	failpoint.Hit("receiver.mid_batch", func() map[string]any {
		m := open()
		m["written"] = half
		return m
	}, nil)
	return s.data.Produce(ctx, recs[half:])
}

// record checks one item against its topic and builds the Kafka record.
func (s *Server) record(it *pb.ShipItem) (*kgo.Record, error) {
	spec, ok := s.cfg.Allowed[it.Topic]
	if !ok {
		return nil, fmt.Errorf("topic %q not allowed", it.Topic)
	}
	if it.KeyType != spec.KeyType {
		return nil, fmt.Errorf("topic %s needs key type %s, got %s", it.Topic, spec.KeyType, it.KeyType)
	}
	if len(it.KeyComponents) != len(spec.Components) {
		return nil, fmt.Errorf("topic %s needs %d key components, got %d", it.Topic, len(spec.Components), len(it.KeyComponents))
	}
	if it.Envelope == nil {
		return nil, errors.New("no envelope")
	}
	k, err := encodeKey(spec, it.KeyComponents)
	if err != nil {
		return nil, err
	}
	v, err := deterministicMarshal(it.Envelope)
	if err != nil {
		return nil, err
	}
	return &kgo.Record{Topic: it.Topic, Key: k, Value: v}, nil
}

func encodeKey(spec *TopicSpec, values []string) ([]byte, error) {
	comps := make([]mtkey.Component, len(values))
	for i, v := range values {
		comps[i] = mtkey.Component{Code: uint8(spec.Components[i]), Value: v}
	}
	return mtkey.Encode(uint16(spec.KeyType), comps)
}

func (s *Server) handleGap(ctx context.Context, ns *nodeStream, g *pb.GapNotice) (*pb.ReceiverMessage, error) {
	if !wire.ValidLane(g.Lane) || g.FirstSeq == 0 || g.LastSeq < g.FirstSeq {
		return nil, rejectError{"invalid gap notice"}
	}
	s.touch(ns, g.Lane, nil)
	next := s.nextSeq(ns, g.Lane)
	if g.LastSeq < next {
		return ack(g.Lane, next-1), nil
	}
	if g.FirstSeq > next {
		return nack(g.Lane, next, fmt.Sprintf("gap notice must start at expected seq %d", next)), nil
	}
	first := g.FirstSeq
	if first < next {
		first = next
	}
	sources := g.Sources
	if len(sources) == 0 {
		sources = []pb.Source{pb.Source_SOURCE_UNSPECIFIED}
	}
	reason := g.Reason
	if reason == pb.GapReason_GAP_REASON_UNSPECIFIED {
		reason = pb.GapReason_DROPPED_BEFORE
	}
	if g.From == nil || g.To == nil {
		// The sender did not know the lost records' times: hold the gap until
		// the next accepted item gives its end (ship-contract.md, "Gap times").
		s.holdGap(ns, g.Lane, first, g.LastSeq, reason, g.Detail, sources, g.Scope)
		s.cfg.Logf("node %s %s: loss of seq %d-%d held until the next item", ns.node, g.Lane, first, g.LastSeq)
		return ack(g.Lane, g.LastSeq), nil
	}
	recs, err := s.gapRecords(ns, g.Lane, &pendingGap{First: first, Last: g.LastSeq, Reason: reason, Scope: g.Scope,
		Detail: g.Detail, Sources: sources, FromNs: g.From.AsTime().UnixNano()}, g.To)
	if err != nil {
		return nil, err
	}
	detail := fmt.Sprintf("seq %d-%d", first, g.LastSeq)
	pctx, cancel := context.WithTimeout(ctx, s.cfg.ProduceTimeout)
	defer cancel()
	if err := s.data.Produce(pctx, recs); err != nil {
		return nack(g.Lane, next, "kafka: "+err.Error()), nil
	}
	if err := s.advance(ns, g.Lane, g.LastSeq+1); err != nil {
		return nack(g.Lane, next, "state write failed"), nil
	}
	s.cfg.Logf("node %s %s: recorded loss %s", ns.node, g.Lane, detail)
	return ack(g.Lane, g.LastSeq), nil
}

func (s *Server) envelope(kind pb.RecordKind, src pb.Source) *pb.Envelope {
	return &pb.Envelope{SchemaMajor: 0, SchemaMinor: 1, ProducerId: ProducerID,
		ProducerVersion: s.cfg.ProducerVersion, Kind: kind, Source: src,
		Run: &pb.RunContext{RunId: s.cfg.RunID}}
}

// completeness builds an INCOMPLETE SourceCompleteness record.
func (s *Server) completeness(src pb.Source, scope string, from, to *timestamppb.Timestamp, gap *pb.Gap) (*kgo.Record, error) {
	// An unknown bound stays unset and consumers treat it as open-ended; the
	// wall clock is never substituted for event time.
	env := s.envelope(pb.RecordKind_SOURCE_COMPLETENESS, src)
	env.Payload = &pb.Envelope_SourceCompleteness{SourceCompleteness: &pb.SourceCompleteness{
		Source: src, Scope: scope, IntervalStart: from, IntervalEnd: to,
		Status: pb.CompletenessStatus_INCOMPLETE, Gaps: []*pb.Gap{gap}}}
	k, err := encodeKey(s.cfg.Completeness, []string{src.String(), scope})
	if err != nil {
		return nil, err
	}
	v, err := deterministicMarshal(env)
	if err != nil {
		return nil, err
	}
	return &kgo.Record{Topic: CompletenessTopic, Key: k, Value: v}, nil
}

// Run writes heartbeats and idle records until ctx ends.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.HeartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick(ctx)
		}
	}
}

func (s *Server) tick(ctx context.Context) {
	now := time.Now()
	var idle []*kgo.Record
	var flushed []*nodeStream
	s.mu.Lock()
	var lw time.Time
	active, unknown := false, false
	for _, ns := range s.streams {
		if ns.connected {
			ns.lastSeen = now
		}
		if !ns.idle && now.Sub(ns.lastSeen) > s.cfg.MaxIdle {
			ns.idle = true
			// In event time (ship-contract.md, "Idle nodes"): open-ended from
			// the node's last accepted event; the next item closes it.
			if !ns.idleOpen {
				var from int64
				for _, t := range ns.lastET {
					from = max(from, t)
				}
				rec, err := s.idleRecord(ns, from, nil,
					fmt.Sprintf("no stream activity for more than %s; excluded from the watermark", s.cfg.MaxIdle))
				if err == nil {
					idle = append(idle, rec)
					ns.idleOpen, ns.idleFrom = true, from
					ns.ver++
					flushed = append(flushed, ns)
				}
			}
			// Pending gaps cannot be closed by a next item any more: write
			// them open-ended (ship-contract.md, "Gap times").
			for _, l := range wire.Lanes {
				if g := ns.pending[l]; g != nil {
					recs, err := s.gapRecords(ns, l, g, nil) // takes no lock
					if err == nil {
						idle = append(idle, recs...)
						delete(ns.pending, l)
						ns.ver++
						flushed = append(flushed, ns)
					}
				}
			}
			s.cfg.Logf("node %s boot %s idle", ns.node, ns.boot)
		}
		if ns.idle {
			continue
		}
		for _, l := range wire.Lanes {
			if !ns.used[l] {
				continue
			}
			active = true
			if ns.wm[l] == nil {
				unknown = true
				continue
			}
			if t := ns.wm[l].AsTime(); lw.IsZero() || t.Before(lw) {
				lw = t
			}
		}
	}
	switch {
	case !active:
		lw = s.lastLW
	case unknown || lw.IsZero():
		lw = time.Unix(0, 0)
	}
	if lw.Before(s.lastLW) {
		lw = s.lastLW // heartbeats never move a promise backwards
	}
	s.lastLW = lw
	var hbs []*kgo.Record
	for name, spec := range s.cfg.Allowed {
		if !spec.Heartbeats {
			continue
		}
		for p := int32(0); p < s.cfg.Partitions[name]; p++ {
			s.hbSeq++
			env := s.envelope(pb.RecordKind_HEARTBEAT, spec.Source)
			env.Payload = &pb.Envelope_Heartbeat{Heartbeat: &pb.Heartbeat{ProducerId: ProducerID,
				ProducerInstance: s.cfg.Instance, Topic: name, Partition: p,
				LowWatermark: timestamppb.New(lw), EmittedAt: timestamppb.New(now), ProducerSeq: s.hbSeq}}
			v, err := deterministicMarshal(env)
			if err != nil {
				continue
			}
			k, _ := mtkey.Encode(uint16(pb.KeyType_KEY_PRODUCER_INSTANCE),
				[]mtkey.Component{{Code: uint8(pb.KeyComponent_PRODUCER_INSTANCE), Value: s.cfg.Instance}})
			hbs = append(hbs, &kgo.Record{Topic: name, Partition: p, Key: k, Value: v})
		}
	}
	s.mu.Unlock()
	pctx, cancel := context.WithTimeout(ctx, s.cfg.ProduceTimeout)
	defer cancel()
	if err := s.data.Produce(pctx, idle); err != nil {
		s.cfg.Logf("idle records not written: %v", err)
	} else {
		for _, ns := range flushed {
			if err := s.commit(ns); err != nil {
				s.cfg.Logf("node %s: state write failed: %v", ns.node, err)
			}
		}
	}
	if err := s.hb.Produce(pctx, hbs); err != nil {
		s.cfg.Logf("heartbeats not written: %v", err)
	}
}

// mergeScope joins the scopes of two notices of one held gap: their key sets' union, or "" (any key)
// when either is unscoped.
func mergeScope(a, b string) string {
	const pre = "keys="
	if !strings.HasPrefix(a, pre) || !strings.HasPrefix(b, pre) {
		return ""
	}
	set := map[string]bool{}
	for _, part := range []string{a[len(pre):], b[len(pre):]} {
		for _, k := range strings.Split(part, "|") {
			if k != "" {
				set[k] = true
			}
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return pre + strings.Join(keys, "|")
}
