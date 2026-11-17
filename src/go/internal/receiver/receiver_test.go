package receiver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/devpki"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/mtkey"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/tlsconf"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/wire"
)

type fakeProducer struct {
	mu    sync.Mutex
	recs  []*kgo.Record
	fails int
}

func (f *fakeProducer) Produce(_ context.Context, recs []*kgo.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return errors.New("broker unavailable")
	}
	f.recs = append(f.recs, recs...)
	return nil
}

func (f *fakeProducer) byTopic(topic string) []*kgo.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*kgo.Record
	for _, r := range f.recs {
		if r.Topic == topic {
			out = append(out, r)
		}
	}
	return out
}

type env struct {
	t     *testing.T
	pki   devpki.Files
	srv   *Server
	data  *fakeProducer
	hb    *fakeProducer
	addr  string
	state string
	stop  func()
}

func topicsPath() string {
	return filepath.Join("..", "..", "..", "..", "spec", "kafka", "topics.yaml")
}

func newEnv(t *testing.T, pki *devpki.Files, state string) *env {
	t.Helper()
	if pki == nil {
		f, err := devpki.Generate(t.TempDir(), []string{"node-1", "node-2"}, []string{"127.0.0.1"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		pki = &f
	}
	if state == "" {
		state = t.TempDir()
	}
	all, err := LoadTopics(topicsPath())
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := Allow(all, "raw.ebpf.v0,norm.events.v0")
	if err != nil {
		t.Fatal(err)
	}
	data, hb := &fakeProducer{}, &fakeProducer{}
	srv := New(Config{Instance: "rx-test", RunID: "test", Allowed: allowed, Completeness: all[CompletenessTopic],
		Partitions: map[string]int32{"raw.ebpf.v0": 3, "norm.events.v0": 2}, StateDir: state,
		HeartbeatEvery: time.Hour, MaxIdle: time.Hour, ProduceTimeout: time.Second,
		Logf: t.Logf}, data, hb)
	tcfg, err := tlsconf.Server(pki.ReceiverCert(), pki.ReceiverKey(), pki.CA())
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tcfg)))
	pb.RegisterIngestServer(gs, srv)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go gs.Serve(lis)
	e := &env{t: t, pki: *pki, srv: srv, data: data, hb: hb, addr: lis.Addr().String(), state: state}
	e.stop = gs.Stop
	t.Cleanup(gs.Stop)
	return e
}

type client struct {
	t      *testing.T
	conn   *grpc.ClientConn
	stream pb.Ingest_ShipClient
}

func (e *env) dial(certNode, helloNode string, tcfg *tls.Config) (*client, *pb.ReceiverMessage, error) {
	e.t.Helper()
	if tcfg == nil {
		var err error
		tcfg, err = tlsconf.Client(e.pki.NodeCert(certNode), e.pki.NodeKey(certNode), e.pki.CA(), "127.0.0.1")
		if err != nil {
			e.t.Fatal(err)
		}
	}
	conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(tcfg)))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { conn.Close() })
	stream, err := pb.NewIngestClient(conn).Ship(context.Background())
	if err != nil {
		return nil, nil, err
	}
	hello := &pb.Hello{NodeId: helloNode, BootId: "boot-1", AgentInstance: "test", SchemaVersion: wire.SchemaVersion}
	if err := stream.Send(&pb.NodeMessage{Msg: &pb.NodeMessage_Hello{Hello: hello}}); err != nil {
		return nil, nil, err
	}
	first, err := stream.Recv()
	return &client{t: e.t, conn: conn, stream: stream}, first, err
}

func item(seq uint64, node string) *pb.ShipItem {
	return &pb.ShipItem{Seq: seq, Topic: "raw.ebpf.v0", KeyType: pb.KeyType_KEY_NODE, KeyComponents: []string{node},
		Envelope: &pb.Envelope{SchemaMajor: 0, SchemaMinor: 1, ProducerId: "node-sensor", Kind: pb.RecordKind_RAW_EBPF,
			Source: pb.Source_EBPF, Payload: &pb.Envelope_RawEbpf{RawEbpf: &pb.RawEbpfRecord{NodeId: node, NodeSeq: seq}}}}
}

func batch(lane pb.Lane, items ...*pb.ShipItem) *pb.NodeMessage {
	sum, _ := wire.HashItems(items)
	return &pb.NodeMessage{Msg: &pb.NodeMessage_Batch{Batch: &pb.Batch{Header: &pb.BatchHeader{
		NodeId: "node-1", BootId: "boot-1", Lane: lane, FirstSeq: items[0].Seq, Count: uint32(len(items)),
		SchemaVersion: wire.SchemaVersion, PayloadSha256: sum}, Items: items}}}
}

func (c *client) send(m *pb.NodeMessage) *pb.ReceiverMessage {
	c.t.Helper()
	if err := c.stream.Send(m); err != nil {
		c.t.Fatal(err)
	}
	r, err := c.stream.Recv()
	if err != nil {
		c.t.Fatal(err)
	}
	return r
}

func wantAck(t *testing.T, r *pb.ReceiverMessage, through uint64) {
	t.Helper()
	if r.GetAck() == nil || r.GetAck().AckedThrough != through {
		t.Fatalf("want Ack(%d), got %v", through, r)
	}
}

func TestInOrderDuplicateAndJump(t *testing.T) {
	e := newEnv(t, nil, "")
	c, w, err := e.dial("node-1", "node-1", nil)
	if err != nil || w.GetWelcome() == nil {
		t.Fatalf("welcome: %v %v", w, err)
	}
	for _, p := range w.GetWelcome().Positions {
		if p.NextExpectedSeq != 1 {
			t.Fatalf("fresh position %v", p)
		}
	}
	wantAck(t, c.send(batch(pb.Lane_NORMAL, item(1, "node-1"), item(2, "node-1"))), 2)
	wantAck(t, c.send(batch(pb.Lane_NORMAL, item(1, "node-1"), item(2, "node-1"))), 2) // duplicate
	r := c.send(batch(pb.Lane_NORMAL, item(5, "node-1")))
	if r.GetNack() == nil || r.GetNack().FromSeq != 3 {
		t.Fatalf("want Nack(3), got %v", r)
	}
	wantAck(t, c.send(batch(pb.Lane_NORMAL, item(2, "node-1"), item(3, "node-1"))), 3) // overlap: only 3 is new
	recs := e.data.byTopic("raw.ebpf.v0")
	if len(recs) != 3 {
		t.Fatalf("wrote %d records, want 3", len(recs))
	}
	wantKey, _ := mtkey.Encode(uint16(pb.KeyType_KEY_NODE), []mtkey.Component{{Code: uint8(pb.KeyComponent_NODE_ID), Value: "node-1"}})
	for i, r := range recs {
		var got pb.Envelope
		if err := proto.Unmarshal(r.Value, &got); err != nil {
			t.Fatal(err)
		}
		if got.GetRawEbpf().NodeSeq != uint64(i+1) || string(r.Key) != string(wantKey) {
			t.Fatalf("record %d: seq %d key %x", i, got.GetRawEbpf().NodeSeq, r.Key)
		}
	}
	// Lanes are independent.
	wantAck(t, c.send(batch(pb.Lane_PRIORITY, item(1, "node-1"))), 1)
}

// normItem is a normalized event on norm.events.v0 with an event time.
func normItem(seq uint64, at time.Time) *pb.ShipItem {
	return &pb.ShipItem{Seq: seq, Topic: "norm.events.v0", KeyType: pb.KeyType_KEY_PRIMARY_ENTITY,
		KeyComponents: []string{"POD", "pod-1"},
		Envelope: &pb.Envelope{SchemaMajor: 0, SchemaMinor: 1, ProducerId: "normalizer", Kind: pb.RecordKind_NORMALIZED_EVENT,
			Source: pb.Source_AUDIT, Payload: &pb.Envelope_NormalizedEvent{NormalizedEvent: &pb.NormalizedEvent{
				EventId: fmt.Sprintf("ev-%d", seq), Source: pb.Source_AUDIT,
				Time: &pb.TimeInfo{EventTime: timestamppb.New(at)}}}}}
}

func completeness(t *testing.T, e *env) []*pb.SourceCompleteness {
	t.Helper()
	var out []*pb.SourceCompleteness
	for _, r := range e.data.byTopic(CompletenessTopic) {
		var got pb.Envelope
		if err := proto.Unmarshal(r.Value, &got); err != nil {
			t.Fatal(err)
		}
		out = append(out, got.GetSourceCompleteness())
	}
	return out
}

func gapNotice(first, last uint64, from, to *timestamppb.Timestamp) *pb.NodeMessage {
	return &pb.NodeMessage{Msg: &pb.NodeMessage_GapNotice{GapNotice: &pb.GapNotice{Lane: pb.Lane_NORMAL,
		FirstSeq: first, LastSeq: last, Reason: pb.GapReason_DROPPED_BEFORE, Detail: "spool overflow",
		Sources: []pb.Source{pb.Source_EBPF}, From: from, To: to}}}
}

func TestGapNoticeWritesCompletenessAndAdvances(t *testing.T) {
	e := newEnv(t, nil, "")
	c, _, _ := e.dial("node-1", "node-1", nil)
	t1, t2 := time.Unix(1000, 0).UTC(), time.Unix(1005, 0).UTC()
	g := gapNotice(1, 4, timestamppb.New(t1), timestamppb.New(t2))
	wantAck(t, c.send(g), 4)
	scs := completeness(t, e)
	if len(scs) != 1 {
		t.Fatalf("%d completeness records", len(scs))
	}
	sc := scs[0]
	if sc.Status != pb.CompletenessStatus_INCOMPLETE || sc.Source != pb.Source_EBPF ||
		sc.Scope != "node=node-1/boot=boot-1/lane=NORMAL" || len(sc.Gaps) != 1 ||
		sc.Gaps[0].Reason != pb.GapReason_DROPPED_BEFORE || !strings.Contains(sc.Gaps[0].Detail, "seq 1-4") ||
		!sc.IntervalStart.AsTime().Equal(t1) || !sc.IntervalEnd.AsTime().Equal(t2) ||
		!sc.Gaps[0].From.AsTime().Equal(t1) || !sc.Gaps[0].To.AsTime().Equal(t2) {
		t.Fatalf("completeness %v", sc)
	}
	wantAck(t, c.send(batch(pb.Lane_NORMAL, item(5, "node-1"))), 5)
	// A gap notice not starting at the expected sequence is refused.
	g.GetGapNotice().FirstSeq, g.GetGapNotice().LastSeq = 9, 10
	if r := c.send(g); r.GetNack() == nil || r.GetNack().FromSeq != 6 {
		t.Fatalf("want Nack(6), got %v", r)
	}
}

// A gap without times is held, across a receiver restart, until the next
// accepted item: from = last accepted event time, to = that item's time.
func TestUntimedGapHeldUntilNextItem(t *testing.T) {
	pki, _ := devpki.Generate(t.TempDir(), []string{"node-1"}, []string{"127.0.0.1"}, time.Hour)
	state := t.TempDir()
	e := newEnv(t, &pki, state)
	c, _, _ := e.dial("node-1", "node-1", nil)
	t1, t2, t3 := time.Unix(2000, 0).UTC(), time.Unix(2001, 0).UTC(), time.Unix(2010, 0).UTC()
	wantAck(t, c.send(batch(pb.Lane_NORMAL, normItem(1, t2), normItem(2, t1))), 2) // latest is t2
	wantAck(t, c.send(gapNotice(3, 5, nil, nil)), 5)
	wantAck(t, c.send(gapNotice(6, 6, nil, nil)), 6) // extends the held gap
	if n := len(completeness(t, e)); n != 0 {
		t.Fatalf("%d completeness records before the next item", n)
	}
	e.stop()
	e2 := newEnv(t, &pki, state)
	c2, w, err := e2.dial("node-1", "node-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range w.GetWelcome().Positions {
		if p.Lane == pb.Lane_NORMAL && p.NextExpectedSeq != 7 {
			t.Fatalf("after restart %v", p)
		}
	}
	wantAck(t, c2.send(batch(pb.Lane_NORMAL, normItem(7, t3))), 7)
	scs := completeness(t, e2)
	if len(scs) != 1 {
		t.Fatalf("%d completeness records", len(scs))
	}
	sc := scs[0]
	if !sc.IntervalStart.AsTime().Equal(t2) || !sc.IntervalEnd.AsTime().Equal(t3) ||
		!strings.Contains(sc.Gaps[0].Detail, "seq 3-6") || sc.Source != pb.Source_EBPF {
		t.Fatalf("completeness %v", sc)
	}
	wantAck(t, c2.send(batch(pb.Lane_NORMAL, normItem(8, t3))), 8)
	if n := len(completeness(t, e2)); n != 1 {
		t.Fatalf("gap written %d times", n)
	}
}

// A held gap whose node goes idle is written open-ended, once.
func TestUntimedGapFlushedOpenEndedOnIdle(t *testing.T) {
	e := newEnv(t, nil, "")
	e.srv.cfg.MaxIdle = time.Millisecond
	c, _, _ := e.dial("node-1", "node-1", nil)
	wantAck(t, c.send(gapNotice(1, 2, nil, nil)), 2)
	c.conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		time.Sleep(20 * time.Millisecond)
		e.srv.tick(context.Background())
		var transport []*pb.SourceCompleteness
		for _, sc := range completeness(t, e) {
			if sc.Gaps[0].Reason == pb.GapReason_DROPPED_BEFORE {
				transport = append(transport, sc)
			}
		}
		if len(transport) == 1 {
			if transport[0].IntervalStart != nil || transport[0].IntervalEnd != nil {
				t.Fatalf("want open-ended gap, got %v", transport[0])
			}
			e.srv.tick(context.Background())
			if n := len(completeness(t, e)); n > 2 { // the gap and the SOURCE_IDLE record
				t.Fatalf("%d completeness records after a second tick", n)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("held gap not flushed: %v", completeness(t, e))
		}
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	pki, _ := devpki.Generate(t.TempDir(), []string{"node-1"}, []string{"127.0.0.1"}, time.Hour)
	state := t.TempDir()
	e := newEnv(t, &pki, state)
	c, _, _ := e.dial("node-1", "node-1", nil)
	wantAck(t, c.send(batch(pb.Lane_NORMAL, item(1, "node-1"), item(2, "node-1"), item(3, "node-1"))), 3)
	e.stop()
	e2 := newEnv(t, &pki, state)
	_, w, err := e2.dial("node-1", "node-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range w.GetWelcome().Positions {
		want := uint64(1)
		if p.Lane == pb.Lane_NORMAL {
			want = 4
		}
		if p.NextExpectedSeq != want {
			t.Fatalf("after restart %v", p)
		}
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]func(m *pb.NodeMessage){
		"payload_sha256 mismatch": func(m *pb.NodeMessage) { m.GetBatch().Header.PayloadSha256 = "00" },
		"not allowed": func(m *pb.NodeMessage) {
			m.GetBatch().Items[0].Topic = "findings.v0"
			m.GetBatch().Header.PayloadSha256, _ = wire.HashItems(m.GetBatch().Items)
		},
		"identity differs": func(m *pb.NodeMessage) { m.GetBatch().Header.NodeId = "node-2" },
		"key type": func(m *pb.NodeMessage) {
			m.GetBatch().Items[0].KeyType = pb.KeyType_KEY_POD
			m.GetBatch().Header.PayloadSha256, _ = wire.HashItems(m.GetBatch().Items)
		},
	}
	for want, mutate := range cases {
		e := newEnv(t, nil, "")
		c, _, _ := e.dial("node-1", "node-1", nil)
		m := batch(pb.Lane_NORMAL, item(1, "node-1"))
		mutate(m)
		r := c.send(m)
		if r.GetReject() == nil || !strings.Contains(r.GetReject().Reason, want) {
			t.Fatalf("%s: got %v", want, r)
		}
		if n := len(e.data.byTopic("raw.ebpf.v0")); n != 0 {
			t.Fatalf("%s: %d records written", want, n)
		}
	}
}

// T7: identity and TLS version are enforced; nothing is written.
func TestIdentityAndTLSEnforced(t *testing.T) {
	e := newEnv(t, nil, "")
	_, r, err := e.dial("node-2", "node-1", nil)
	if err != nil || r.GetReject() == nil || !strings.Contains(r.GetReject().Reason, "does not match certificate") {
		t.Fatalf("impersonation: %v %v", r, err)
	}
	ca, _ := tlsconf.Client(e.pki.NodeCert("node-1"), e.pki.NodeKey("node-1"), e.pki.CA(), "127.0.0.1")
	noCert := ca.Clone()
	noCert.Certificates = nil
	if _, _, err := e.dial("", "node-1", noCert); err == nil {
		t.Fatal("client without certificate accepted")
	}
	tls12 := ca.Clone()
	tls12.MinVersion, tls12.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if _, _, err := e.dial("", "node-1", tls12); err == nil {
		t.Fatal("TLS 1.2 client accepted")
	}
	if n := len(e.data.recs); n != 0 {
		t.Fatalf("%d records written", n)
	}
}

func TestKafkaFailureNacksThenRecovers(t *testing.T) {
	e := newEnv(t, nil, "")
	e.data.fails = 1
	c, _, _ := e.dial("node-1", "node-1", nil)
	r := c.send(batch(pb.Lane_NORMAL, item(1, "node-1")))
	if r.GetNack() == nil || r.GetNack().FromSeq != 1 {
		t.Fatalf("want Nack(1), got %v", r)
	}
	wantAck(t, c.send(batch(pb.Lane_NORMAL, item(1, "node-1"))), 1)
}

// T8 (unit part): heartbeats on every partition; watermark is the minimum
// over active lanes and never moves back; idle nodes are reported.
func TestHeartbeatsWatermarkAndIdle(t *testing.T) {
	e := newEnv(t, nil, "")
	e.srv.tick(context.Background())
	hbs := e.hb.byTopic("raw.ebpf.v0")
	if len(hbs) != 3 {
		t.Fatalf("%d heartbeats on raw.ebpf.v0, want 3", len(hbs))
	}
	for i, r := range hbs {
		if r.Partition != int32(i) {
			t.Fatalf("heartbeat %d on partition %d", i, r.Partition)
		}
	}
	c, _, _ := e.dial("node-1", "node-1", nil)
	t1 := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	m := batch(pb.Lane_NORMAL, item(1, "node-1"))
	m.GetBatch().Header.LowWatermark = timestamppb.New(t1)
	wantAck(t, c.send(m), 1)
	e.hb.recs = nil
	e.srv.tick(context.Background())
	var env pb.Envelope
	proto.Unmarshal(e.hb.byTopic("raw.ebpf.v0")[0].Value, &env)
	if !env.GetHeartbeat().LowWatermark.AsTime().Equal(t1) {
		t.Fatalf("watermark %v want %v", env.GetHeartbeat().LowWatermark.AsTime(), t1)
	}
	// Idle: disconnect, make the node stale, tick.
	c.conn.Close()
	time.Sleep(100 * time.Millisecond)
	e.srv.mu.Lock()
	e.srv.cfg.MaxIdle = time.Millisecond
	for _, ns := range e.srv.streams {
		ns.connected = false
		ns.lastSeen = time.Now().Add(-time.Second)
	}
	e.srv.mu.Unlock()
	e.hb.recs = nil
	e.srv.tick(context.Background())
	var idle []*pb.SourceCompleteness
	for _, r := range e.data.byTopic(CompletenessTopic) {
		var env pb.Envelope
		proto.Unmarshal(r.Value, &env)
		if sc := env.GetSourceCompleteness(); sc.Gaps[0].Reason == pb.GapReason_SOURCE_IDLE {
			idle = append(idle, sc)
		}
	}
	if len(idle) != 1 || idle[0].Scope != "node=node-1/boot=boot-1" {
		t.Fatalf("idle records %v", idle)
	}
	proto.Unmarshal(e.hb.byTopic("raw.ebpf.v0")[0].Value, &env)
	if env.GetHeartbeat().LowWatermark.AsTime().Before(t1) {
		t.Fatal("watermark moved backwards after the node went idle")
	}
}

func idleRecords(t *testing.T, e *env) []*pb.SourceCompleteness {
	t.Helper()
	var out []*pb.SourceCompleteness
	for _, sc := range completeness(t, e) {
		if sc.Gaps[0].Reason == pb.GapReason_SOURCE_IDLE {
			out = append(out, sc)
		}
	}
	return out
}

func makeIdle(e *env) {
	e.srv.mu.Lock()
	e.srv.cfg.MaxIdle = time.Millisecond
	for _, ns := range e.srv.streams {
		ns.connected = false
		ns.lastSeen = time.Now().Add(-time.Second)
	}
	e.srv.mu.Unlock()
	e.srv.tick(context.Background())
}

// An idle gap is in event time: open-ended from the node's latest accepted
// event, written once, and closed (across a receiver restart) by the next
// timed item, whose event time ends it.
func TestIdleGapInEventTimeClosedByNextItem(t *testing.T) {
	pki, _ := devpki.Generate(t.TempDir(), []string{"node-1"}, []string{"127.0.0.1"}, time.Hour)
	state := t.TempDir()
	e := newEnv(t, &pki, state)
	c, _, _ := e.dial("node-1", "node-1", nil)
	t1, t2, t3 := time.Unix(3000, 0).UTC(), time.Unix(3005, 0).UTC(), time.Unix(3100, 0).UTC()
	wantAck(t, c.send(batch(pb.Lane_NORMAL, normItem(1, t2), normItem(2, t1))), 2)
	c.conn.Close()
	time.Sleep(100 * time.Millisecond)
	makeIdle(e)
	makeIdle(e) // a second tick writes nothing new
	idle := idleRecords(t, e)
	if len(idle) != 1 || !idle[0].IntervalStart.AsTime().Equal(t2) || idle[0].IntervalEnd != nil ||
		idle[0].Gaps[0].To != nil || idle[0].Source != pb.Source_SOURCE_UNSPECIFIED {
		t.Fatalf("open idle record %v", idle)
	}
	e.stop()
	e2 := newEnv(t, &pki, state)
	c2, _, err := e2.dial("node-1", "node-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	wantAck(t, c2.send(batch(pb.Lane_NORMAL, normItem(3, t3))), 3)
	idle = idleRecords(t, e2)
	if len(idle) != 1 || !idle[0].IntervalStart.AsTime().Equal(t2) || !idle[0].IntervalEnd.AsTime().Equal(t3) ||
		idle[0].Scope != "node=node-1/boot=boot-1" {
		t.Fatalf("closing idle record %v", idle)
	}
	wantAck(t, c2.send(batch(pb.Lane_NORMAL, normItem(4, t3))), 4)
	if n := len(idleRecords(t, e2)); n != 1 {
		t.Fatalf("idle gap closed %d times", n)
	}
}

func TestMergeScopeUnionsKeysAndDropsToUnscoped(t *testing.T) {
	if s := mergeScope("keys=b|a", "keys=c|a"); s != "keys=a|b|c" {
		t.Fatalf("merge %q", s)
	}
	if s := mergeScope("keys=a", ""); s != "" {
		t.Fatalf("merge with an unscoped notice %q", s)
	}
}
