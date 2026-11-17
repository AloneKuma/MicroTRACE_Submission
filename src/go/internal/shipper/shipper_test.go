package shipper

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/devpki"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/faults"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/receiver"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/tlsconf"
)

type sink struct {
	mu   sync.Mutex
	recs []*kgo.Record
}

func (s *sink) Produce(_ context.Context, recs []*kgo.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, recs...)
	return nil
}

func (s *sink) topic(name string) []*kgo.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*kgo.Record
	for _, r := range s.recs {
		if r.Topic == name {
			out = append(out, r)
		}
	}
	return out
}

type rig struct {
	pki   devpki.Files
	data  *sink
	addr  string
	stop  func()
	state string
}

func startReceiver(t *testing.T, pki devpki.Files, state, addr string) *rig {
	t.Helper()
	all, err := receiver.LoadTopics(filepath.Join("..", "..", "..", "..", "spec", "kafka", "topics.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	allowed, _ := receiver.Allow(all, "raw.ebpf.v0")
	data := &sink{}
	srv := receiver.New(receiver.Config{Instance: "rx", RunID: "t", Allowed: allowed,
		Completeness: all[receiver.CompletenessTopic], Partitions: map[string]int32{"raw.ebpf.v0": 1},
		StateDir: state, HeartbeatEvery: time.Hour, MaxIdle: time.Hour, ProduceTimeout: time.Second,
		Logf: t.Logf}, data, &sink{})
	tcfg, _ := tlsconf.Server(pki.ReceiverCert(), pki.ReceiverKey(), pki.CA())
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tcfg)))
	pb.RegisterIngestServer(gs, srv)
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	return &rig{pki: pki, data: data, addr: lis.Addr().String(), stop: gs.Stop, state: state}
}

func newShipper(t *testing.T, r *rig, spoolDir string, mod func(*Config)) *Shipper {
	t.Helper()
	tcfg, err := tlsconf.Client(r.pki.NodeCert("node-1"), r.pki.NodeKey("node-1"), r.pki.CA(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{NodeID: "node-1", BootID: "boot-1", Instance: "t", Addr: r.addr, TLS: tcfg,
		SpoolDir: spoolDir, BatchMax: 50, Linger: time.Millisecond, Logf: t.Logf}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mkItem(i int) *pb.ShipItem {
	return &pb.ShipItem{Topic: "raw.ebpf.v0", KeyType: pb.KeyType_KEY_NODE, KeyComponents: []string{"node-1"},
		Envelope: &pb.Envelope{SchemaMinor: 1, Kind: pb.RecordKind_RAW_EBPF, Source: pb.Source_EBPF,
			Payload: &pb.Envelope_RawEbpf{RawEbpf: &pb.RawEbpfRecord{NodeId: "node-1", NodeSeq: uint64(i)}}}}
}

func submit(t *testing.T, s *Shipper, lane pb.Lane, from, to int) {
	t.Helper()
	for i := from; i <= to; i++ {
		if err := s.Submit(lane, mkItem(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
}

// nodeSeqs returns the NodeSeq of each delivered raw.ebpf.v0 record, in order.
func nodeSeqs(t *testing.T, recs []*kgo.Record) []uint64 {
	var out []uint64
	for _, r := range recs {
		var env pb.Envelope
		if err := proto.Unmarshal(r.Value, &env); err != nil {
			t.Fatal(err)
		}
		out = append(out, env.GetRawEbpf().NodeSeq)
	}
	return out
}

func run(t *testing.T, s *Shipper, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := s.CloseInput(); err != nil {
		t.Fatal(err)
	}
	if err := s.Run(ctx, true); err != nil {
		t.Fatal(err)
	}
}

func pki(t *testing.T) devpki.Files {
	f, err := devpki.Generate(t.TempDir(), []string{"node-1"}, []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDeliversEverythingOnceInOrder(t *testing.T) {
	r := startReceiver(t, pki(t), t.TempDir(), "")
	s := newShipper(t, r, t.TempDir(), nil)
	submit(t, s, pb.Lane_NORMAL, 1, 1000)
	submit(t, s, pb.Lane_PRIORITY, 2001, 2010)
	run(t, s, 30*time.Second)
	got := nodeSeqs(t, r.data.topic("raw.ebpf.v0"))
	if len(got) != 1010 {
		t.Fatalf("delivered %d, want 1010", len(got))
	}
	var normal []uint64
	for _, n := range got {
		if n <= 1000 {
			normal = append(normal, n)
		}
	}
	for i, n := range normal {
		if n != uint64(i+1) {
			t.Fatalf("normal lane out of order at %d: %d", i, n)
		}
	}
}

type dropOnce struct {
	mu      sync.Mutex
	dropped map[uint64]bool
	targets map[uint64]bool
}

func (d *dropOnce) Batch(_ pb.Lane, b *pb.Batch) []*pb.NodeMessage {
	d.mu.Lock()
	defer d.mu.Unlock()
	f := b.Header.FirstSeq
	if d.targets[f] && !d.dropped[f] {
		d.dropped[f] = true
		return nil
	}
	return []*pb.NodeMessage{{Msg: &pb.NodeMessage_Batch{Batch: b}}}
}

// A batch lost in transit is recovered: a later batch triggers a nack, and a
// lost final batch is resent after the retransmit timeout.
func TestTransitLossIsRecovered(t *testing.T) {
	r := startReceiver(t, pki(t), t.TempDir(), "")
	d := &dropOnce{dropped: map[uint64]bool{}, targets: map[uint64]bool{1: true, 151: true}}
	s := newShipper(t, r, t.TempDir(), func(c *Config) {
		c.Transit, c.Retransmit, c.BatchMax, c.Linger = d, 300*time.Millisecond, 50, 0
	})
	submit(t, s, pb.Lane_NORMAL, 1, 200)
	run(t, s, 30*time.Second)
	got := nodeSeqs(t, r.data.topic("raw.ebpf.v0"))
	if len(got) != 200 || !d.dropped[1] || !d.dropped[151] {
		t.Fatalf("delivered %d, dropped %v", len(got), d.dropped)
	}
	for i, n := range got {
		if n != uint64(i+1) {
			t.Fatalf("out of order at %d: %d", i, n)
		}
	}
}

// T6 (unit part): spool overflow before the receiver is reachable is
// reported as exactly the dropped range; everything else arrives.
func TestSpoolOverflowIsReportedExactly(t *testing.T) {
	p := pki(t)
	r := startReceiver(t, p, t.TempDir(), "")
	size := len(mustMarshal(t, mkItem(1)))
	s := newShipper(t, r, t.TempDir(), func(c *Config) { c.SpoolMaxBytes = int64(size * 100) })
	submit(t, s, pb.Lane_NORMAL, 1, 130) // about 30 dropped
	run(t, s, 30*time.Second)
	st := s.Stats()["NORMAL"]
	if len(st.Gaps) != 1 {
		t.Fatalf("gaps %+v", st.Gaps)
	}
	g := st.Gaps[0]
	got := nodeSeqs(t, r.data.topic("raw.ebpf.v0"))
	if g.First != 1 || uint64(len(got)) != 130-g.Last || got[0] != g.Last+1 {
		t.Fatalf("gap %+v, delivered %d starting at %d", g, len(got), got[0])
	}
	cs := r.data.topic(receiver.CompletenessTopic)
	if len(cs) != 1 {
		t.Fatalf("%d completeness records", len(cs))
	}
	var env pb.Envelope
	proto.Unmarshal(cs[0].Value, &env)
	sc := env.GetSourceCompleteness()
	if sc.Source != pb.Source_EBPF || sc.Gaps[0].Reason != pb.GapReason_DROPPED_BEFORE {
		t.Fatalf("completeness %v", sc)
	}
}

func mustMarshal(t *testing.T, it *pb.ShipItem) []byte {
	it.Seq = 1
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// T2/T3 (unit part): receiver restart and shipper restart lose nothing.
func TestRestartsLoseNothing(t *testing.T) {
	p := pki(t)
	state, spoolDir := t.TempDir(), t.TempDir()
	r := startReceiver(t, p, state, "")
	s := newShipper(t, r, spoolDir, nil)
	submit(t, s, pb.Lane_NORMAL, 1, 300)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, false) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done
	s.Close()
	delivered := len(r.data.topic("raw.ebpf.v0"))
	r.stop()

	r2 := startReceiver(t, p, state, r.addr)
	r2.data.recs = nil
	s2 := newShipper(t, r2, spoolDir, nil)
	submit(t, s2, pb.Lane_NORMAL, 301, 400)
	run(t, s2, 30*time.Second)
	got := nodeSeqs(t, r2.data.topic("raw.ebpf.v0"))
	if delivered+len(got) != 400 {
		t.Fatalf("first run %d + second run %d != 400", delivered, len(got))
	}
	if len(got) > 0 && got[0] != uint64(delivered+1) {
		t.Fatalf("second run starts at %d, want %d", got[0], delivered+1)
	}
}

// Transit-stage loss: exactly the unselected records arrive, and the
// receiver's completeness records name exactly the dropped sequences.
func TestTransitFaultLossIsExactAndReported(t *testing.T) {
	r := startReceiver(t, pki(t), t.TempDir(), "")
	plan, err := faults.Parse([]byte("version: faultplan.v0\nseed: 3\nfaults:\n  - {id: l20, kind: loss, stage: transit, rate: 0.2}\n"))
	if err != nil {
		t.Fatal(err)
	}
	flog, err := faults.OpenLog("", plan, faults.StageTransit, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	s := newShipper(t, r, t.TempDir(), func(c *Config) { c.Transit = faults.NewTransit(plan, flog) })
	n := 2000
	for i := 1; i <= n; i++ {
		it := mkItem(i)
		it.Envelope.LogicalId = fmt.Sprintf("ev-%d", i)
		if err := s.Submit(pb.Lane_NORMAL, it); err != nil {
			t.Fatal(err)
		}
	}
	s.Sync()
	run(t, s, 30*time.Second)
	got := map[uint64]bool{}
	for _, seq := range nodeSeqs(t, r.data.topic("raw.ebpf.v0")) {
		if got[seq] {
			t.Fatalf("seq %d delivered twice", seq)
		}
		got[seq] = true
	}
	dropped := 0
	for i := 1; i <= n; i++ {
		picked := plan.Picked(plan.Faults[0], fmt.Sprintf("ev-%d", i))
		if picked == got[uint64(i)] {
			t.Fatalf("record %d: picked=%v delivered=%v", i, picked, got[uint64(i)])
		}
		if picked {
			dropped++
		}
	}
	covered := 0
	for _, rec := range r.data.topic(receiver.CompletenessTopic) {
		var env pb.Envelope
		proto.Unmarshal(rec.Value, &env)
		var a, b int
		if _, err := fmt.Sscanf(env.GetSourceCompleteness().Gaps[0].Detail, "transport seq %d-%d", &a, &b); err != nil {
			t.Fatal(err)
		}
		for i := a; i <= b; i++ {
			if got[uint64(i)] {
				t.Fatalf("seq %d both delivered and reported lost", i)
			}
			covered++
		}
	}
	if covered != dropped || dropped == 0 {
		t.Fatalf("reported %d lost, dropped %d", covered, dropped)
	}
}
