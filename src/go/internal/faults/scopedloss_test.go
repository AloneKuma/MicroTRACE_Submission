package faults

import (
	"strings"
	"testing"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
)

// ebpfEnv is an eBPF event with a process lineage and, when op != 0, a socket.
func ebpfEnv(lineage string, op pb.SocketOp, local, remote *pb.Endpoint) *pb.Envelope {
	rec := &pb.RawEbpfRecord{NodeId: "node-1", BootId: "boot-1", EventFamily: "proc.exec"}
	if op != pb.SocketOp_SOCKET_OP_UNSPECIFIED {
		rec.EventFamily = "net.connect"
		rec.Detail = &pb.RawEbpfRecord_Socket{Socket: &pb.SocketDetail{Op: op, Local: local, Remote: remote}}
	}
	ne := &pb.NormalizedEvent{Source: pb.Source_EBPF, Record: &pb.NormalizedEvent_Ebpf{Ebpf: rec}}
	if lineage != "" {
		ne.Derived = &pb.NormalizedEvent_EbpfDerived{EbpfDerived: &pb.EbpfDerived{LineageId: lineage}}
	}
	return &pb.Envelope{Payload: &pb.Envelope_NormalizedEvent{NormalizedEvent: ne}}
}

// The key strings must equal mtcore.orchestrator.keys.loss_keys (tests/test_scoped_loss.py).
func TestLossKeysMatchThePythonWitnessKeys(t *testing.T) {
	cl := &pb.Endpoint{Ip: "10.0.0.1", Port: 40000, Protocol: 6}
	sv := &pb.Endpoint{Ip: "10.0.0.2", Port: 8080}
	k, ok := view{"norm.events.v0", ebpfEnv("ln-1", pb.SocketOp_CONNECT, cl, sv)}.lossKeys()
	if !ok || strings.Join(k, " ") != "L:node-1:boot-1:ln-1 F:10.0.0.1:40000:10.0.0.2:8080:6" {
		t.Fatalf("connect keys %v %v", k, ok)
	}
	// the ACCEPT end of the same connection gives the same flow key
	k, ok = view{"norm.events.v0", ebpfEnv("", pb.SocketOp_ACCEPT, sv, cl)}.lossKeys()
	if !ok || strings.Join(k, " ") != "F:10.0.0.1:40000:10.0.0.2:8080:6" {
		t.Fatalf("accept keys %v %v", k, ok)
	}
	if _, ok := (view{"norm.events.v0", normEnv(1, pb.Source_AUDIT, "")}).lossKeys(); ok {
		t.Fatal("a non-eBPF record has no loss key")
	}
}

func TestLossScopeIsUnscopedWhenAnyItemHasNoKey(t *testing.T) {
	a := &pb.ShipItem{Topic: "norm.events.v0", Envelope: ebpfEnv("ln-2", 0, nil, nil)}
	b := &pb.ShipItem{Topic: "norm.events.v0", Envelope: ebpfEnv("ln-1", 0, nil, nil)}
	if s := lossScope([]*pb.ShipItem{a, b, a}); s != "keys=L:node-1:boot-1:ln-1|L:node-1:boot-1:ln-2" {
		t.Fatalf("scope %q", s)
	}
	c := &pb.ShipItem{Topic: "norm.events.v0", Envelope: normEnv(1, pb.Source_AUDIT, "")}
	if s := lossScope([]*pb.ShipItem{a, c}); s != "" {
		t.Fatalf("scope with a keyless item %q", s)
	}
}

func TestTransitGapNoticeCarriesTheLossScope(t *testing.T) {
	p := plan(t, "  - {id: x, kind: suppress, stage: transit, select: {logical_ids: [ev-3]}}\n")
	lg, _ := memLog(t, p)
	tr := NewTransit(p, lg)
	b := shipBatch(1, 4)
	b.Items[2].Envelope = ebpfEnv("ln-7", 0, nil, nil)
	b.Items[2].Envelope.LogicalId = "ev-3"
	var scope string
	for _, m := range tr.Batch(pb.Lane_NORMAL, b) {
		if g := m.GetGapNotice(); g != nil {
			scope = g.Scope
		}
	}
	if scope != "keys=L:node-1:boot-1:ln-7" {
		t.Fatalf("gap notice scope %q", scope)
	}
}
