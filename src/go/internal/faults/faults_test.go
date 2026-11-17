package faults

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/wire"
)

var t0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func normEnv(i int, src pb.Source, family string) *pb.Envelope {
	ne := &pb.NormalizedEvent{EventId: fmt.Sprintf("ev-%d", i), Source: src,
		Time: &pb.TimeInfo{EventTime: timestamppb.New(t0.Add(time.Duration(i) * time.Second)),
			SourceTime: timestamppb.New(t0.Add(time.Duration(i) * time.Second)), ClockUncertaintyNs: 1000}}
	if family != "" {
		ne.Record = &pb.NormalizedEvent_Ebpf{Ebpf: &pb.RawEbpfRecord{EventFamily: family}}
	}
	return &pb.Envelope{SchemaMinor: 1, Kind: pb.RecordKind_NORMALIZED_EVENT, Source: src,
		LogicalId: fmt.Sprintf("ev-%d", i), Payload: &pb.Envelope_NormalizedEvent{NormalizedEvent: ne}}
}

// stream builds n normalized-event lines, one second apart.
func stream(t *testing.T, n int, src pb.Source, family string) []*Line {
	t.Helper()
	var buf bytes.Buffer
	for i := 1; i <= n; i++ {
		env, _ := protojson.Marshal(normEnv(i, src, family))
		l := map[string]any{"lane": "NORMAL", "topic": "norm.events.v0", "key_type": "KEY_PRIMARY_ENTITY",
			"key_components": []string{"Pod", "uid"}, "envelope": json.RawMessage(env)}
		b, _ := json.Marshal(l)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	lines, err := ReadLines(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

func plan(t *testing.T, y string) *Plan {
	t.Helper()
	p, err := Parse([]byte("version: faultplan.v0\nseed: 7\nfaults:\n" + y))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ids(lines []*Line) []string {
	var out []string
	for _, l := range lines {
		if !l.IsWatermark() {
			out = append(out, l.env.LogicalId)
		}
	}
	return out
}

func memLog(t *testing.T, p *Plan) (*Log, *bytes.Buffer) {
	var b bytes.Buffer
	l := &Log{w: &b}
	l.enc = json.NewEncoder(&b)
	return l, &b
}

func entries(t *testing.T, b *bytes.Buffer) []Entry {
	var out []Entry
	for _, ln := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if ln == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestPlanValidation(t *testing.T) {
	bad := map[string]string{
		"unknown kind":      "  - {id: a, kind: melt, stage: source}\n",
		"cannot use stage":  "  - {id: a, kind: skew, stage: transit, offset: 1s}\n",
		"loss needs rate":   "  - {id: a, kind: loss, stage: source}\n",
		"outage needs":      "  - {id: a, kind: outage, stage: source}\n",
		"duplicate":         "  - {id: a, kind: loss, stage: source, rate: 0.1}\n  - {id: a, kind: loss, stage: source, rate: 0.1}\n",
		"unknown source":    "  - {id: a, kind: loss, stage: source, rate: 0.1, select: {sources: [NOPE]}}\n",
		"rate":              "  - {id: a, kind: loss, stage: source, rate: 1.5}\n",
		"blind needs after": "  - {id: a, kind: blind, stage: source}\n",
	}
	for want, y := range bad {
		_, err := Parse([]byte("version: faultplan.v0\nseed: 1\nfaults:\n" + y))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got %v", want, err)
		}
	}
	if _, err := Load("../../../../spec/faults/example-plan.yaml"); err != nil {
		t.Fatalf("example plan: %v", err)
	}
}

func TestSelectionDeterministicAndRateBounded(t *testing.T) {
	p := plan(t, "  - {id: l, kind: loss, stage: source, rate: 0.2}\n")
	f := p.Faults[0]
	n, picked := 10000, 0
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("ev-%d", i)
		a, b := p.Picked(f, id), p.Picked(f, id)
		if a != b {
			t.Fatal("selection not deterministic")
		}
		if a {
			picked++
		}
	}
	sd := math.Sqrt(float64(n) * 0.2 * 0.8)
	if math.Abs(float64(picked)-2000) > 4*sd {
		t.Fatalf("picked %d of %d at rate 0.2 (4 sd = %.0f)", picked, n, 4*sd)
	}
	// A different seed picks differently.
	q := plan(t, "  - {id: l, kind: loss, stage: source, rate: 0.2}\n")
	q.Seed = 8
	same := 0
	for i := 0; i < n; i++ {
		if p.Picked(f, fmt.Sprintf("ev-%d", i)) == q.Picked(q.Faults[0], fmt.Sprintf("ev-%d", i)) {
			same++
		}
	}
	if same == n {
		t.Fatal("seed has no effect")
	}
}

func TestSkewShiftsTimesAndDeclaresUncertainty(t *testing.T) {
	for _, declare := range []bool{false, true} {
		p := plan(t, fmt.Sprintf("  - {id: s, kind: skew, stage: source, offset: -250ms, declare_uncertainty: %v}\n", declare))
		lg, _ := memLog(t, p)
		out, err := ApplySource(p, stream(t, 3, pb.Source_EBPF, ""), lg)
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range out {
			b, _ := l.Bytes()
			var back Line
			json.Unmarshal(b, &back)
			env := &pb.Envelope{}
			if err := protojson.Unmarshal(back.Envelope, env); err != nil {
				t.Fatal(err)
			}
			ti := env.GetNormalizedEvent().Time
			want := t0.Add(time.Duration(i+1)*time.Second - 250*time.Millisecond)
			if !ti.EventTime.AsTime().Equal(want) || !ti.SourceTime.AsTime().Equal(want) {
				t.Fatalf("event %v source %v want %v", ti.EventTime.AsTime(), ti.SourceTime.AsTime(), want)
			}
			wantU := uint64(1000)
			if declare {
				wantU = uint64(250 * time.Millisecond)
			}
			if ti.ClockUncertaintyNs != wantU {
				t.Fatalf("declare=%v uncertainty %d want %d", declare, ti.ClockUncertaintyNs, wantU)
			}
		}
	}
}

func TestDelayReorders(t *testing.T) {
	p := plan(t, "  - {id: d, kind: delay, stage: source, delay: 2500ms, select: {logical_ids: [ev-2]}}\n")
	lg, b := memLog(t, p)
	out, _ := ApplySource(p, stream(t, 5, pb.Source_EBPF, ""), lg)
	if got := strings.Join(ids(out), ","); got != "ev-1,ev-3,ev-4,ev-2,ev-5" {
		t.Fatalf("order %s", got)
	}
	if e := entries(t, b); len(e) != 1 || e[0].Action != ActDelayed || e[0].LogicalID != "ev-2" {
		t.Fatalf("log %+v", e)
	}
}

func TestOutageBlindStopSuppress(t *testing.T) {
	cases := []struct {
		y    string
		fam  string
		want string
	}{
		{"  - {id: o, kind: outage, stage: source, select: {from: \"2026-10-08T12:00:02Z\", to: \"2026-10-08T12:00:04Z\"}}\n", "",
			"ev-1,ev-4,ev-5"},
		{"  - {id: b, kind: blind, stage: source, after: \"2026-10-08T12:00:03Z\", select: {event_families: [file.read]}}\n", "file.read",
			"ev-1,ev-2"},
		{"  - {id: s, kind: stop, stage: source, after: \"2026-10-08T12:00:04Z\"}\n", "", "ev-1,ev-2,ev-3"},
		{"  - {id: x, kind: suppress, stage: source, select: {logical_ids: [ev-3]}}\n", "", "ev-1,ev-2,ev-4,ev-5"},
	}
	for _, c := range cases {
		p := plan(t, c.y)
		lg, b := memLog(t, p)
		out, err := ApplySource(p, stream(t, 5, pb.Source_EBPF, c.fam), lg)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(ids(out), ","); got != c.want {
			t.Fatalf("%s: got %s want %s", p.Faults[0].Kind, got, c.want)
		}
		if n := len(entries(t, b)); n != 5-len(ids(out)) {
			t.Fatalf("%s: %d log entries for %d drops", p.Faults[0].Kind, n, 5-len(ids(out)))
		}
	}
	// Blind leaves other families alone.
	p := plan(t, "  - {id: b, kind: blind, stage: source, after: \"2026-10-08T12:00:03Z\", select: {event_families: [file.read]}}\n")
	lg, _ := memLog(t, p)
	out, _ := ApplySource(p, stream(t, 5, pb.Source_EBPF, "net.connect"), lg)
	if len(out) != 5 {
		t.Fatalf("blind dropped another family: %d left", len(out))
	}
}

func TestForgeInsertsCount(t *testing.T) {
	p := plan(t, "  - {id: f, kind: forge, stage: source, after: \"2026-10-08T12:00:02Z\", count: 3}\n")
	lg, b := memLog(t, p)
	out, _ := ApplySource(p, stream(t, 4, pb.Source_EBPF, ""), lg)
	got := strings.Join(ids(out), ",")
	if got != "ev-1,ev-2,forged-f-1,forged-f-2,forged-f-3,ev-3,ev-4" {
		t.Fatalf("order %s", got)
	}
	if e := entries(t, b); len(e) != 3 || e[0].Action != ActForged {
		t.Fatalf("log %+v", e)
	}
}

func TestSourceLossMatchesPicked(t *testing.T) {
	p := plan(t, "  - {id: l, kind: loss, stage: source, rate: 0.3}\n")
	lg, _ := memLog(t, p)
	in := stream(t, 200, pb.Source_EBPF, "")
	out, _ := ApplySource(p, in, lg)
	kept := map[string]bool{}
	for _, id := range ids(out) {
		kept[id] = true
	}
	for i := 1; i <= 200; i++ {
		id := fmt.Sprintf("ev-%d", i)
		if p.Picked(p.Faults[0], id) == kept[id] {
			t.Fatalf("%s: picked=%v kept=%v", id, p.Picked(p.Faults[0], id), kept[id])
		}
	}
}

func shipBatch(first uint64, n int) *pb.Batch {
	var items []*pb.ShipItem
	for i := 0; i < n; i++ {
		items = append(items, &pb.ShipItem{Seq: first + uint64(i), Topic: "norm.events.v0",
			Envelope: normEnv(int(first)+i, pb.Source_AUDIT, "")})
	}
	sum, _ := wire.HashItems(items)
	return &pb.Batch{Header: &pb.BatchHeader{NodeId: "n", BootId: "b", Lane: pb.Lane_NORMAL, FirstSeq: first,
		Count: uint32(n), PayloadSha256: sum}, Items: items}
}

func TestTransitSplitsIntoBatchesAndExactGaps(t *testing.T) {
	p := plan(t, "  - {id: x, kind: suppress, stage: transit, select: {logical_ids: [ev-3, ev-4, ev-7]}}\n")
	lg, b := memLog(t, p)
	tr := NewTransit(p, lg)
	for pass := 0; pass < 2; pass++ { // a retransmission must give the same messages
		msgs := tr.Batch(pb.Lane_NORMAL, shipBatch(1, 8))
		var got []string
		for _, m := range msgs {
			if bt := m.GetBatch(); bt != nil {
				sum, _ := wire.HashItems(bt.Items)
				if sum != bt.Header.PayloadSha256 || int(bt.Header.Count) != len(bt.Items) || bt.Items[0].Seq != bt.Header.FirstSeq {
					t.Fatalf("bad batch header %+v", bt.Header)
				}
				got = append(got, fmt.Sprintf("B%d-%d", bt.Items[0].Seq, bt.Items[len(bt.Items)-1].Seq))
			} else if g := m.GetGapNotice(); g != nil {
				if g.Reason != pb.GapReason_DROPPED_BEFORE || len(g.Sources) != 1 || g.Sources[0] != pb.Source_AUDIT {
					t.Fatalf("gap %+v", g)
				}
				// Item i has event time t0+i s, so the gap spans its first and last item.
				if !g.From.AsTime().Equal(t0.Add(time.Duration(g.FirstSeq)*time.Second)) ||
					!g.To.AsTime().Equal(t0.Add(time.Duration(g.LastSeq)*time.Second)) {
					t.Fatalf("gap times %v..%v", g.From.AsTime(), g.To.AsTime())
				}
				got = append(got, fmt.Sprintf("G%d-%d", g.FirstSeq, g.LastSeq))
			}
		}
		if s := strings.Join(got, " "); s != "B1-2 G3-4 B5-6 G7-7 B8-8" {
			t.Fatalf("pass %d: %s", pass, s)
		}
	}
	e := entries(t, b)
	if len(e) != 3 || e[0].Seq != 3 || e[2].Seq != 7 || e[0].Action != ActDroppedReported {
		t.Fatalf("log (once per seq) %+v", e)
	}
}

func TestTransitWithoutDropsPassesBatchThrough(t *testing.T) {
	p := plan(t, "  - {id: l, kind: loss, stage: transit, rate: 0}\n")
	lg, _ := memLog(t, p)
	b := shipBatch(1, 5)
	msgs := NewTransit(p, lg).Batch(pb.Lane_NORMAL, b)
	if len(msgs) != 1 || msgs[0].GetBatch() != b {
		t.Fatalf("batch not passed through: %v", msgs)
	}
}
