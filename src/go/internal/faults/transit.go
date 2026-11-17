package faults

import (
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/wire"
)

// Transit applies transit-stage faults inside the shipper, after sequencing.
// Dropped items become GapNotices naming their exact sequences, so the
// receiver records the loss. It implements shipper.Transit.
type Transit struct {
	plan   *Plan
	faults []Fault
	log    *Log
	mu     sync.Mutex
	logged map[pb.Lane]map[uint64]bool
}

// NewTransit returns the transit stage of p.
func NewTransit(p *Plan, log *Log) *Transit {
	return &Transit{plan: p, faults: p.ForStage(StageTransit), log: log,
		logged: map[pb.Lane]map[uint64]bool{}}
}

// dropBy returns the first transit fault that drops the item, or "".
func (t *Transit) dropBy(it *pb.ShipItem) (string, string) {
	v := view{it.Topic, it.Envelope}
	for _, f := range t.faults {
		if !f.Select.matches(v) {
			continue
		}
		if f.Kind == "loss" && !t.plan.Picked(f, v.id()) {
			continue
		}
		return f.ID, f.Kind
	}
	return "", ""
}

type run struct {
	dropped bool
	items   []*pb.ShipItem
	ids     map[string]bool
}

// Batch splits b into batches of kept items and gap notices for dropped ones,
// in sequence order. The same batch always gives the same result.
func (t *Transit) Batch(lane pb.Lane, b *pb.Batch) []*pb.NodeMessage {
	if len(t.faults) == 0 {
		return []*pb.NodeMessage{{Msg: &pb.NodeMessage_Batch{Batch: b}}}
	}
	var runs []*run
	for _, it := range b.Items {
		id, kind := t.dropBy(it)
		dropped := id != ""
		if n := len(runs); n == 0 || runs[n-1].dropped != dropped {
			runs = append(runs, &run{dropped: dropped, ids: map[string]bool{}})
		}
		r := runs[len(runs)-1]
		r.items = append(r.items, it)
		if dropped {
			r.ids[id] = true
			t.record(lane, it, id, kind)
		}
	}
	if len(runs) == 1 && !runs[0].dropped {
		return []*pb.NodeMessage{{Msg: &pb.NodeMessage_Batch{Batch: b}}}
	}
	var out []*pb.NodeMessage
	for _, r := range runs {
		first, last := r.items[0].Seq, r.items[len(r.items)-1].Seq
		if !r.dropped {
			h := proto.Clone(b.Header).(*pb.BatchHeader)
			h.FirstSeq, h.Count = first, uint32(len(r.items))
			sum, err := wire.HashItems(r.items)
			if err != nil {
				continue
			}
			h.PayloadSha256 = sum
			out = append(out, &pb.NodeMessage{Msg: &pb.NodeMessage_Batch{Batch: &pb.Batch{Header: h, Items: r.items}}})
			continue
		}
		var ids []string
		for id := range r.ids {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		srcSet := map[pb.Source]bool{}
		var from, to time.Time
		for _, it := range r.items {
			srcSet[view{it.Topic, it.Envelope}.source()] = true
			if et, ok := wire.EventTime(it.Envelope); ok {
				if from.IsZero() || et.Before(from) {
					from = et
				}
				if et.After(to) {
					to = et
				}
			}
		}
		var srcs []pb.Source
		for s := range srcSet {
			srcs = append(srcs, s)
		}
		sort.Slice(srcs, func(i, j int) bool { return srcs[i] < srcs[j] })
		g := &pb.GapNotice{Lane: lane, FirstSeq: first, LastSeq: last, Reason: pb.GapReason_DROPPED_BEFORE,
			Detail: "injected fault " + strings.Join(ids, ","), Sources: srcs, Scope: lossScope(r.items)}
		if !from.IsZero() {
			g.From, g.To = timestamppb.New(from), timestamppb.New(to)
		}
		out = append(out, &pb.NodeMessage{Msg: &pb.NodeMessage_GapNotice{GapNotice: g}})
	}
	return out
}

// record logs a dropped item once, even if it is retransmitted.
func (t *Transit) record(lane pb.Lane, it *pb.ShipItem, id, kind string) {
	t.mu.Lock()
	if t.logged[lane] == nil {
		t.logged[lane] = map[uint64]bool{}
	}
	if t.logged[lane][it.Seq] {
		t.mu.Unlock()
		return
	}
	t.logged[lane][it.Seq] = true
	t.mu.Unlock()
	_ = t.log.Add(Entry{FaultID: id, Kind: kind, Stage: StageTransit, LogicalID: view{it.Topic, it.Envelope}.id(),
		Topic: it.Topic, Lane: lane.String(), Seq: it.Seq, Action: ActDroppedReported})
}
