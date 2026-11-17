package faults

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
)

// view gives the fields selectors and faults read from one record.
type view struct {
	topic string
	env   *pb.Envelope
}

func (v view) source() pb.Source {
	if ne := v.env.GetNormalizedEvent(); ne != nil && ne.Source != pb.Source_SOURCE_UNSPECIFIED {
		return ne.Source
	}
	return v.env.GetSource()
}

func (v view) eventFamily() string {
	if ne := v.env.GetNormalizedEvent(); ne != nil && ne.GetEbpf() != nil {
		return ne.GetEbpf().EventFamily
	}
	return v.env.GetRawEbpf().GetEventFamily()
}

// eventTime is NormalizedEvent.time.event_time, if present.
func (v view) eventTime() (time.Time, bool) {
	ne := v.env.GetNormalizedEvent()
	if ne == nil || ne.GetTime() == nil || ne.GetTime().GetEventTime() == nil {
		return time.Time{}, false
	}
	return ne.GetTime().GetEventTime().AsTime(), true
}

// id is the record's logical ID, or a hash of its canonical bytes.
func (v view) id() string {
	if v.env.GetLogicalId() != "" {
		return v.env.GetLogicalId()
	}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(v.env)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// matches applies the selector; time windows need an event time.
func (s Selector) matches(v view) bool {
	if len(s.Sources) > 0 && !contains(s.Sources, v.source().String()) {
		return false
	}
	if len(s.Topics) > 0 && !contains(s.Topics, v.topic) {
		return false
	}
	if len(s.EventFamilies) > 0 && !contains(s.EventFamilies, v.eventFamily()) {
		return false
	}
	if len(s.LogicalIDs) > 0 && !contains(s.LogicalIDs, v.env.GetLogicalId()) {
		return false
	}
	if s.From != nil || s.To != nil {
		t, ok := v.eventTime()
		if !ok || (s.From != nil && t.Before(*s.From)) || (s.To != nil && !t.Before(*s.To)) {
			return false
		}
	}
	return true
}

// atOrAfter reports whether the record's event time is >= t.
func (v view) atOrAfter(t *time.Time) bool {
	et, ok := v.eventTime()
	return ok && !et.Before(*t)
}

// lossKeys are the witness keys a lost copy of the record could have fed or contradicted, in the
// strings of mtcore.orchestrator.keys.loss_keys (2026-11-17, scoped loss): "L:node:boot:lineage"
// for an eBPF event with a process lineage, "F:clientIP:clientPort:serverIP:serverPort:proto" for
// a CONNECT or ACCEPT with both endpoints. ok is false for a record with neither (or any non-eBPF
// record): a gap holding such a record must stay unscoped.
func (v view) lossKeys() (keys []string, ok bool) {
	ne := v.env.GetNormalizedEvent()
	e := ne.GetEbpf()
	if e == nil {
		return nil, false
	}
	if lin := ne.GetEbpfDerived().GetLineageId(); lin != "" && e.GetNodeId() != "" && e.GetBootId() != "" {
		keys = append(keys, fmt.Sprintf("L:%s:%s:%s", e.GetNodeId(), e.GetBootId(), lin))
	}
	if sk := e.GetSocket(); sk != nil && sk.GetLocal().GetIp() != "" && sk.GetRemote().GetIp() != "" {
		var client, server *pb.Endpoint
		switch sk.GetOp() {
		case pb.SocketOp_CONNECT:
			client, server = sk.GetLocal(), sk.GetRemote()
		case pb.SocketOp_ACCEPT:
			client, server = sk.GetRemote(), sk.GetLocal()
		}
		if client != nil {
			prot := server.GetProtocol()
			if prot == 0 {
				prot = client.GetProtocol()
			}
			keys = append(keys, fmt.Sprintf("F:%s:%d:%s:%d:%d", client.GetIp(), client.GetPort(),
				server.GetIp(), server.GetPort(), prot))
		}
	}
	for _, k := range keys {
		if strings.ContainsAny(k, "/|") {
			return nil, false
		}
	}
	return keys, len(keys) > 0
}

// lossScope is the gap scope naming the loss keys of dropped items ("keys=k1|k2", sorted), or ""
// when any item has no key, so the gap stays node-wide.
func lossScope(items []*pb.ShipItem) string {
	set := map[string]bool{}
	for _, it := range items {
		ks, ok := view{it.Topic, it.Envelope}.lossKeys()
		if !ok {
			return ""
		}
		for _, k := range ks {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return "keys=" + strings.Join(out, "|")
}
