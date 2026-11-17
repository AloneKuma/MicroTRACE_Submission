package faults

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
)

// Line is one shipper input line (cmd/shipper documents the format).
type Line struct {
	Lane          string          `json:"lane,omitempty"`
	Topic         string          `json:"topic,omitempty"`
	KeyType       string          `json:"key_type,omitempty"`
	KeyComponents []string        `json:"key_components,omitempty"`
	Envelope      json.RawMessage `json:"envelope,omitempty"`
	Watermark     string          `json:"watermark,omitempty"`

	raw      []byte
	env      *pb.Envelope
	modified bool
	// Emit is when the line leaves the source stage, in event time.
	Emit time.Time `json:"-"`
}

// IsWatermark reports whether the line declares a watermark.
func (l *Line) IsWatermark() bool { return l.Watermark != "" }

func (l *Line) lane() string {
	if l.Lane == "" {
		return "NORMAL"
	}
	return l.Lane
}

// ReadLines parses shipper input lines.
func ReadLines(r io.Reader) ([]*Line, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	var out []*Line
	for n := 1; ; n++ {
		raw, err := br.ReadBytes('\n')
		if len(trim(raw)) > 0 {
			l := &Line{raw: append([]byte(nil), trim(raw)...)}
			if jerr := json.Unmarshal(l.raw, l); jerr != nil {
				return nil, fmt.Errorf("line %d: %w", n, jerr)
			}
			if !l.IsWatermark() {
				l.env = &pb.Envelope{}
				if perr := protojson.Unmarshal(l.Envelope, l.env); perr != nil {
					return nil, fmt.Errorf("line %d: envelope: %w", n, perr)
				}
			}
			out = append(out, l)
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// Bytes is the line as written: unchanged input bytes, or re-encoded when a
// fault altered or fabricated it.
func (l *Line) Bytes() ([]byte, error) {
	if !l.modified {
		return l.raw, nil
	}
	env, err := protojson.Marshal(l.env)
	if err != nil {
		return nil, err
	}
	l.Envelope = env
	return json.Marshal(l)
}

// ApplySource applies the plan's source-stage faults and returns the lines in
// emit order. Every effect is logged.
func ApplySource(p *Plan, lines []*Line, log *Log) ([]*Line, error) {
	faults := p.ForStage(StageSource)
	var out []*Line
	stopped := false
	forged := map[string]bool{}
	var lastEmit time.Time
	for _, ln := range lines {
		if stopped {
			if !ln.IsWatermark() {
				v := view{ln.Topic, ln.env}
				if err := log.Add(Entry{FaultID: stopID(faults), Kind: "stop", Stage: StageSource, LogicalID: v.id(),
					Topic: ln.Topic, Lane: ln.lane(), Action: ActDroppedUnreported}); err != nil {
					return nil, err
				}
			}
			continue
		}
		if ln.IsWatermark() {
			ln.Emit = lastEmit
			out = append(out, ln)
			continue
		}
		v := view{ln.Topic, ln.env}
		var delay time.Duration
		var extra []*Line
		drop := ""
		for _, f := range faults {
			if f.Kind == "stop" && v.atOrAfter(f.After) {
				stopped, drop = true, f.ID
			}
		}
		for _, f := range faults {
			if drop != "" {
				break
			}
			switch f.Kind {
			case "loss":
				if f.Select.matches(v) && p.Picked(f, v.id()) {
					drop = f.ID
				}
			case "outage", "suppress":
				if f.Select.matches(v) {
					drop = f.ID
				}
			case "blind":
				if f.Select.matches(v) && v.atOrAfter(f.After) {
					drop = f.ID
				}
			case "skew":
				if f.Select.matches(v) && skew(ln, f) {
					if err := log.Add(Entry{FaultID: f.ID, Kind: f.Kind, Stage: StageSource, LogicalID: v.id(), Topic: ln.Topic,
						Lane: ln.lane(), Action: ActShifted, Detail: "offset " + f.Offset.String()}); err != nil {
						return nil, err
					}
				}
			case "delay":
				if f.Select.matches(v) && p.Picked(f, v.id()) {
					delay += f.Delay.Duration
					if err := log.Add(Entry{FaultID: f.ID, Kind: f.Kind, Stage: StageSource, LogicalID: v.id(), Topic: ln.Topic,
						Lane: ln.lane(), Action: ActDelayed, Detail: "delay " + f.Delay.String()}); err != nil {
						return nil, err
					}
				}
			case "forge":
				if !forged[f.ID] && f.Select.matches(v) && v.atOrAfter(f.After) {
					forged[f.ID] = true
					for i := 0; i < f.Count; i++ {
						c := forge(ln, f, i)
						extra = append(extra, c)
						if err := log.Add(Entry{FaultID: f.ID, Kind: f.Kind, Stage: StageSource, LogicalID: c.env.LogicalId,
							Topic: c.Topic, Lane: c.lane(), Action: ActForged, Detail: "template " + v.id()}); err != nil {
							return nil, err
						}
					}
				}
			}
		}
		base := lastEmit
		if et, ok := v.eventTime(); ok {
			base = et
		}
		if drop != "" {
			kind := kindOf(faults, drop)
			if err := log.Add(Entry{FaultID: drop, Kind: kind, Stage: StageSource, LogicalID: v.id(), Topic: ln.Topic,
				Lane: ln.lane(), Action: ActDroppedUnreported}); err != nil {
				return nil, err
			}
		} else {
			ln.Emit = base.Add(delay)
			out = append(out, ln)
		}
		for _, c := range extra {
			if et, ok := (view{c.Topic, c.env}).eventTime(); ok {
				c.Emit = et
			} else {
				c.Emit = base
			}
			out = append(out, c)
		}
		lastEmit = base
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Emit.Before(out[j].Emit) })
	return out, nil
}

func stopID(faults []Fault) string {
	for _, f := range faults {
		if f.Kind == "stop" {
			return f.ID
		}
	}
	return ""
}

func kindOf(faults []Fault, id string) string {
	for _, f := range faults {
		if f.ID == id {
			return f.Kind
		}
	}
	return ""
}

// skew shifts the record's source and event times; it reports whether the
// record had an event time to shift.
func skew(ln *Line, f Fault) bool {
	ne := ln.env.GetNormalizedEvent()
	if ne == nil || ne.GetTime() == nil || ne.GetTime().GetEventTime() == nil {
		return false
	}
	t := ne.Time
	t.EventTime = timestamppb.New(t.EventTime.AsTime().Add(f.Offset.Duration))
	if t.SourceTime != nil {
		t.SourceTime = timestamppb.New(t.SourceTime.AsTime().Add(f.Offset.Duration))
	}
	if f.DeclareUncertainty {
		off := f.Offset.Duration
		if off < 0 {
			off = -off
		}
		if uint64(off) > t.ClockUncertaintyNs {
			t.ClockUncertaintyNs = uint64(off)
		}
	}
	ln.modified = true
	return true
}

// forge makes the i-th fabricated copy of a template line: a new logical ID
// and event ID, and an event time i+1 milliseconds after the template's.
func forge(tmpl *Line, f Fault, i int) *Line {
	env := proto.Clone(tmpl.env).(*pb.Envelope)
	id := fmt.Sprintf("forged-%s-%d", f.ID, i+1)
	env.LogicalId = id
	if ne := env.GetNormalizedEvent(); ne != nil {
		ne.EventId = id
		if ne.GetTime().GetEventTime() != nil {
			ne.Time.EventTime = timestamppb.New(ne.Time.EventTime.AsTime().Add(time.Duration(i+1) * time.Millisecond))
		}
	}
	return &Line{Lane: tmpl.Lane, Topic: tmpl.Topic, KeyType: tmpl.KeyType,
		KeyComponents: append([]string(nil), tmpl.KeyComponents...), env: env, modified: true}
}
