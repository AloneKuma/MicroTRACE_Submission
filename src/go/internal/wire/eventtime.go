package wire

import (
	"time"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
)

// EventTime is the record's event time where the record carries one:
// NormalizedEvent.time.event_time, or the source time of a raw record that has
// a wall-clock time. Raw eBPF records carry only kernel monotonic time and
// gateway records no time, so they report false.
func EventTime(env *pb.Envelope) (time.Time, bool) {
	if ne := env.GetNormalizedEvent(); ne != nil {
		if t := ne.GetTime().GetEventTime(); t != nil {
			return t.AsTime(), true
		}
		return time.Time{}, false
	}
	var ts interface{ AsTime() time.Time }
	switch p := env.GetPayload().(type) {
	case *pb.Envelope_RawAudit:
		if t := p.RawAudit.GetRequestReceivedTimestamp(); t != nil {
			ts = t
		} else if t := p.RawAudit.GetStageTimestamp(); t != nil {
			ts = t
		}
	case *pb.Envelope_RawKyverno:
		if t := p.RawKyverno.GetAdmissionTime(); t != nil {
			ts = t
		}
	case *pb.Envelope_RawDbAudit:
		if t := p.RawDbAudit.GetServerTime(); t != nil {
			ts = t
		}
	case *pb.Envelope_RawPathFlow:
		if t := p.RawPathFlow.GetFlowStart(); t != nil {
			ts = t
		}
	case *pb.Envelope_ContextObservation:
		if t := p.ContextObservation.GetObservedTime(); t != nil {
			ts = t
		}
	}
	if ts == nil {
		return time.Time{}, false
	}
	return ts.AsTime(), true
}

// RecordSource is NormalizedEvent.source when set, else Envelope.source.
func RecordSource(env *pb.Envelope) pb.Source {
	if ne := env.GetNormalizedEvent(); ne != nil && ne.Source != pb.Source_SOURCE_UNSPECIFIED {
		return ne.Source
	}
	return env.GetSource()
}

// TimeNs is t in Unix nanoseconds, or 0 when ok is false (0 means unknown).
func TimeNs(t time.Time, ok bool) int64 {
	if !ok {
		return 0
	}
	return t.UnixNano()
}
