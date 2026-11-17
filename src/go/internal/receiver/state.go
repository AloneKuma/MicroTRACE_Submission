package receiver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
)

// stateStore keeps each (node, boot) stream's durable lane state in
// <dir>/<node>/<boot>.json, written atomically: the next expected sequence,
// the latest accepted event time, and gaps waiting for their end time
// (ship-contract.md, "Gap times").
type stateStore struct{ dir string }

// pendingGap is a reported loss whose end time is not known yet: it is
// written to Kafka when the next item on the lane is accepted.
type pendingGap struct {
	First   uint64       `json:"first"`
	Last    uint64       `json:"last"`
	Reason  pb.GapReason `json:"reason"`
	Detail  string       `json:"detail"`
	Sources []pb.Source  `json:"sources"`
	// Scope of the lost items from the sender's notices ("keys=..."), "" when any notice had none.
	Scope string `json:"scope,omitempty"`
	// Event time of the last accepted item before the gap; 0 if none.
	FromNs int64 `json:"from_ns"`
}

// streamState is one (node, boot) stream's durable state.
type streamState struct {
	next    map[pb.Lane]uint64
	lastET  map[pb.Lane]int64
	pending map[pb.Lane]*pendingGap
	// An open-ended SOURCE_IDLE gap was written and awaits its end.
	idleOpen bool
	idleFrom int64
}

type persisted struct {
	Next        map[string]uint64      `json:"next"`
	LastEventNs map[string]int64       `json:"last_event_ns,omitempty"`
	Pending     map[string]*pendingGap `json:"pending,omitempty"`
	IdleOpen    bool                   `json:"idle_open,omitempty"`
	IdleFromNs  int64                  `json:"idle_from_ns,omitempty"`
}

func newStreamState() streamState {
	return streamState{next: map[pb.Lane]uint64{pb.Lane_PRIORITY: 1, pb.Lane_NORMAL: 1},
		lastET: map[pb.Lane]int64{}, pending: map[pb.Lane]*pendingGap{}}
}

func (s stateStore) path(node, boot string) string {
	return filepath.Join(s.dir, node, boot+".json")
}

func (s stateStore) load(node, boot string) (streamState, error) {
	st := newStreamState()
	raw, err := os.ReadFile(s.path(node, boot))
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	var p persisted
	if err := json.Unmarshal(raw, &p); err != nil || p.Next == nil {
		// Earlier format: a flat map from lane name to next sequence.
		var old map[string]uint64
		if err := json.Unmarshal(raw, &old); err != nil {
			return st, err
		}
		p = persisted{Next: old}
	}
	for name, n := range p.Next {
		if l, ok := pb.Lane_value[name]; ok && n > 0 {
			st.next[pb.Lane(l)] = n
		}
	}
	for name, t := range p.LastEventNs {
		if l, ok := pb.Lane_value[name]; ok {
			st.lastET[pb.Lane(l)] = t
		}
	}
	for name, g := range p.Pending {
		if l, ok := pb.Lane_value[name]; ok && g != nil {
			st.pending[pb.Lane(l)] = g
		}
	}
	st.idleOpen, st.idleFrom = p.IdleOpen, p.IdleFromNs
	return st, nil
}

func (s stateStore) save(node, boot string, st streamState) error {
	p := persisted{Next: map[string]uint64{}, LastEventNs: map[string]int64{}, Pending: map[string]*pendingGap{},
		IdleOpen: st.idleOpen, IdleFromNs: st.idleFrom}
	for l, n := range st.next {
		p.Next[l.String()] = n
	}
	for l, t := range st.lastET {
		p.LastEventNs[l.String()] = t
	}
	for l, g := range st.pending {
		p.Pending[l.String()] = g
	}
	raw, _ := json.Marshal(p)
	path := s.path(node, boot)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Windows refuses to flush a directory handle; the rename is journaled
	// there (Exp. 3 local dry run only; Linux behaviour unchanged).
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
