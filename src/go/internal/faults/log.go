package faults

import (
	"encoding/json"
	"io"
	"os"
	"sync"
)

// Actions recorded in the fault log.
const (
	ActDroppedUnreported = "dropped_unreported"
	ActDroppedReported   = "dropped_reported"
	ActShifted           = "shifted"
	ActDelayed           = "delayed"
	ActForged            = "forged"
)

// Entry is one effect on one record.
type Entry struct {
	FaultID   string `json:"fault_id"`
	Kind      string `json:"kind"`
	Stage     string `json:"stage"`
	LogicalID string `json:"logical_id"`
	Topic     string `json:"topic"`
	Lane      string `json:"lane"`
	Seq       uint64 `json:"seq,omitempty"`
	Action    string `json:"action"`
	Detail    string `json:"detail,omitempty"`
}

// Log writes the fault log (restricted, truth side only).
type Log struct {
	mu  sync.Mutex
	w   io.Writer
	f   *os.File
	enc *json.Encoder
}

// OpenLog creates path and writes the header. An empty path discards entries.
func OpenLog(path string, p *Plan, stage, node string) (*Log, error) {
	l := &Log{w: io.Discard}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		l.f, l.w = f, f
	}
	l.enc = json.NewEncoder(l.w)
	hdr := map[string]any{"header": map[string]any{"version": p.Version, "plan_sha256": p.SHA256,
		"seed": p.Seed, "stage": stage, "node": node}}
	if err := l.enc.Encode(hdr); err != nil {
		return nil, err
	}
	return l, nil
}

// Add appends one entry.
func (l *Log) Add(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(e)
}

// Close syncs and closes the log file.
func (l *Log) Close() error {
	if l.f == nil {
		return nil
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	return l.f.Close()
}
