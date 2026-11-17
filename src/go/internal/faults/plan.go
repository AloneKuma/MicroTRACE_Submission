// Package faults applies Experiment 3 fault plans (spec/faults/fault-contract.md):
// at the source stage, as a filter in front of the shipper, and at the
// transit stage, inside the shipper after sequencing.
package faults

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
)

// Version is the plan format this package implements.
const Version = "faultplan.v0"

// Stages.
const (
	StageSource  = "source"
	StageTransit = "transit"
)

// Duration is a YAML duration such as "250ms" or "-3s".
type Duration struct{ time.Duration }

// UnmarshalYAML parses a Go duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// Selector picks records; every field given must match.
type Selector struct {
	Sources       []string   `yaml:"sources"`
	Topics        []string   `yaml:"topics"`
	EventFamilies []string   `yaml:"event_families"`
	LogicalIDs    []string   `yaml:"logical_ids"`
	From          *time.Time `yaml:"from"`
	To            *time.Time `yaml:"to"`
}

// Fault is one entry of a plan.
type Fault struct {
	ID                 string     `yaml:"id"`
	Kind               string     `yaml:"kind"`
	Stage              string     `yaml:"stage"`
	Select             Selector   `yaml:"select"`
	Rate               *float64   `yaml:"rate"`
	Offset             Duration   `yaml:"offset"`
	DeclareUncertainty bool       `yaml:"declare_uncertainty"`
	Delay              Duration   `yaml:"delay"`
	After              *time.Time `yaml:"after"`
	Count              int        `yaml:"count"`
}

// Plan is a parsed, validated fault plan.
type Plan struct {
	Version string  `yaml:"version"`
	Seed    uint64  `yaml:"seed"`
	Faults  []Fault `yaml:"faults"`
	// SHA256 of the plan file, for the fault log header.
	SHA256 string `yaml:"-"`
}

var kindStages = map[string][]string{
	"loss":     {StageSource, StageTransit},
	"outage":   {StageSource, StageTransit},
	"suppress": {StageSource, StageTransit},
	"skew":     {StageSource},
	"delay":    {StageSource},
	"stop":     {StageSource},
	"blind":    {StageSource},
	"forge":    {StageSource},
}

// Load reads and validates a plan file.
func Load(path string) (*Plan, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse validates a plan.
func Parse(raw []byte) (*Plan, error) {
	var p Plan
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	p.SHA256 = hex.EncodeToString(sum[:])
	if p.Version != Version {
		return nil, fmt.Errorf("plan version %q, want %s", p.Version, Version)
	}
	seen := map[string]bool{}
	for i := range p.Faults {
		f := &p.Faults[i]
		if err := f.validate(); err != nil {
			return nil, fmt.Errorf("fault %d (%s): %w", i, f.ID, err)
		}
		if seen[f.ID] {
			return nil, fmt.Errorf("duplicate fault id %q", f.ID)
		}
		seen[f.ID] = true
	}
	return &p, nil
}

func (f *Fault) validate() error {
	if f.ID == "" {
		return fmt.Errorf("missing id")
	}
	stages, ok := kindStages[f.Kind]
	if !ok {
		return fmt.Errorf("unknown kind %q", f.Kind)
	}
	okStage := false
	for _, s := range stages {
		okStage = okStage || s == f.Stage
	}
	if !okStage {
		return fmt.Errorf("kind %s cannot use stage %q (allowed: %v)", f.Kind, f.Stage, stages)
	}
	for _, s := range f.Select.Sources {
		if _, ok := pb.Source_value[s]; !ok {
			return fmt.Errorf("unknown source %q", s)
		}
	}
	if f.Rate != nil && (*f.Rate < 0 || *f.Rate > 1) {
		return fmt.Errorf("rate %v outside 0..1", *f.Rate)
	}
	sel := f.Select
	hasSel := len(sel.Sources)+len(sel.Topics)+len(sel.EventFamilies)+len(sel.LogicalIDs) > 0 || sel.From != nil || sel.To != nil
	switch f.Kind {
	case "loss":
		if f.Rate == nil {
			return fmt.Errorf("loss needs rate")
		}
	case "outage":
		if sel.From == nil || sel.To == nil || !sel.To.After(*sel.From) {
			return fmt.Errorf("outage needs select.from < select.to")
		}
	case "suppress":
		if len(sel.LogicalIDs) == 0 {
			return fmt.Errorf("suppress needs select.logical_ids")
		}
	case "skew":
		if f.Offset.Duration == 0 {
			return fmt.Errorf("skew needs a non-zero offset")
		}
	case "delay":
		if f.Delay.Duration <= 0 {
			return fmt.Errorf("delay needs delay > 0")
		}
	case "stop":
		if f.After == nil {
			return fmt.Errorf("stop needs after")
		}
	case "blind":
		if f.After == nil || !hasSel {
			return fmt.Errorf("blind needs after and a selector")
		}
	case "forge":
		if f.After == nil || f.Count <= 0 {
			return fmt.Errorf("forge needs after and count > 0")
		}
	}
	return nil
}

// ForStage returns the plan's faults for one stage, in plan order.
func (p *Plan) ForStage(stage string) []Fault {
	var out []Fault
	for _, f := range p.Faults {
		if f.Stage == stage {
			out = append(out, f)
		}
	}
	return out
}

// Picked reports whether a record is selected at the fault's rate (rate nil = 1).
func (p *Plan) Picked(f Fault, logicalID string) bool {
	rate := 1.0
	if f.Rate != nil {
		rate = *f.Rate
	}
	if rate >= 1 {
		return true
	}
	if rate <= 0 {
		return false
	}
	return draw(p.Seed, f.ID, logicalID) < rate
}

// draw maps (seed, fault, record) to [0, 1).
func draw(seed uint64, faultID, logicalID string) float64 {
	h := sha256.New()
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seed)
	h.Write(s[:])
	h.Write([]byte{0})
	h.Write([]byte(faultID))
	h.Write([]byte{0})
	h.Write([]byte(logicalID))
	v := binary.BigEndian.Uint64(h.Sum(nil)[:8])
	return float64(v>>11) / float64(uint64(1)<<53)
}
