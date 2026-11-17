package receiver

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
)

// CompletenessTopic receives transport-loss and idle records.
const CompletenessTopic = "source.completeness.v0"

// TopicSpec is one topic from spec/kafka/topics.yaml.
type TopicSpec struct {
	Name       string
	KeyType    pb.KeyType
	Components []pb.KeyComponent
	// Heartbeats: the topic's kinds include HEARTBEAT.
	Heartbeats bool
	// Source used on heartbeat envelopes for this topic.
	Source pb.Source
}

type topicsFile struct {
	Topics []struct {
		Name          string   `yaml:"name"`
		KeyType       string   `yaml:"key_type"`
		KeyComponents []string `yaml:"key_components"`
		Kinds         []string `yaml:"kinds"`
	} `yaml:"topics"`
}

var topicSources = map[string]pb.Source{
	"raw.ebpf.v0":        pb.Source_EBPF,
	"raw.audit.v0":       pb.Source_AUDIT,
	"raw.gateway.v0":     pb.Source_GATEWAY,
	"raw.kyverno.v0":     pb.Source_KYVERNO,
	"context.cluster.v0": pb.Source_CLUSTER_CONTEXT,
	"raw.dbaudit.v0":     pb.Source_DB_AUDIT,
	"raw.pathflow.v0":    pb.Source_PATH_FLOW,
}

// LoadTopics reads topics.yaml and returns every topic's spec.
func LoadTopics(path string) (map[string]*TopicSpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f topicsFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	out := map[string]*TopicSpec{}
	for _, t := range f.Topics {
		kt, ok := pb.KeyType_value[t.KeyType]
		if !ok {
			return nil, fmt.Errorf("%s: unknown key type %q", t.Name, t.KeyType)
		}
		spec := &TopicSpec{Name: t.Name, KeyType: pb.KeyType(kt), Source: topicSources[t.Name]}
		for _, c := range t.KeyComponents {
			code, ok := pb.KeyComponent_value[c]
			if !ok {
				return nil, fmt.Errorf("%s: unknown key component %q", t.Name, c)
			}
			spec.Components = append(spec.Components, pb.KeyComponent(code))
		}
		for _, k := range t.Kinds {
			if k == "HEARTBEAT" {
				spec.Heartbeats = true
			}
		}
		out[t.Name] = spec
	}
	if out[CompletenessTopic] == nil {
		return nil, fmt.Errorf("topics file has no %s", CompletenessTopic)
	}
	return out, nil
}

// Allow returns the specs of the named topics, which must all exist.
func Allow(all map[string]*TopicSpec, names string) (map[string]*TopicSpec, error) {
	out := map[string]*TopicSpec{}
	for _, n := range strings.Split(names, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		s, ok := all[n]
		if !ok {
			return nil, fmt.Errorf("allowlisted topic %q is not in topics.yaml", n)
		}
		out[n] = s
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty topic allowlist")
	}
	return out, nil
}
