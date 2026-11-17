package receiver

import (
	"context"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

// Producer writes records and returns only once Kafka has acknowledged all of
// them (or the context ends).
type Producer interface {
	Produce(ctx context.Context, recs []*kgo.Record) error
}

// KafkaProducer is an idempotent franz-go producer with acks=all.
type KafkaProducer struct{ Client *kgo.Client }

// NewKafkaProducer returns a producer. With manual set, each record's
// Partition field is used (heartbeats); otherwise keys are placed by Kafka's
// murmur2, as the Java client does (KAFKA-KEY-PARTITION).
func NewKafkaProducer(brokers []string, manual bool) (*KafkaProducer, error) {
	part := kgo.StickyKeyPartitioner(nil)
	if manual {
		part = kgo.ManualPartitioner()
	}
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.RecordPartitioner(part),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerLinger(0),
	)
	if err != nil {
		return nil, err
	}
	return &KafkaProducer{Client: cl}, nil
}

// Produce writes recs and waits for every acknowledgement.
func (p *KafkaProducer) Produce(ctx context.Context, recs []*kgo.Record) error {
	if len(recs) == 0 {
		return nil
	}
	return p.Client.ProduceSync(ctx, recs...).FirstErr()
}

// Close flushes and closes the client.
func (p *KafkaProducer) Close() { p.Client.Close() }

// PartitionCounts returns the partition count of each topic.
func PartitionCounts(ctx context.Context, cl *kgo.Client, topics []string) (map[string]int32, error) {
	td, err := kadm.NewClient(cl).ListTopics(ctx, topics...)
	if err != nil {
		return nil, err
	}
	out := map[string]int32{}
	for _, t := range topics {
		d, ok := td[t]
		if !ok || d.Err != nil {
			if ok {
				return nil, d.Err
			}
			return nil, &missingTopic{t}
		}
		out[t] = int32(len(d.Partitions))
	}
	return out, nil
}

type missingTopic struct{ name string }

func (m *missingTopic) Error() string { return "topic " + m.name + " does not exist" }
