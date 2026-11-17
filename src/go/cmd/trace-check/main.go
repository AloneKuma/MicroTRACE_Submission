// Command trace-check reads and writes Kafka records from Go, so tests can
// check that Go and Python agree on record bytes, Envelope decoding and key
// partitioning.
//
// Each mode reads one JSON object per line on stdin and writes one per line
// on stdout.
//
//	read:  {"topic","partition","offset"} -> {"topic","partition","offset","envelope_json"}
//	write: {"topic","key_hex","value_b64"} -> {"topic","partition","offset"}
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
)

type position struct {
	Topic     string `json:"topic"`
	Partition int32  `json:"partition"`
	Offset    int64  `json:"offset"`
}

type readResult struct {
	position
	EnvelopeJSON string `json:"envelope_json"`
}

type writeRequest struct {
	Topic    string `json:"topic"`
	KeyHex   string `json:"key_hex"`
	ValueB64 string `json:"value_b64"`
}

func main() {
	brokers := flag.String("brokers", "127.0.0.1:9092", "bootstrap broker")
	mode := flag.String("mode", "read", "read or write")
	flag.Parse()

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 16<<20)
	out := json.NewEncoder(os.Stdout)

	var err error
	switch *mode {
	case "read":
		err = readAll(*brokers, in, out)
	case "write":
		err = writeAll(*brokers, in, out)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "trace-check:", err)
		os.Exit(1)
	}
}

func readAll(brokers string, in *bufio.Scanner, out *json.Encoder) error {
	for in.Scan() {
		var p position
		if err := json.Unmarshal(in.Bytes(), &p); err != nil {
			return err
		}
		rec, err := fetchOne(brokers, p)
		if err != nil {
			return err
		}
		env := &pb.Envelope{}
		if err := proto.Unmarshal(rec.Value, env); err != nil {
			return fmt.Errorf("%s/%d@%d: %w", p.Topic, p.Partition, p.Offset, err)
		}
		js, err := protojson.Marshal(env)
		if err != nil {
			return err
		}
		if err := out.Encode(readResult{position: p, EnvelopeJSON: string(js)}); err != nil {
			return err
		}
	}
	return in.Err()
}

func fetchOne(brokers string, p position) (*kgo.Record, error) {
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers),
		kgo.ConsumePartitions(map[string]map[int32]kgo.Offset{
			p.Topic: {p.Partition: kgo.NewOffset().At(p.Offset)},
		}),
	)
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		fs := cl.PollFetches(ctx)
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s/%d@%d: no record before timeout", p.Topic, p.Partition, p.Offset)
		}
		if errs := fs.Errors(); len(errs) > 0 {
			return nil, errs[0].Err
		}
		var found *kgo.Record
		fs.EachRecord(func(r *kgo.Record) {
			if found == nil && r.Offset == p.Offset {
				found = r
			}
		})
		if found != nil {
			return found, nil
		}
	}
}

func writeAll(brokers string, in *bufio.Scanner, out *json.Encoder) error {
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers),
		// nil hasher = Kafka's murmur2, the Java client's key partitioning.
		kgo.RecordPartitioner(kgo.StickyKeyPartitioner(nil)),
	)
	if err != nil {
		return err
	}
	defer cl.Close()
	ctx := context.Background()
	for in.Scan() {
		var w writeRequest
		if err := json.Unmarshal(in.Bytes(), &w); err != nil {
			return err
		}
		key, err := hex.DecodeString(w.KeyHex)
		if err != nil {
			return err
		}
		val, err := base64.StdEncoding.DecodeString(w.ValueB64)
		if err != nil {
			return err
		}
		res := cl.ProduceSync(ctx, &kgo.Record{Topic: w.Topic, Key: key, Value: val})
		r, err := res.First()
		if err != nil {
			return err
		}
		if err := out.Encode(position{Topic: r.Topic, Partition: r.Partition, Offset: r.Offset}); err != nil {
			return err
		}
	}
	return in.Err()
}
