// Command shipper sends records to the ingest receiver
// (spec/kafka/ship-contract.md).
//
// Input is one JSON object per line:
//
//	{"lane":"NORMAL","topic":"raw.ebpf.v0","key_type":"KEY_NODE","key_components":["node-1"],"envelope":{...}}
//	{"lane":"NORMAL","watermark":"2026-10-08T12:00:00Z"}
//
// "envelope" is the Envelope in Protobuf JSON form; "lane" defaults to NORMAL.
// HEARTBEAT envelopes are skipped: the receiver is the Kafka producer and
// writes its own heartbeats (ship-contract.md, "Watermarks and heartbeats").
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/faults"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/shipper"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/spool"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/tlsconf"
)

type line struct {
	Lane          string          `json:"lane"`
	Topic         string          `json:"topic"`
	KeyType       string          `json:"key_type"`
	KeyComponents []string        `json:"key_components"`
	Envelope      json.RawMessage `json:"envelope"`
	Watermark     string          `json:"watermark"`
}

func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "boot-unknown"
	}
	return strings.TrimSpace(string(b))
}

func main() {
	addr := flag.String("receiver", "127.0.0.1:50051", "receiver address")
	serverName := flag.String("server-name", "127.0.0.1", "name in the receiver certificate")
	cert := flag.String("cert", "", "node certificate (PEM); its common name is the node ID")
	key := flag.String("key", "", "node key (PEM)")
	ca := flag.String("ca", "", "CA that signs the receiver certificate (PEM)")
	node := flag.String("node-id", "", "node ID (must match the certificate)")
	boot := flag.String("boot-id", bootID(), "boot ID; a new value starts new sequences")
	instance := flag.String("instance", "shipper", "agent instance name")
	spoolDir := flag.String("spool", "spool", "spool directory")
	spoolMax := flag.Int64("spool-max-bytes", 256<<20, "spool size per lane")
	batchMax := flag.Int("batch-max", 500, "items per NORMAL batch")
	linger := flag.Duration("linger", 20*time.Millisecond, "time a NORMAL batch waits to fill")
	window := flag.Int("window", 4096, "unacknowledged items in flight per lane")
	retransmit := flag.Duration("retransmit", 30*time.Second, "resend after this long without an ack")
	input := flag.String("input", "-", "input file of JSON lines, or - for stdin")
	drain := flag.Bool("drain", false, "exit once input ends and every item is acknowledged or reported")
	stats := flag.String("stats", "", "write per-lane statistics as JSON here on exit")
	faultPlan := flag.String("faults", "", "fault plan (spec/faults); applies its transit-stage faults after sequencing")
	faultLog := flag.String("fault-log", "", "fault log path (restricted, truth side only)")
	status := flag.Bool("status", false, "print each lane's next sequence from the spool as JSON and exit (no connection)")
	flag.Parse()

	if *status {
		printStatus(*spoolDir, *boot, *spoolMax)
		return
	}

	tcfg, err := tlsconf.Client(*cert, *key, *ca, *serverName)
	if err != nil {
		log.Fatal(err)
	}
	var transit shipper.Transit
	if *faultPlan != "" {
		plan, err := faults.Load(*faultPlan)
		if err != nil {
			log.Fatal(err)
		}
		flog, err := faults.OpenLog(*faultLog, plan, faults.StageTransit, *node)
		if err != nil {
			log.Fatal(err)
		}
		defer flog.Close()
		transit = faults.NewTransit(plan, flog)
	}
	s, err := shipper.New(shipper.Config{NodeID: *node, BootID: *boot, Instance: *instance, Addr: *addr, TLS: tcfg,
		SpoolDir: *spoolDir, SpoolMaxBytes: *spoolMax, BatchMax: *batchMax, Linger: *linger,
		Window: *window, Retransmit: *retransmit, Transit: transit})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var in io.Reader = os.Stdin
	if *input != "-" {
		f, err := os.Open(*input)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		in = f
	}
	readErr := make(chan error, 1)
	go func() { readErr <- feed(s, in) }()

	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx, *drain) }()

	var exit error
	select {
	case err := <-readErr:
		if err != nil {
			exit = err
			stop()
			<-runErr
		} else {
			exit = <-runErr
		}
	case exit = <-runErr:
	}
	if err := s.Close(); err != nil && exit == nil {
		exit = err
	}
	if *stats != "" {
		raw, _ := json.MarshalIndent(s.Stats(), "", "  ")
		if err := os.WriteFile(*stats, raw, 0o644); err != nil && exit == nil {
			exit = err
		}
	}
	if exit != nil && exit != context.Canceled {
		log.Fatal(exit)
	}
}

// printStatus reports how many items each lane's spool has sequenced, so a
// restarted producer knows where its input resumes.
func printStatus(dir, boot string, max int64) {
	out := map[string]uint64{}
	for _, l := range []pb.Lane{pb.Lane_PRIORITY, pb.Lane_NORMAL} {
		sp, err := spool.Open(filepath.Join(dir, boot, l.String()), max, nil)
		if err != nil {
			log.Fatal(err)
		}
		out[l.String()] = sp.Next()
		sp.Close()
	}
	raw, _ := json.Marshal(map[string]any{"next_seq": out})
	fmt.Println(string(raw))
}

func feed(s *shipper.Shipper, in io.Reader) error {
	r := bufio.NewReaderSize(in, 1<<20)
	n := 0
	for {
		raw, err := r.ReadBytes('\n')
		if len(strings.TrimSpace(string(raw))) > 0 {
			if perr := handleLine(s, raw); perr != nil {
				return fmt.Errorf("input line %d: %w", n+1, perr)
			}
			n++
			if n%512 == 0 || r.Buffered() == 0 {
				if serr := s.Sync(); serr != nil {
					return serr
				}
			}
		}
		if err == io.EOF {
			return s.CloseInput()
		}
		if err != nil {
			return err
		}
	}
}

func handleLine(s *shipper.Shipper, raw []byte) error {
	var l line
	if err := json.Unmarshal(raw, &l); err != nil {
		return err
	}
	laneID := pb.Lane_NORMAL
	if l.Lane != "" {
		v, ok := pb.Lane_value[l.Lane]
		if !ok {
			return fmt.Errorf("unknown lane %q", l.Lane)
		}
		laneID = pb.Lane(v)
	}
	if l.Watermark != "" {
		t, err := time.Parse(time.RFC3339Nano, l.Watermark)
		if err != nil {
			return err
		}
		if err := s.Sync(); err != nil {
			return err
		}
		s.SetWatermark(laneID, t)
		return nil
	}
	kt, ok := pb.KeyType_value[l.KeyType]
	if !ok {
		return fmt.Errorf("unknown key type %q", l.KeyType)
	}
	env := &pb.Envelope{}
	if err := protojson.Unmarshal(l.Envelope, env); err != nil {
		return err
	}
	if env.GetKind() == pb.RecordKind_HEARTBEAT {
		return nil
	}
	return s.Submit(laneID, &pb.ShipItem{Topic: l.Topic, KeyType: pb.KeyType(kt), KeyComponents: l.KeyComponents, Envelope: env})
}
