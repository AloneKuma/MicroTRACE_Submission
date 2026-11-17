// Command receiver is the ingest receiver of the shipping contract
// (spec/kafka/ship-contract.md).
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/receiver"
	"github.com/AloneKuma/MicroTRACE/src/go/internal/tlsconf"
)

const version = "0.1.0"

func main() {
	listen := flag.String("listen", "127.0.0.1:50051", "address to listen on")
	cert := flag.String("cert", "", "receiver certificate (PEM)")
	key := flag.String("key", "", "receiver key (PEM)")
	ca := flag.String("ca", "", "CA that signs node certificates (PEM)")
	brokers := flag.String("brokers", "127.0.0.1:9092", "Kafka bootstrap brokers, comma-separated")
	topics := flag.String("topics", "spec/kafka/topics.yaml", "topics.yaml")
	allow := flag.String("allow", "raw.ebpf.v0,raw.audit.v0,raw.gateway.v0,raw.kyverno.v0,raw.dbaudit.v0,raw.pathflow.v0,context.cluster.v0,norm.events.v0",
		"topics shipped items may be written to")
	state := flag.String("state", "receiver-state", "directory for per-node sequence state")
	instance := flag.String("instance", "ingest-receiver-1", "producer instance name")
	runID := flag.String("run-id", "dev", "run_id on envelopes the receiver writes")
	heartbeat := flag.Duration("heartbeat", time.Second, "heartbeat interval")
	maxIdle := flag.Duration("max-idle", 30*time.Second, "silence after which a node is reported idle")
	produceTimeout := flag.Duration("produce-timeout", 15*time.Second, "Kafka write timeout per batch")
	flag.Parse()

	all, err := receiver.LoadTopics(*topics)
	if err != nil {
		log.Fatal(err)
	}
	allowed, err := receiver.Allow(all, *allow)
	if err != nil {
		log.Fatal(err)
	}
	bl := strings.Split(*brokers, ",")
	data, err := receiver.NewKafkaProducer(bl, false)
	if err != nil {
		log.Fatal(err)
	}
	defer data.Close()
	hb, err := receiver.NewKafkaProducer(bl, true)
	if err != nil {
		log.Fatal(err)
	}
	defer hb.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var names []string
	for n := range allowed {
		names = append(names, n)
	}
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	parts, err := receiver.PartitionCounts(pctx, data.Client, append(names, receiver.CompletenessTopic))
	cancel()
	if err != nil {
		log.Fatal(err)
	}

	srv := receiver.New(receiver.Config{
		Instance: *instance, ProducerVersion: version, RunID: *runID,
		Allowed: allowed, Completeness: all[receiver.CompletenessTopic], Partitions: parts,
		StateDir: *state, HeartbeatEvery: *heartbeat, MaxIdle: *maxIdle, ProduceTimeout: *produceTimeout,
	}, data, hb)

	tcfg, err := tlsconf.Server(*cert, *key, *ca)
	if err != nil {
		log.Fatal(err)
	}
	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tcfg)),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 10 * time.Second, Timeout: 5 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second, PermitWithoutStream: true}),
	)
	pb.RegisterIngestServer(gs, srv)
	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	go srv.Run(ctx)
	go func() {
		<-ctx.Done()
		gs.Stop()
	}()
	log.Printf("receiver %s listening on %s, writing %d topics", *instance, lis.Addr(), len(allowed))
	if err := gs.Serve(lis); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
