// Command faultinject applies the source-stage faults of a fault plan
// (spec/faults/fault-contract.md) to a base stream of shipper input lines and
// writes the faulted lines for the shipper. Transit-stage faults are applied
// by the shipper itself (-faults).
//
//	faultinject -plan plan.yaml -node node-1 -log faults.jsonl < base.jsonl | shipper -input - ...
//
// With -pace, records are written at event-time speed. Several node streams
// of one run replayed side by side (Exp. 3 senders) share one clock through
// -pace-origin (the event time that maps to the start) and -start-at-ms (the
// wall-clock start); without them each process starts at its own first record.
package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"os"
	"time"

	"github.com/AloneKuma/MicroTRACE/src/go/internal/faults"
)

func main() {
	planPath := flag.String("plan", "", "fault plan (required)")
	input := flag.String("input", "-", "base stream of shipper input lines, or - for stdin")
	output := flag.String("output", "-", "faulted lines, or - for stdout")
	logPath := flag.String("log", "", "fault log path (restricted, truth side only)")
	node := flag.String("node", "", "node this stream belongs to (for the log header)")
	pace := flag.Float64("pace", 0, "emit at event-time speed times this factor; 0 writes at once")
	paceOrigin := flag.String("pace-origin", "", "with -pace: event time (RFC 3339) that maps to the start (default: the first record's)")
	startAt := flag.Int64("start-at-ms", 0, "with -pace: wall-clock start in Unix ms (default: now)")
	flag.Parse()
	var origin time.Time
	if *paceOrigin != "" {
		t, err := time.Parse(time.RFC3339Nano, *paceOrigin)
		if err != nil {
			log.Fatalf("-pace-origin: %v", err)
		}
		origin = t
	}

	plan, err := faults.Load(*planPath)
	if err != nil {
		log.Fatal(err)
	}
	var in io.Reader = os.Stdin
	if *input != "-" {
		f, err := os.Open(*input)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		in = f
	}
	lines, err := faults.ReadLines(in)
	if err != nil {
		log.Fatal(err)
	}
	flog, err := faults.OpenLog(*logPath, plan, faults.StageSource, *node)
	if err != nil {
		log.Fatal(err)
	}
	out, err := faults.ApplySource(plan, lines, flog)
	if err != nil {
		log.Fatal(err)
	}
	if err := flog.Close(); err != nil {
		log.Fatal(err)
	}

	var w io.Writer = os.Stdout
	if *output != "-" {
		f, err := os.Create(*output)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = f
	}
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()
	t0 := origin
	start := time.Now()
	if *startAt > 0 {
		start = time.UnixMilli(*startAt)
	}
	for _, ln := range out {
		if *pace > 0 && !ln.Emit.IsZero() {
			if t0.IsZero() {
				t0 = ln.Emit
			}
			wait := paceWait(ln.Emit, t0, start, *pace, time.Now())
			if wait > 0 {
				if err := bw.Flush(); err != nil {
					log.Fatal(err)
				}
				time.Sleep(wait)
			}
		}
		b, err := ln.Bytes()
		if err != nil {
			log.Fatal(err)
		}
		bw.Write(b)
		bw.WriteByte('\n')
	}
	log.Printf("faultinject: %d lines in, %d out", len(lines), len(out))
}

// paceWait is how long to wait before writing a record emitted at emit (event
// time), when event time origin maps to wall time start and replay runs at
// pace times event-time speed. Records at or before the origin are not held.
func paceWait(emit, origin, start time.Time, pace float64, now time.Time) time.Duration {
	return time.Duration(float64(emit.Sub(origin))/pace) - now.Sub(start)
}
