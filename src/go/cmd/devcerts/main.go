// Command devcerts makes a development CA, a receiver certificate and one
// client certificate per node for the shipping link. For development and
// tests only; never for an evaluated run.
//
//	devcerts -out certs -nodes node-1,node-2 -hosts 127.0.0.1,localhost
package main

import (
	"flag"
	"log"
	"strings"
	"time"

	"github.com/AloneKuma/MicroTRACE/src/go/internal/devpki"
)

func main() {
	out := flag.String("out", "certs", "output directory")
	nodes := flag.String("nodes", "node-1", "node IDs, comma-separated")
	hosts := flag.String("hosts", "127.0.0.1,localhost", "receiver names and IPs, comma-separated")
	days := flag.Int("days", 30, "validity in days")
	flag.Parse()
	n := strings.Split(*nodes, ",")
	if _, err := devpki.Generate(*out, n, strings.Split(*hosts, ","), time.Duration(*days)*24*time.Hour); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote CA, receiver and %d node certificates to %s", len(n), *out)
}
