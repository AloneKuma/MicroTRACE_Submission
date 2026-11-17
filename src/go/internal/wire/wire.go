// Package wire holds rules shared by the shipper and the ingest receiver
// (spec/kafka/ship-contract.md).
package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	"google.golang.org/protobuf/proto"

	pb "github.com/AloneKuma/MicroTRACE/src/go/gen/microtracev0"
)

// SchemaVersion is the shipping contract version sent in Hello and headers.
const SchemaVersion = "ship.v0"

var deterministic = proto.MarshalOptions{Deterministic: true}

// MarshalItem is the canonical serialization of one item.
func MarshalItem(it *pb.ShipItem) ([]byte, error) {
	return deterministic.Marshal(it)
}

// HashItems is the lowercase hex SHA-256 over each item's canonical
// serialization, concatenated in order.
func HashItems(items []*pb.ShipItem) (string, error) {
	h := sha256.New()
	for _, it := range items {
		b, err := MarshalItem(it)
		if err != nil {
			return "", err
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidID reports whether a node, boot or instance ID is safe to use in file
// names and scopes.
func ValidID(s string) bool { return idPattern.MatchString(s) }

// Scope names one node lane in completeness records.
func Scope(node, boot string, lane pb.Lane) string {
	return fmt.Sprintf("node=%s/boot=%s/lane=%s", node, boot, lane)
}

// Lanes in sending order.
var Lanes = []pb.Lane{pb.Lane_PRIORITY, pb.Lane_NORMAL}

// ValidLane reports whether lane is PRIORITY or NORMAL.
func ValidLane(l pb.Lane) bool { return l == pb.Lane_PRIORITY || l == pb.Lane_NORMAL }
