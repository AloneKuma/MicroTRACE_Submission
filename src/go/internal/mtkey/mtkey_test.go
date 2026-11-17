package mtkey

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Every key in the spec's example trace must decode and re-encode to the
// same bytes.
func TestTraceKeysRoundTrip(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "spec", "examples", "trace-v0.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var trace struct {
		Records []struct {
			Label  string `json:"label"`
			KeyHex string `json:"key_hex"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatal(err)
	}
	if len(trace.Records) == 0 {
		t.Fatal("no records")
	}
	for _, r := range trace.Records {
		key, err := hex.DecodeString(r.KeyHex)
		if err != nil {
			t.Fatal(err)
		}
		_, kt, comps, err := Decode(key)
		if err != nil {
			t.Fatalf("%s: %v", r.Label, err)
		}
		again, err := Encode(kt, comps)
		if err != nil {
			t.Fatalf("%s: %v", r.Label, err)
		}
		if !bytes.Equal(again, key) {
			t.Fatalf("%s: re-encoded %x, want %x", r.Label, again, key)
		}
	}
}

// Fixed vectors computed with spec/tools/mtcodec.py encode_key.
func TestMatchesPythonMtcodec(t *testing.T) {
	cases := []struct {
		keyType uint16
		comps   []Component
		hex     string
	}{
		{1, []Component{{1, "node-1"}}, "4d540000010101000000066e6f64652d31"},
		{6, []Component{{6, "Pod"}, {7, "5e1a-uid"}}, "4d54000006020600000003506f640700000008356531612d756964"},
		{13, []Component{{12, "pod-uid-1"}, {11, "ln-abc"}}, "4d5400000d020c00000009706f642d7569642d310b000000066c6e2d616263"},
		{19, []Component{{21, "ingest-receiver-1"}}, "4d54000013011500000011696e676573742d72656365697665722d31"},
		{18, []Component{{19, "EBPF"}, {20, "node=n1/boot=b/lane=NORMAL"}}, "4d5400001202130000000445425046140000001a6e6f64653d6e312f626f6f743d622f6c616e653d4e4f524d414c"},
		{7, []Component{{8, "ServiceAccount"}, {9, "system:serviceaccount:ns:sä"}}, "4d5400000702080000000e536572766963654163636f756e74090000001c73797374656d3a736572766963656163636f756e743a6e733a73c3a4"},
	}
	for _, c := range cases {
		got, err := Encode(c.keyType, c.comps)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != c.hex {
			t.Fatalf("got %x want %s", got, c.hex)
		}
	}
}

func TestRejectsEmptyComponent(t *testing.T) {
	if _, err := Encode(1, []Component{{1, ""}}); err == nil {
		t.Fatal("empty component accepted")
	}
}
