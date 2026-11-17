package failpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func readLog(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// fakeExit records the code instead of exiting.
func fakeExit(t *testing.T) *[]int {
	codes := &[]int{}
	old := exit
	exit = func(c int) { *codes = append(*codes, c) }
	t.Cleanup(func() { exit = old; Configure(env(nil)) })
	return codes
}

func TestDisabledDoesNothing(t *testing.T) {
	codes := fakeExit(t)
	if err := Configure(env(nil)); err != nil {
		t.Fatal(err)
	}
	Hit("receiver.mid_batch", nil, nil)
	if len(*codes) != 0 {
		t.Fatal("fired while disabled")
	}
}

func TestFiresOnTheNthQualifyingHitAndLogsFirst(t *testing.T) {
	codes := fakeExit(t)
	log := filepath.Join(t.TempDir(), "fp.log")
	if err := Configure(env(map[string]string{"MT_FAILPOINT": "p", "MT_FAILPOINT_NTH": "2",
		"MT_FAILPOINT_LOG": log})); err != nil {
		t.Fatal(err)
	}
	open := false
	req := func() bool { return open }
	st := func() map[string]any { return map[string]any{"records": 3} }
	Hit("p", nil, req) // does not qualify
	open = true
	Hit("other", nil, nil) // another name
	Hit("p", nil, req)     // 1st qualifying
	Hit("p", st, req)      // 2nd: fires
	Hit("p", nil, req)     // fires once
	if len(*codes) != 1 || (*codes)[0] != ExitCode {
		t.Fatalf("exit codes %v", *codes)
	}
	entries := readLog(t, log)
	if len(entries) != 1 {
		t.Fatalf("log %v", entries)
	}
	e := entries[0]
	if e["failpoint"] != "p" || e["hit"].(float64) != 2 || e["mode"] != "exit" ||
		e["state"].(map[string]any)["records"].(float64) != 3 {
		t.Fatalf("entry %v", e)
	}
}

func TestHitsBeforeTheAfterFileExistDoNotCount(t *testing.T) {
	codes := fakeExit(t)
	dir := t.TempDir()
	after := filepath.Join(dir, "armed")
	if err := Configure(env(map[string]string{"MT_FAILPOINT": "p", "MT_FAILPOINT_NTH": "2",
		"MT_FAILPOINT_AFTER": after, "MT_FAILPOINT_LOG": filepath.Join(dir, "fp.log")})); err != nil {
		t.Fatal(err)
	}
	Hit("p", nil, nil)
	Hit("p", nil, nil) // the prefill: not counted
	if len(*codes) != 0 {
		t.Fatal("fired before the after file existed")
	}
	if err := os.WriteFile(after, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	Hit("p", nil, nil) // 1st counted
	Hit("p", nil, nil) // 2nd: fires
	if len(*codes) != 1 {
		t.Fatalf("exit codes %v", *codes)
	}
	if e := readLog(t, filepath.Join(dir, "fp.log"))[0]; e["hit"].(float64) != 2 {
		t.Fatalf("entry %v", e)
	}
}

func TestPauseBlocksUntilReleased(t *testing.T) {
	fakeExit(t)
	dir := t.TempDir()
	log, rel := filepath.Join(dir, "fp.log"), filepath.Join(dir, "release")
	if err := Configure(env(map[string]string{"MT_FAILPOINT": "p", "MT_FAILPOINT_MODE": "pause",
		"MT_FAILPOINT_LOG": log, "MT_FAILPOINT_RELEASE": rel})); err != nil {
		t.Fatal(err)
	}
	returned := make(chan struct{})
	go func() { Hit("p", nil, nil); close(returned) }()
	select {
	case <-returned:
		t.Fatal("returned before release")
	case <-time.After(200 * time.Millisecond):
	}
	os.WriteFile(rel, []byte("go"), 0o644)
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("not released")
	}
	entries := readLog(t, log)
	if len(entries) != 2 || entries[1]["released"] != true {
		t.Fatalf("log %v", entries)
	}
}

func TestBadSettingsAreRejected(t *testing.T) {
	fakeExit(t)
	for _, m := range []map[string]string{
		{"MT_FAILPOINT_MODE": "crash"},
		{"MT_FAILPOINT_NTH": "0"},
		{"MT_FAILPOINT": "p", "MT_FAILPOINT_MODE": "pause"},
	} {
		if Configure(env(m)) == nil {
			t.Fatalf("accepted %v", m)
		}
	}
}
