// Package failpoint is the Go side of src/python/mtcore/failpoint.py:
// named crash points for Exp. 5 (evaluation-plan.md section 4, part A),
// compiled into every build and disabled unless armed.
//
//	failpoint.Hit("receiver.after_store_before_ack", state, require)
//
// The environment is read once at start (Configure in tests):
//
//   - MT_FAILPOINT          name of the one failpoint to arm
//   - MT_FAILPOINT_NTH      fire on the n-th qualifying hit (default 1)
//   - MT_FAILPOINT_MODE     "exit" (default) or "pause"
//   - MT_FAILPOINT_LOG      append one JSON line per firing here, fsynced
//   - MT_FAILPOINT_RELEASE  pause mode: block until this file exists
//   - MT_FAILPOINT_AFTER    hits count only once this file exists (the crash
//     runner creates it after a history prefill)
//
// A hit qualifies when require is nil or returns true. On firing, the line
// {"failpoint","hit","pid","time_ns","mode","state"} is written and fsynced
// first; exit mode then calls os.Exit(137), so no deferred function, flush
// or acknowledgement runs. Pause mode logs, blocks until the release file
// appears, logs {"released": true, ...} and returns; it fires once. A
// disabled failpoint costs one string comparison.
package failpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

// ExitCode is what an exit-mode firing exits with (as SIGKILL would).
const ExitCode = 137

var (
	mu      sync.Mutex
	armed   string
	nth     = 1
	mode    = "exit"
	logPath string
	release string
	after   string
	count   int
	done    bool
	exit    = os.Exit // replaced in tests
)

func init() {
	if err := Configure(os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "failpoint:", err)
		os.Exit(2)
	}
}

// Configure (re)reads the settings through getenv and resets the count.
func Configure(getenv func(string) string) error {
	mu.Lock()
	defer mu.Unlock()
	a, m := getenv("MT_FAILPOINT"), getenv("MT_FAILPOINT_MODE")
	if m == "" {
		m = "exit"
	}
	if m != "exit" && m != "pause" {
		return fmt.Errorf("MT_FAILPOINT_MODE must be exit or pause, not %q", m)
	}
	n := 1
	if s := getenv("MT_FAILPOINT_NTH"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			return fmt.Errorf("MT_FAILPOINT_NTH must be >= 1, not %q", s)
		}
		n = v
	}
	r := getenv("MT_FAILPOINT_RELEASE")
	if m == "pause" && a != "" && r == "" {
		return fmt.Errorf("pause mode needs MT_FAILPOINT_RELEASE")
	}
	armed, nth, mode, logPath, release = a, n, m, getenv("MT_FAILPOINT_LOG"), r
	after = getenv("MT_FAILPOINT_AFTER")
	count, done = 0, false
	return nil
}

// Armed is the armed failpoint's name ("" when none).
func Armed() string {
	mu.Lock()
	defer mu.Unlock()
	return armed
}

// Hit fires if name is armed and this is its n-th qualifying hit. state is
// called only then; it summarises the open state the kill interrupts.
func Hit(name string, state func() map[string]any, require func() bool) {
	if name != armed {
		return
	}
	mu.Lock()
	if done {
		mu.Unlock()
		return
	}
	if after != "" {
		if _, err := os.Stat(after); err != nil {
			mu.Unlock()
			return
		}
		after = "" // seen once; no more checks
	}
	if require != nil && !require() {
		mu.Unlock()
		return
	}
	count++
	if count != nth {
		mu.Unlock()
		return
	}
	done = true
	var st map[string]any
	if state != nil {
		st = state()
	}
	entry := map[string]any{"failpoint": name, "hit": count, "pid": os.Getpid(), "time_ns": time.Now().UnixNano(),
		"mode": mode, "state": st}
	m, rel := mode, release
	mu.Unlock()
	write(entry)
	if m == "exit" {
		exit(ExitCode)
		return
	}
	for {
		if _, err := os.Stat(rel); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	entry["released"], entry["time_ns"] = true, time.Now().UnixNano()
	write(entry)
}

func write(entry map[string]any) {
	line, err := json.Marshal(entry)
	if err != nil {
		line = []byte(fmt.Sprintf(`{"failpoint":%q,"error":%q}`, entry["failpoint"], err.Error()))
	}
	line = append(line, '\n')
	if logPath == "" {
		os.Stderr.Write(line)
		return
	}
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		os.Stderr.Write(line)
		return
	}
	defer f.Close()
	f.Write(line)
	f.Sync()
}
