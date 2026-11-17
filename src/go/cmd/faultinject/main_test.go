package main

import (
	"testing"
	"time"
)

// Two node streams with different first records share one clock: a record
// 20 s after the origin waits 20 s from the common start in both processes.
func TestPaceWaitSharedOrigin(t *testing.T) {
	origin := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	start := time.UnixMilli(1_800_000_000_000)
	emit := origin.Add(20 * time.Second)
	if w := paceWait(emit, origin, start, 1, start); w != 20*time.Second {
		t.Fatalf("wait %v, want 20s", w)
	}
	// Half a second later the same record waits 19.5 s; at pace 2 it waits 10 s from the start.
	if w := paceWait(emit, origin, start, 1, start.Add(500*time.Millisecond)); w != 19500*time.Millisecond {
		t.Fatalf("wait %v, want 19.5s", w)
	}
	if w := paceWait(emit, origin, start, 2, start); w != 10*time.Second {
		t.Fatalf("wait %v, want 10s", w)
	}
	// A record before the origin is not held.
	if w := paceWait(origin.Add(-time.Second), origin, start, 1, start); w > 0 {
		t.Fatalf("wait %v, want <= 0", w)
	}
}
