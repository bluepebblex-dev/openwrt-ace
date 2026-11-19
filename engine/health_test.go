package main

import (
	"testing"

	"github.com/bluepebblex-dev/openwrt-ace/engine/internal/core"
)

// The failure counter is the difference between a session that shakes off a
// hiccup and one that throws away a working endpoint: a torn-down endpoint
// shows up here as the same generic error a single DNS timeout does, so the
// counting is what tells them apart. These lock that down.
func TestJudgeHealthTransientFailureDoesNotRotate(t *testing.T) {
	cases := []struct {
		name       string
		fails      int
		ok         bool
		wantFails  int
		wantRepair bool
		wantRecov  bool
	}{
		{"healthy stays healthy", 0, true, 0, false, false},
		{"one failure counted, no rotation", 0, false, 1, false, false},
		{"two failures counted, no rotation", 1, false, 2, false, false},
		{"third failure rotates", 2, false, 0, true, false},
		{"recovered after one failure clears it", 1, true, 0, false, true},
		{"recovered after two failures clears it", 2, true, 0, false, true},
		{"counting restarts after a rotation", 0, false, 1, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := judgeHealth(tc.fails, tc.ok)
			if got.fails != tc.wantFails || got.repair != tc.wantRepair || got.recovered != tc.wantRecov {
				t.Fatalf("judgeHealth(%d,%v) = %+v, want fails=%d repair=%v recovered=%v",
					tc.fails, tc.ok, got, tc.wantFails, tc.wantRepair, tc.wantRecov)
			}
		})
	}
}

// A whole bad streak then one good answer: the endpoint must survive it. This
// is the case a heavier hand gets wrong - the failures are real, they just
// stopped being true.
func TestJudgeHealthStreakThenRecovery(t *testing.T) {
	fails := 0
	for i := 0; i < healthFailLimit-1; i++ {
		v := judgeHealth(fails, false)
		if v.repair {
			t.Fatalf("rotated after %d failures", i+1)
		}
		fails = v.fails
	}
	v := judgeHealth(fails, true)
	if v.repair || v.fails != 0 || !v.recovered {
		t.Fatalf("judgeHealth(%d,true) = %+v, want cleared and reported recovered", fails, v)
	}
}

// processAlive must not claim liveness for pids that cannot be ours: ownership
// is decided by this answer, and a wrong "alive" keeps a session unmonitored.
func TestProcessAliveRejectsImpossiblePids(t *testing.T) {
	for _, pid := range []int{0, -1} {
		if processAlive(pid) {
			t.Fatalf("processAlive(%d) = true, want false", pid)
		}
	}
}

// P0 probe layering. The fast local probe's only job is to pardon a slow
// external probe when the core is still moving bytes; it must never invent
// liveness for an idle core or override a slow probe that succeeded.
func TestLocalLinkMoving(t *testing.T) {
	cases := []struct {
		name             string
		prev, cur        core.TrafficSample
		havePrev         bool
		wantMoving       bool
	}{
		{
			name:       "instantaneous up rate",
			cur:        core.TrafficSample{UpBps: 1024},
			wantMoving: true,
		},
		{
			name:       "instantaneous down rate",
			cur:        core.TrafficSample{DownBps: 512},
			wantMoving: true,
		},
		{
			name:       "cumulative bytes grew since last tick",
			prev:       core.TrafficSample{UpTotal: 100, DownTotal: 200},
			cur:        core.TrafficSample{UpTotal: 100, DownTotal: 260},
			havePrev:   true,
			wantMoving: true,
		},
		{
			name:       "idle core, cumulative unchanged",
			prev:       core.TrafficSample{UpTotal: 100, DownTotal: 200},
			cur:        core.TrafficSample{UpTotal: 100, DownTotal: 200},
			havePrev:   true,
			wantMoving: false,
		},
		{
			name:       "no previous sample and no rate cannot claim moving",
			cur:        core.TrafficSample{UpTotal: 999, DownTotal: 999},
			havePrev:   false,
			wantMoving: false,
		},
		{
			name:       "totals going backwards is not movement",
			prev:       core.TrafficSample{UpTotal: 500, DownTotal: 500},
			cur:        core.TrafficSample{UpTotal: 100, DownTotal: 100},
			havePrev:   true,
			wantMoving: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := localLinkMoving(tc.prev, tc.cur, tc.havePrev)
			if got != tc.wantMoving {
				t.Fatalf("localLinkMoving = %v, want %v (prev=%+v cur=%+v havePrev=%v)",
					got, tc.wantMoving, tc.prev, tc.cur, tc.havePrev)
			}
		})
	}
}

func TestDataPlaneOKIsOneWay(t *testing.T) {
	cases := []struct {
		name                         string
		slowOK, localMoving, wantOK  bool
	}{
		{"slow probe answered", true, false, true},
		{"slow answered and local moving", true, true, true},
		{"slow timed out but local moving - slow link", false, true, true},
		{"both silent - dead", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dataPlaneOK(tc.slowOK, tc.localMoving); got != tc.wantOK {
				t.Fatalf("dataPlaneOK(%v,%v) = %v, want %v", tc.slowOK, tc.localMoving, got, tc.wantOK)
			}
		})
	}
}

// End-to-end over the failure counter: a slow-but-live link must never rotate,
// no matter how many external probes time out; a genuinely dead one must still
// rotate after the usual limit. This is the regression that caused the whole
// house to flap - a working link rebuilt every 30s.
func TestSlowLinkNeverTriggersRepair(t *testing.T) {
	fails := 0
	for i := 0; i < healthFailLimit*5; i++ {
		// External probe times out, local core still moves bytes.
		live := dataPlaneOK(false, true)
		v := judgeHealth(fails, live)
		if v.repair {
			t.Fatalf("rotated after %d slow-link ticks; slow link must not repair", i+1)
		}
		fails = v.fails
		if fails != 0 {
			t.Fatalf("slow link accumulated %d failures, want 0", fails)
		}
	}
}

func TestDeadLinkStillTriggersRepair(t *testing.T) {
	fails := 0
	rotated := false
	for i := 0; i < healthFailLimit; i++ {
		// Both probes silent: external timeout and core not moving bytes.
		live := dataPlaneOK(false, false)
		v := judgeHealth(fails, live)
		fails = v.fails
		if v.repair {
			rotated = true
			break
		}
	}
	if !rotated {
		t.Fatalf("dead link did not rotate after %d failures", healthFailLimit)
	}
}

// A healthy session that is simply idle (no traffic) still relies on the slow
// probe: the local probe alone must not keep it alive when the external probe
// says dead. Otherwise a torn-down endpoint with a warmed cache never repairs.
func TestIdleCoreDoesNotMaskDeadEndpoint(t *testing.T) {
	fails := 0
	rotated := false
	for i := 0; i < healthFailLimit; i++ {
		// External says dead; local core idle (not moving).
		live := dataPlaneOK(false, false)
		v := judgeHealth(fails, live)
		fails = v.fails
		if v.repair {
			rotated = true
			break
		}
	}
	if !rotated {
		t.Fatalf("dead endpoint masked by idle core; did not rotate after %d failures", healthFailLimit)
	}
}
