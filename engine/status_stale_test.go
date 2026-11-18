package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A session can end without a clean disconnect: SIGKILL from Activity Monitor,
// memory pressure, a force quit. The state file keeps connected:true while
// nothing serves the tunnel, so the UI shows "connected" and offers to
// disconnect a connection that is gone. Status must correct that, because it is
// the only command that ever looks at such a session.
func TestStatusClearsSessionWithDeadCore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WARP_CLIENT_HOME", dir)

	stale := clientState{
		Connected: true,
		CorePID:   999999, // cannot exist
		MixedPort: 7890,
		APIPort:   9090,
		TUN:       true,
		Proto:     "awg",
	}
	raw, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runStatusCmd(context.Background(), options{mixedPort: 7890, apiPort: 9090}); err != nil {
		t.Fatalf("runStatusCmd: %v", err)
	}

	after, err := loadState()
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if after.Connected {
		t.Error("connected stayed true for a session whose core is gone")
	}
	if after.CorePID != 0 {
		t.Errorf("core_pid = %d, want 0", after.CorePID)
	}
	if after.DNSService != "" || after.DNSSnap != nil {
		t.Errorf("resolver takeover record survived: service=%q snap=%v", after.DNSService, after.DNSSnap)
	}
}

// A session with a live core must survive a status call untouched — the guard
// above must only fire on a genuinely dead pid.
func TestStatusKeepsSessionWithLiveCore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WARP_CLIENT_HOME", dir)

	live := clientState{
		Connected: true,
		CorePID:   os.Getpid(), // this test process: definitely alive
		MixedPort: 7890,
		APIPort:   9090,
		TUN:       true,
		Proto:     "awg",
	}
	raw, err := json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runStatusCmd(context.Background(), options{mixedPort: 7890, apiPort: 9090}); err != nil {
		t.Fatalf("runStatusCmd: %v", err)
	}
	after, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	if !after.Connected {
		t.Error("status cleared a session whose core is alive")
	}
	if after.CorePID != os.Getpid() {
		t.Errorf("core_pid changed to %d", after.CorePID)
	}
}
