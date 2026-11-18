package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluepebblex-dev/openwrt-ace/engine/internal/core"
)

// syncBuffer keeps bridgeSend's background writes from racing the test's reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A connect command must produce exactly one terminal result. An early ACK
// used to make clients report "connected" before the tunnel existed and hid
// the real failure result that followed.
func TestConnectEmitsSingleTerminalResult(t *testing.T) {
	if core.IsElevated() {
		t.Skip("test uses the non-elevated TUN check to fail fast")
	}

	oldOut := bridgeOut
	oldStage := connectStage
	defer func() {
		setBridgeOut(oldOut)
		connectStage = oldStage
	}()

	buf := &syncBuffer{}
	setBridgeOut(buf)
	sess := newBridgeSession()

	// tun_mode without elevation fails before account/scan/network work,
	// keeping the test offline and deterministic.
	opts, err := json.Marshal(map[string]any{"tun_mode": true})
	if err != nil {
		t.Fatal(err)
	}
	if sess.handle(bridgeMsg{ID: 77, Cmd: "connect", Opts: opts}) {
		t.Fatal("connect must not end the bridge session")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(buf.String(), `"event":"result"`) {
		time.Sleep(10 * time.Millisecond)
	}

	var results []bridgeEvent
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e bridgeEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad bridge event %q: %v", line, err)
		}
		if e.Event == "result" && e.ID == 77 {
			results = append(results, e)
		}
	}
	if len(results) != 1 {
		t.Fatalf("connect must emit exactly one result, got %d:\n%s", len(results), buf.String())
	}
	if results[0].OK || !strings.Contains(results[0].Error, "管理员") {
		t.Fatalf("unexpected connect result: %+v", results[0])
	}
}
