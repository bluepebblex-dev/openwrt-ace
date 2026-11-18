package core

import (
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A listener that is not our core must neither be killed nor be allowed to
// produce the old opaque message: the whole point is that the user is told
// which program is holding the port.
func TestWaitPortFreeNamesForeignListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	err = waitPortFree("127.0.0.1", port, 400*time.Millisecond, "/nonexistent/mihomo")
	if err == nil {
		t.Fatal("waitPortFree returned nil with a live listener on the port")
	}
	if !errors.Is(err, ErrPortInUse) {
		t.Fatalf("error does not wrap ErrPortInUse: %v", err)
	}
	// The unix implementation reports the pid; on a platform where the caller
	// cannot inspect other processes it falls back to a generic phrase, so only
	// assert the port and that something identifying is present.
	if !strings.Contains(err.Error(), strconv.Itoa(port)) {
		t.Fatalf("error does not name the port: %v", err)
	}
	if !strings.Contains(err.Error(), "pid ") && !strings.Contains(err.Error(), "权限") {
		t.Fatalf("error names no owner: %v", err)
	}

	// A foreign process is never collateral damage.
	conn, derr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 500*time.Millisecond)
	if derr != nil {
		t.Fatalf("foreign listener was killed: %v", derr)
	}
	_ = conn.Close()
}

// A port nobody holds must return immediately: connect must not pay the
// five-second wait on the happy path.
func TestWaitPortFreeReturnsImmediately(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	start := time.Now()
	if err := waitPortFree("127.0.0.1", port, 5*time.Second, "/nonexistent/mihomo"); err != nil {
		t.Fatalf("waitPortFree on a free port: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("free port took %v, expected an immediate return", d)
	}
}

// Port 0 means "no port configured" and must never block.
func TestWaitPortFreeSkipsZero(t *testing.T) {
	if err := waitPortFree("127.0.0.1", 0, 5*time.Second, ""); err != nil {
		t.Fatalf("port 0: %v", err)
	}
}

// reapOwnCoreOnPort must be a no-op when the executable name does not match,
// otherwise a connect could kill whatever app happens to sit on the port.
func TestReapOwnCoreIgnoresForeignBinary(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	if reapOwnCoreOnPort(port, "/tmp/definitely-not-mihomo") {
		t.Fatal("reaped a listener that is not our core")
	}
	if reapOwnCoreOnPort(port, "") {
		t.Fatal("reaped a listener with an empty expected executable")
	}
}

// The app-level policy on connect is that the session ports belong to us: a
// holder must be ended and named, whatever it is.
func TestKillPortHoldersEndsForeignListener(t *testing.T) {
	// nc needs an explicit port to be predictable; find a free one first.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cmd := exec.Command("/usr/bin/nc", "-l", "127.0.0.1", strconv.Itoa(port))
	if err := cmd.Start(); err != nil {
		t.Skipf("nc unavailable: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	time.Sleep(600 * time.Millisecond)
	if len(portListeners(port)) == 0 {
		t.Skip("nc did not bind (blocked in this environment)")
	}
	killed := KillPortHolders(port)
	if len(killed) == 0 {
		t.Fatalf("no holder was ended on port %d", port)
	}
	if !strings.Contains(killed[0], "pid ") {
		t.Fatalf("killed description names no pid: %q", killed[0])
	}
	time.Sleep(400 * time.Millisecond)
	if left := portListeners(port); len(left) != 0 {
		t.Fatalf("port still held: %v", left)
	}
}

// Our own process must never be a target: the engine may legitimately listen on
// a port it is asked to free.
func TestKillPortHoldersSkipsSelf(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	if killed := KillPortHolders(port); len(killed) != 0 {
		t.Fatalf("killed itself: %v", killed)
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second); err != nil {
		t.Fatalf("own listener died: %v", err)
	}
}
