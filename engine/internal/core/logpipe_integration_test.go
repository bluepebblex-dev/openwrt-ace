package core

import (
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

type failingWriter struct{ n int }

func (f *failingWriter) Write(p []byte) (int, error) {
	f.n += len(p)
	return 0, errors.New("pipe closed")
}

// A log sink that keeps failing must not take the core down with it.
//
// This is the regression test for the worst bug this client had: the GUI's log
// pipe was closed as soon as connect returned, the child's next log line hit
// EPIPE, mihomo (a Go program) died of SIGPIPE, and the session reported
// "connected" while nothing carried traffic. swallowWriter is the fix.
func TestBrokenLogWriterKeepsCoreAlive(t *testing.T) {
	bin := os.Getenv("WARP_TEST_MIHOMO")
	if bin == "" {
		t.Skip("set WARP_TEST_MIHOMO=<path to mihomo> to run this test")
	}
	dir := t.TempDir()
	port := 17894
	c, err := New(Config{BinaryPath: bin, WorkDir: dir, MixedPort: port, APIPort: 19094, LogWriter: &failingWriter{}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	cfg := []byte("mixed-port: " + strconv.Itoa(port) + "\nexternal-controller: 127.0.0.1:19094\nmode: direct\nlog-level: info\nproxies: []\nrules:\n  - MATCH,DIRECT\n")
	if err := c.WriteConfig(cfg); err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.Stop()
	time.Sleep(2 * time.Second)

	// 产生流量，逼内核写日志
	for i := 0; i < 10; i++ {
		conn, derr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if derr != nil {
			t.Fatalf("第 %d 次：内核已经不可连接，说明仍被日志写死: %v", i+1, derr)
		}
		_ = conn.Close()
		time.Sleep(150 * time.Millisecond)
	}
	t.Log("日志写入持续失败，内核仍存活")
}
