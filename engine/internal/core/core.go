// Package core manages an embedded Clash/Mihomo core as the client's traffic
// engine. It owns the core binary, the working directory (config + geodata),
// the child process, and the host-side integration knobs (system proxy, TUN).
//
// The package is transport-agnostic: it takes a complete mihomo config.yaml as
// bytes and does not know about WARP, WireGuard, AmneziaWG or MASQUE. The
// caller (package main) renders those proxies from warpscout's engine.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xhwarp/warp-client/internal/filelock"
	"github.com/xhwarp/warp-client/internal/fsowner"
)

// Defaults for the managed config, matching what every Clash GUI client uses.
const (
	DefaultMixedPort = 7890
	DefaultAPIPort   = 9090
	ConfigName       = "config.yaml"
	geoSiteName      = "geosite.dat"
	geoIPName        = "geoip.dat"
)

// Config drives a Core.
type Config struct {
	// BinaryPath is the absolute path to the mihomo core executable.
	BinaryPath string
	// WorkDir is where config.yaml and geodata live.
	WorkDir string
	// MixedPort is the local HTTP+SOCKS port handed to system apps.
	MixedPort int
	// APIPort is the external-controller REST port (status / hot-reload).
	APIPort int
	// TUN enables the TUN inbound (needs admin + wintun on Windows).
	TUN bool
	// TieCoreToClient, when true, ties the core's lifetime to this process
	// (Windows job object, kill-on-close): a GUI killed mid-session must
	// never leave a stray core holding the ports. The CLI connect leaves
	// the core running on purpose — its whole contract is a connect command
	// that returns while the proxy keeps serving, with disconnect as a
	// separate invocation that reaches the core through the recorded pid.
	TieCoreToClient bool
	// LogWriter, when non-nil, receives a copy of everything the core process
	// writes to stdout/stderr (the GUI log panel). nil keeps the plain
	// passthrough to this process's own stdout.
	LogWriter io.Writer
}

// stdoutIsConsole reports whether our stdout is a real console. Only a console
// can be handed to a long-lived child safely: it has no reader that waits for
// EOF, unlike a pipe or a redirect.
func stdoutIsConsole() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// coreLogFile opens the file a CLI-mode core's output goes to, or returns nil
// when the console can take it directly. Callers defer Close: exec duplicates
// the handle for the child, so the parent's copy is done with once Start returns.
func coreLogFile(workDir string) *os.File {
	if stdoutIsConsole() {
		return nil
	}
	p := filepath.Join(workDir, "core.log")
	// The file is the durable sink and is appended on every session; cap it so
	// a long-lived install does not grow a hundred-megabyte log nobody reads.
	if fi, err := os.Stat(p); err == nil && fi.Size() > 4<<20 {
		_ = os.Remove(p)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil
	}
	// The core runs as root while the GUI and the user's shell do not: without
	// the chown, a core that dies after connect leaves its only explanation in a
	// file nobody but root can read.
	fsowner.Adopt(p, workDir)
	if fi, err := f.Stat(); err == nil && fi.Size() == 0 {
		_ = os.Chmod(p, 0o644)
	}
	return f
}

// swallowWriter never reports an error. A log sink that goes away — the GUI's
// pipe closing when its session ends, a log file on a full disk — must not
// become EPIPE inside the core: mihomo is a Go program, so a failed write to
// its stdout is SIGPIPE and the process dies. That is precisely how a session
// used to report "connected" and then stop carrying traffic a second later.
type swallowWriter struct{ w io.Writer }

func (s swallowWriter) Write(p []byte) (int, error) {
	if s.w != nil {
		_, _ = s.w.Write(p)
	}
	return len(p), nil
}

// Core is a running (or runnable) mihomo instance.
type Core struct {
	cfg    Config
	mu     sync.Mutex
	cmd    *exec.Cmd
	done   chan struct{}
	cancel context.CancelFunc
	// exitCode is how the child died (Windows exception codes are negative
	// ints). WaitReady reads it so a crash is reported as a crash instead of
	// "not ready within deadline".
	exitCode  int
	exitKnown bool
}

// New validates and prepares a Core. It does not start anything.
func New(cfg Config) (*Core, error) {
	if cfg.BinaryPath == "" {
		return nil, errors.New("core: empty BinaryPath")
	}
	if cfg.WorkDir == "" {
		return nil, errors.New("core: empty WorkDir")
	}
	if cfg.MixedPort == 0 {
		cfg.MixedPort = DefaultMixedPort
	}
	if cfg.APIPort == 0 {
		cfg.APIPort = DefaultAPIPort
	}
	abs, err := filepath.Abs(cfg.BinaryPath)
	if err != nil {
		return nil, err
	}
	cfg.BinaryPath = abs
	clearLaunchAttrs(abs)
	ensureExecutable(abs)
	return &Core{cfg: cfg}, nil
}

// ConfigPath returns where the running config is (or will be) written.
func (c *Core) ConfigPath() string {
	return filepath.Join(c.cfg.WorkDir, ConfigName)
}

// WriteConfig persists config bytes atomically into the work dir.
func (c *Core) WriteConfig(configYAML []byte) error {
	if err := os.MkdirAll(c.cfg.WorkDir, 0o755); err != nil {
		return fmt.Errorf("core: workdir: %w", err)
	}
	path := c.ConfigPath()
	// Repair from another engine process can rewrite the same config.yaml while
	// a connect is starting. Serialize the write so mihomo never reloads a
	// half-written file.
	return filelock.WithLock(path, func() error {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, configYAML, 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	})
}

// Running reports whether the core process is alive.
func (c *Core) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmd != nil
}

// PID returns the OS process id of the running core, or 0 when it has not
// been started (or has already exited) in this instance.
func (c *Core) PID() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd == nil || c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

// Start launches the core pointed at cfg.WorkDir. It blocks only until the
// process is spawned; use WaitReady to await readiness.
func (c *Core) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != nil {
		return errors.New("core: already running")
	}
	if err := os.MkdirAll(c.cfg.WorkDir, 0o755); err != nil {
		return fmt.Errorf("core: workdir: %w", err)
	}
	// Nothing may be listening on the core's ports when the new process binds
	// them. A leftover core that was killed but has not finished dying keeps
	// 7890/9090 bound; the new mihomo then fails its bind yet does NOT exit,
	// WaitReady and the tunnel verification get answered by the dying ghost,
	// and the connect reports success over a port that goes dark moments
	// later. Waiting for the ports to be free closes that whole failure class
	// no matter who left the listener behind.
	if err := waitPortFree("127.0.0.1", c.cfg.MixedPort, 5*time.Second, c.cfg.BinaryPath); err != nil {
		return fmt.Errorf("core: mixed port: %w", err)
	}
	if err := waitPortFree("127.0.0.1", c.cfg.APIPort, 5*time.Second, c.cfg.BinaryPath); err != nil {
		return fmt.Errorf("core: api port: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, c.cfg.BinaryPath, "-d", c.cfg.WorkDir)
	cmd.Dir = c.cfg.WorkDir
	// The core logs to stdout/stderr. With a GUI LogWriter attached it is the
	// ONLY sink: os.Stdout may be a dead handle in the windowsgui build, and
	// one failing writer in a MultiWriter stops the exec copier goroutine,
	// which fills the pipe and freezes the core. The CLI keeps its console.
	if c.cfg.LogWriter != nil {
		// Two sinks, both error-swallowing: core.log is the durable one (and
		// the only way to explain a core that dies after connect), the GUI
		// pipe is the live one. Neither may fail the write, for the SIGPIPE
		// reason spelled out on swallowWriter.
		sinks := []io.Writer{}
		if f := coreLogFile(c.cfg.WorkDir); f != nil {
			defer f.Close()
			sinks = append(sinks, swallowWriter{w: f})
		}
		sinks = append(sinks, swallowWriter{w: c.cfg.LogWriter})
		w := io.MultiWriter(sinks...)
		cmd.Stdout = w
		cmd.Stderr = w
	} else if f := coreLogFile(c.cfg.WorkDir); f != nil {
		// stdout is not a console: hand the core a log file, never our own
		// stdout. A child that inherited a pipe's write end keeps it open after
		// this process exits, so the reader on the other side (a script, an IDE
		// task, `ace connect | tee log`) blocks until the core dies —
		// a connect that "hangs" despite having succeeded.
		defer f.Close()
		cmd.Stdout = f
		cmd.Stderr = f
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	hideConsole(cmd)
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("core: start %s: %w", c.cfg.BinaryPath, err)
	}
	// GUI mode (and only GUI mode — see TieCoreToClient) ties the core to
	// this process's lifetime so a killed client can never orphan it.
	if c.cfg.TieCoreToClient {
		spawnWatchdog(cmd.Process.Pid)
	}
	c.cmd = cmd
	c.cancel = cancel
	c.done = make(chan struct{})
	go func() {
		err := cmd.Wait()
		c.mu.Lock()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				c.exitCode = ee.ExitCode()
				c.exitKnown = true
			}
		}
		c.cmd = nil
		c.mu.Unlock()
		close(c.done)
	}()
	return nil
}

// WaitReady polls the external-controller until it answers or ctx expires.
func (c *Core) WaitReady(ctx context.Context) error {
	base := "http://127.0.0.1:" + strconv.Itoa(c.cfg.APIPort) + "/version"
	for {
		select {
		case <-ctx.Done():
			if code, ok := c.CrashCode(); ok {
				return &CrashError{Code: code}
			}
			return fmt.Errorf("core: not ready within deadline: %w", ctx.Err())
		case <-c.done:
			// The child exited before it ever answered. Say why: a crash code
			// is a completely different problem from a config the core refused.
			if code, ok := c.CrashCode(); ok {
				return &CrashError{Code: code}
			}
			return fmt.Errorf("core: exited before it became ready")
		default:
		}
		if pingController(base) {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// CrashCode reports the Windows exception code the core died with, if it died
// on one (0xC0000005 and friends) rather than being stopped or exiting cleanly.
func (c *Core) CrashCode() (uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.exitKnown {
		return 0, false
	}
	code := uint32(c.exitCode)
	if code < 0xC0000000 {
		return 0, false
	}
	return code, true
}

// Stop terminates the core process and waits for it to exit.
func (c *Core) Stop() error {
	c.mu.Lock()
	cmd := c.cmd
	cancel := c.cancel
	c.mu.Unlock()
	if cmd == nil {
		return nil
	}
	if cancel != nil {
		cancel()
	}
	if c.done != nil {
		select {
		case <-c.done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-c.done
		}
	}
	return nil
}

// ErrPortInUse marks "somebody else is listening on a port this core needs".
// Callers match it to tell a port conflict apart from an endpoint failure: the
// latter is worth retrying on another node, the former is not worth retrying at
// all.
var ErrPortInUse = errors.New("port in use")

// waitPortFree blocks until nothing accepts connections on host:port, or the
// timeout expires. On loopback a refused dial is the definitive "no listener"
// answer, so anything that keeps accepting past the deadline is a leftover
// process the new core cannot coexist with — better a clear error than a
// bind-failed zombie core behind a "connected" light.
//
// expectExe lets the waiter recognise a listener that is our own core from a
// previous session: that one is reaped on the spot instead of burning the whole
// timeout. Anything else is left strictly alone — it may be an unrelated app —
// and the error names it so the user knows what to quit.
func waitPortFree(host string, port int, timeout time.Duration, expectExe string) error {
	if port <= 0 {
		return nil
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	deadline := time.Now().Add(timeout)
	reapTried := false
	for {
		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err != nil {
			return nil
		}
		_ = conn.Close()
		if !reapTried {
			reapTried = true
			if reapOwnCoreOnPort(port, expectExe) {
				continue
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: 端口 %d 被 %s 占用，请先退出该程序（或换一个端口）",
				ErrPortInUse, port, describePortOwner(port))
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// KillPortHolders ends every process listening on port and returns a short
// "name (pid N)" description of each one it killed. Unlike KillStaleCores this
// deliberately does not check who the process is: the session owns its mixed
// and API ports, a foreign listener there makes the connect impossible, and the
// old behaviour (wait five seconds, then fail) left the user with an error they
// could not act on. The caller reports what was killed so anything that turns
// out to matter can be started again.
func KillPortHolders(port int) []string {
	if port <= 0 {
		return nil
	}
	self := os.Getpid()
	var killed []string
	for pid, name := range portListeners(port) {
		if pid <= 1 || pid == self {
			continue
		}
		if name == "" {
			name = processName(pid)
		}
		label := fmt.Sprintf("pid %d", pid)
		if name != "" {
			label = fmt.Sprintf("%s (pid %d)", filepath.Base(name), pid)
		}
		// An empty expected executable disables the image check on purpose:
		// the holder may well be something this app never started.
		if err := KillByPID(pid, ""); err != nil {
			continue
		}
		killed = append(killed, label)
	}
	return killed
}

// reapOwnCoreOnPort kills a listener on port only when its executable is the
// same binary we are about to start. Returns true when something was reaped.
func reapOwnCoreOnPort(port int, expectExe string) bool {
	want := filepath.Base(expectExe)
	if want == "" || want == "." {
		return false
	}
	for pid, name := range portListeners(port) {
		if name == "" {
			name = processName(pid) // lsof gives no command name on some hosts
		}
		if !sameExeName(name, want) {
			continue
		}
		if KillByPID(pid, want) == nil {
			return true
		}
	}
	return false
}

// sameExeName matches a process's command name against the expected binary.
// lsof truncates command names to nine characters, so a prefix counts: "mihomo"
// is the full name anyway, but a "mihomo-1.19" style binary would otherwise
// never match its own leftover.
func sameExeName(name, want string) bool {
	if name == "" || want == "" {
		return false
	}
	base := filepath.Base(name)
	if base == want || name == want {
		return true
	}
	return len(base) >= 5 && strings.HasPrefix(want, base)
}

// describePortOwner renders "mihomo (pid 1234)" or a generic note for the error
// message, so a port clash stops being an unguessable dead end.
func describePortOwner(port int) string {
	for pid, name := range portListeners(port) {
		if name == "" {
			name = processName(pid)
		}
		if name != "" {
			return fmt.Sprintf("%s (pid %d)", filepath.Base(name), pid)
		}
		return fmt.Sprintf("pid %d", pid)
	}
	return "其他进程（需要更高权限才能看到）"
}

// ProxyDelay asks the running external-controller for the round-trip latency
// (ms) of the named proxy or proxy-group, through the given test URL. The GUI
// poller feeds this into its latency chart.
func ProxyDelay(apiPort int, name, testURL string) (int64, error) {
	base := "http://127.0.0.1:" + strconv.Itoa(apiPort) + "/proxies/" + name + "/delay"
	client := httpClient(6 * time.Second)
	u := base + "?url=" + url.QueryEscape(testURL) + "&timeout=5000"
	resp, err := client.Get(u)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("core: delay %d", resp.StatusCode)
	}
	var body struct {
		Delay int64 `json:"delay"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, err
	}
	return body.Delay, nil
}

// TrafficSample is one reading of the core's throughput plus the running
// totals for the session.
type TrafficSample struct {
	UpBps     int64 // bytes/sec right now
	DownBps   int64
	UpTotal   int64 // bytes since the core started (i.e. this session)
	DownTotal int64
}

// TrafficSampleNow samples the core's counters once.
//
// /traffic streams one object per second (bytes/sec), so a GET that decodes a
// single JSON value and hangs up yields one sample. Current cores also put the
// running totals in that same object, which is what lets the home page show a
// session total without a second request; older cores omit them, and then the
// totals come from /connections.
func TrafficSampleNow(apiPort int) (TrafficSample, error) {
	var out TrafficSample
	u := "http://127.0.0.1:" + strconv.Itoa(apiPort) + "/traffic"
	client := httpClient(3 * time.Second)
	resp, err := client.Get(u)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("core: traffic %d", resp.StatusCode)
	}
	// Pointers on purpose: nil means "this core does not report totals", which
	// is different from a total that is genuinely zero at session start.
	var body struct {
		Up        int64  `json:"up"`
		Down      int64  `json:"down"`
		UpTotal   *int64 `json:"upTotal"`
		DownTotal *int64 `json:"downTotal"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return out, err
	}
	out.UpBps, out.DownBps = body.Up, body.Down
	if body.UpTotal != nil && body.DownTotal != nil {
		out.UpTotal, out.DownTotal = *body.UpTotal, *body.DownTotal
		return out, nil
	}
	// Best effort: a core that answers /traffic but not /connections still has
	// a usable speed, and the caller must not lose the sample over a total.
	if tu, td, terr := TrafficTotals(apiPort); terr == nil {
		out.UpTotal, out.DownTotal = tu, td
	}
	return out, nil
}

// Traffic samples the core's live throughput counters once.
func Traffic(apiPort int) (up, down int64, err error) {
	s, err := TrafficSampleNow(apiPort)
	if err != nil {
		return 0, 0, err
	}
	return s.UpBps, s.DownBps, nil
}

// TrafficTotals reads the core's cumulative byte counters (since the core
// started, which for this app is the start of the session). /traffic only
// streams the per-second rate, so before this the UI had no way to show a
// session total - it could only ever display the current speed.
//
// /connections carries both counters next to the live connection list; only the
// two totals are decoded, and the list is skipped by the decoder rather than
// materialised.
func TrafficTotals(apiPort int) (up, down int64, err error) {
	u := "http://127.0.0.1:" + strconv.Itoa(apiPort) + "/connections"
	client := httpClient(3 * time.Second)
	resp, err := client.Get(u)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("core: connections %d", resp.StatusCode)
	}
	var body struct {
		DownloadTotal int64 `json:"downloadTotal"`
		UploadTotal   int64 `json:"uploadTotal"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, 0, err
	}
	return body.UploadTotal, body.DownloadTotal, nil
}

func pingController(base string) bool {
	client := httpClient(1 * time.Second)
	resp, err := client.Get(base)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 500
}
