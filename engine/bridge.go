package main

// bridge is the JSON-lines control channel between the macOS SwiftUI client
// and this Go engine. It drives the exact same functions the Windows native
// GUI drives (runConnectCmd / runDisconnectCmd / runCachedScan / settings),
// so the Mac build has full feature parity with the original client.
//
// Protocol (newline-delimited JSON over stdin/stdout):
//   in:  {"id":1,"cmd":"connect","opts":{...}}
//   out: {"event":"stage","text":"..."}          progress line
//   out: {"event":"corelog","text":"..."}        mihomo core log line
//   out: {"event":"state","state":{...}}         clientState snapshot
//   out: {"event":"result","id":1,"ok":true,...} command result
//
// A result event is the TERMINAL outcome of a command: exactly one per id,
// emitted only when the work has actually finished. Async commands must not
// send an early "started" ACK with the same id - clients would treat it as
// success (e.g. report "connected" before the tunnel exists) and drop the
// real failure result that follows.
//
// Stderr is reserved for plain diagnostic text; the GUI reads stdout only.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xhwarp/warp-client/internal/cache"
	"github.com/xhwarp/warp-client/internal/core"
	"github.com/xhwarp/warp-client/internal/subscription"
)

// bridgeMsg is an inbound command.
type bridgeMsg struct {
	ID   int64           `json:"id"`
	Cmd  string          `json:"cmd"`
	Opts json.RawMessage `json:"opts"`
}

// bridgeEvent is an outbound event.
type bridgeEvent struct {
	Event string          `json:"event"`
	ID    int64           `json:"id,omitempty"`
	OK    bool            `json:"ok,omitempty"`
	Text  string          `json:"text,omitempty"`
	Error string          `json:"error,omitempty"`
	State *clientState    `json:"state,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

var (
	bridgeOutMu sync.Mutex
	bridgeOut   io.Writer = os.Stdout // stdout in stdio mode, socket conn in socket mode
)

func setBridgeOut(w io.Writer) {
	bridgeOutMu.Lock()
	bridgeOut = w
	bridgeOutMu.Unlock()
}

func bridgeSend(e bridgeEvent) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	bridgeOutMu.Lock()
	defer bridgeOutMu.Unlock()
	_, _ = bridgeOut.Write(b)
}

// bridgeConnectOpts mirrors the fields the GUI sets on options for a connect.
type bridgeConnectOpts struct {
	Proto         string `json:"proto"`
	TunMode       bool   `json:"tun_mode"`
	ScanNow       bool   `json:"scan_now"`
	MixedPort     int    `json:"mixed_port"`
	APIPort       int    `json:"api_port"`
	TimeoutSec    int    `json:"timeout_sec"`
	MTU           int    `json:"mtu"`
	AllowLan      bool   `json:"allow_lan"`
	Family        string `json:"family"`
	IPv6          bool   `json:"ipv6"`
	ProxyMode     string `json:"proxy_mode"`
	DNS           string `json:"dns"`
	DNSOff        bool   `json:"dns_off"`
	DNSLeak       bool   `json:"dns_leak"`
	DomainDirect  string `json:"domain_direct"`
	DomainProxy   string `json:"domain_proxy"`
	NoGuard       bool   `json:"no_guard"`
	Pick          string `json:"pick"`
	Psiphon       bool   `json:"psiphon"`
	PsiphonRegion string `json:"psiphon_region"`
	OpenVPN       bool   `json:"openvpn"`
	OpenVPNRegion string `json:"openvpn_region"`
	OpenVPNNode   string `json:"openvpn_node"`
	OuterProto    string `json:"outer_proto"`
	InnerProto    string `json:"inner_proto"`
	// Subscription carrier ("订阅前置"): SubURL is the Clash subscription link,
	// SubNode the pinned node name ("" = fastest), SubCarrier the on/off switch.
	SubURL     string `json:"sub_url"`
	SubNode    string `json:"sub_node"`
	SubCarrier bool   `json:"sub_carrier"`
}

// buildConnectOptions converts the bridge options into the engine's options —
// the same shape defaultConnectOptions + settings.apply produce in the GUI.
func buildConnectOptions(b bridgeConnectOpts) options {
	// macOS GUI contract: TUN capture only. Even a stale settings file that
	// still says "proxy" must not lead the engine to edit network services -
	// the tun device routes everything, and the proxy edit is exactly what
	// users asked us to stop doing (undo-on-exit, LAN/China sites broken).
	// connect.go enforces the same rule, this keeps the GUI path honest too.
	if runtime.GOOS == "darwin" {
		b.TunMode = true
	}
	o := defaultConnectOptions(b.Proto, b.TunMode, b.ScanNow)
	if b.MixedPort > 0 {
		o.mixedPort = b.MixedPort
	}
	if b.APIPort > 0 {
		o.apiPort = b.APIPort
	}
	if b.TimeoutSec > 0 {
		o.timeoutSec = b.TimeoutSec
	}
	o.mtu = b.MTU
	o.allowLan = b.AllowLan
	if b.Family != "" {
		o.family = b.Family
	}
	o.ipv6 = b.IPv6
	if b.ProxyMode != "" {
		o.proxyMode = b.ProxyMode
	}
	o.dns = b.DNS
	o.noDNS = b.DNSOff
	o.dnsLeak = b.DNSLeak && !b.DNSOff
	o.domainDirect = parseList(b.DomainDirect)
	o.domainProxy = parseList(b.DomainProxy)
	o.noGuard = b.NoGuard
	o.pick = b.Pick
	o.psiphonRegion = b.PsiphonRegion
	o.openvpnRegion = b.OpenVPNRegion
	o.openvpnNodePin = b.OpenVPNNode
	if b.OuterProto != "" {
		o.outerProto = b.OuterProto
	}
	if b.InnerProto != "" {
		o.innerProto = b.InnerProto
	}
	if b.Psiphon && !strings.HasPrefix(o.proto, protoWWarp) {
		o.psiphonMode = true
	}
	if b.OpenVPN && !strings.HasPrefix(o.proto, protoWWarp) {
		o.openvpnMode = true
	}
	o.subURL = strings.TrimSpace(b.SubURL)
	o.subNode = strings.TrimSpace(b.SubNode)
	o.subCarrier = b.SubCarrier && o.subURL != ""
	return o
}

func parseList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
}

// bridgeSession owns the in-flight connect and processes commands.
//
// connectDone exists because "cancel" must not merely ask the connect to stop:
// the UI reports "已断开" the moment cancel returns, so by then the goroutine
// has to be gone and anything it started has to be torn down. Without the wait,
// a core started microseconds later outlives the click — an orphan holding the
// mixed port until the next connect kills it.
type bridgeSession struct {
	ctxMu         sync.Mutex
	connectCtx    context.Context
	connectCancel context.CancelFunc
	connectDone   chan struct{}
	// The live session's core-log pipe. It is handed over when a connect
	// succeeds and closed only when that session ends: closing it early is
	// what used to kill the core (SIGPIPE on its next log line) a second
	// after the UI said "connected".
	logPr *io.PipeReader
	logPw *io.PipeWriter
}

// holdCoreLog takes ownership of a successful session's log pipe, replacing and
// closing whatever the previous session left behind.
func (s *bridgeSession) holdCoreLog(pr *io.PipeReader, pw *io.PipeWriter) {
	s.ctxMu.Lock()
	oldPr, oldPw := s.logPr, s.logPw
	s.logPr, s.logPw = pr, pw
	s.ctxMu.Unlock()
	if oldPw != nil {
		_ = oldPw.Close()
	}
	if oldPr != nil {
		_ = oldPr.Close()
	}
}

// closeCoreLog ends the log stream of a finished session.
func (s *bridgeSession) closeCoreLog() {
	s.holdCoreLog(nil, nil)
}

// cancelConnectAndWait cancels the running connect (if any) and waits for its
// goroutine to return. Reports false when the deadline passed first: the caller
// then tells the user rather than pretending the teardown succeeded.
func (s *bridgeSession) cancelConnectAndWait(timeout time.Duration) bool {
	s.ctxMu.Lock()
	cancel, done := s.connectCancel, s.connectDone
	s.ctxMu.Unlock()
	if cancel == nil {
		return true
	}
	cancel()
	if done == nil {
		return true
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func newBridgeSession() *bridgeSession {
	// Wire the engine's progress seam to bridge events.
	connectStage = func(s string) { bridgeSend(bridgeEvent{Event: "stage", Text: s}) }
	return &bridgeSession{}
}

// handle processes one inbound command. Returns true on "quit".
func (s *bridgeSession) handle(m bridgeMsg) bool {
	switch m.Cmd {
	case "connect":
		var b bridgeConnectOpts
		if len(m.Opts) > 0 {
			_ = json.Unmarshal(m.Opts, &b)
		}
		// One connect at a time: a second one would fight the first for the
		// same ports, and the loser's failure would be reported against a
		// connect the user has already replaced.
		if !s.cancelConnectAndWait(20 * time.Second) {
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false,
				Error: "上一个连接还没停下，请稍后重试"})
			return false
		}
		s.closeCoreLog()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		s.ctxMu.Lock()
		s.connectCtx, s.connectCancel, s.connectDone = ctx, cancel, done
		s.ctxMu.Unlock()

		// Tee core logs into bridge events.
		pr, pw := io.Pipe()
		go func() {
			defer pr.Close()
			bs := bufio.NewScanner(pr)
			bs.Buffer(make([]byte, 64*1024), 1024*1024)
			for bs.Scan() {
				t := strings.TrimSpace(bs.Text())
				if t != "" {
					bridgeSend(bridgeEvent{Event: "corelog", Text: t})
				}
			}
		}()

		o := buildConnectOptions(b)
		o.coreLog = pw
		id := m.ID
		go func(id int64, o options, ctx context.Context, pw *io.PipeWriter, done chan struct{}) {
			// Deferred so EVERY exit path (panic included) releases the
			// cancel slot and unblocks a waiter.
			defer close(done)
			defer func() {
				s.ctxMu.Lock()
				if s.connectDone == done {
					s.connectCtx, s.connectCancel, s.connectDone = nil, nil, nil
				}
				s.ctxMu.Unlock()
			}()
			err := runConnectCmd(ctx, o)
			if err != nil {
				_ = pw.Close()
			} else {
				// 内核还在往这个管道写日志。交给会话保管，断开时再关——
				// 提前关掉就是内核下一行日志 SIGPIPE 退出。
				s.holdCoreLog(pr, pw)
			}
			if err != nil {
				bridgeSend(bridgeEvent{Event: "result", ID: id, OK: false, Error: err.Error()})
			} else {
				bridgeSend(bridgeEvent{Event: "result", ID: id, OK: true})
			}
			if st, e := loadState(); e == nil {
				bridgeSend(bridgeEvent{Event: "state", State: &st})
			}
		}(id, o, ctx, pw, done)
		// No early ACK here: the single result from the goroutine above is the
		// only signal that the tunnel is really up (or really failed).

	case "cancel":
		// 取消的语义是「停下并把已经起来的东西收回去」，所以回复要等到这两件事
		// 都做完：连接协程自己在退出的路上会 Stop 掉内核，随后的 disconnect 补上
		// 它还没来得及写进 state 的那部分（内核 pid、TUN 路由、系统 DNS）。
		stopped := s.cancelConnectAndWait(20 * time.Second)
		s.closeCoreLog()
		terr := runDisconnectCmd(context.Background(), options{mixedPort: core.DefaultMixedPort})
		switch {
		case !stopped:
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false,
				Error: "取消超时：引擎没有及时停下，已强制断开，请看日志确认内核是否退出"})
		case terr != nil:
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false, Error: terr.Error()})
		default:
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true})
		}
		if st, e := loadState(); e == nil {
			bridgeSend(bridgeEvent{Event: "state", State: &st})
		}

	case "disconnect":
		// The connect button is clickable mid-connect: stop that attempt first,
		// or its core is started right after the teardown below and survives it.
		s.cancelConnectAndWait(20 * time.Second)
		s.closeCoreLog()
		err := runDisconnectCmd(context.Background(), options{mixedPort: core.DefaultMixedPort})
		if err != nil {
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false, Error: err.Error()})
		} else {
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true})
		}
		if st, e := loadState(); e == nil {
			bridgeSend(bridgeEvent{Event: "state", State: &st})
		}

	case "status":
		st, err := loadState()
		if err != nil {
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false, Error: err.Error()})
		} else {
			b, _ := json.Marshal(st)
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true, Data: b})
		}

	case "settings_get":
		st := loadSettings()
		b, _ := json.Marshal(st)
		bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true, Data: b})

	case "settings_set":
		var st clientSettings
		if err := json.Unmarshal(m.Opts, &st); err != nil {
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false, Error: err.Error()})
		} else if err := saveSettings(st); err != nil {
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false, Error: err.Error()})
		} else {
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true})
		}

	case "list":
		var b struct {
			Proto string `json:"proto"`
			IPv6  bool   `json:"ipv6"`
		}
		if len(m.Opts) > 0 {
			_ = json.Unmarshal(m.Opts, &b)
		}
		cs, ok := cachedScanFor(b.Proto, b.IPv6)
		if !ok {
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true, Data: json.RawMessage("[]")})
		} else {
			if cs.Results == nil {
				cs.Results = []cachedEndpoint{}
			}
			d, _ := json.Marshal(cs.Results)
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true, Data: d})
		}

	case "traffic":
		var b struct {
			Port int `json:"port"`
		}
		_ = json.Unmarshal(m.Opts, &b)
		s, err := core.TrafficSampleNow(b.Port)
		if err != nil {
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false, Error: err.Error()})
		} else {
			d, _ := json.Marshal(map[string]int64{
				"up":         s.UpBps,
				"down":       s.DownBps,
				"up_total":   s.UpTotal,
				"down_total": s.DownTotal,
			})
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true, Data: d})
		}

	case "paths":
		d, _ := appDir()
		cd, _ := coreDir()
		bin := ""
		if cd != "" {
			bin = core.CoreInDir(cd)
		}
		coreVersion := ""
		coreSize := int64(0)
		if bin != "" {
			if fi, err := os.Stat(bin); err == nil {
				coreSize = fi.Size()
			}
			if coreSize > 0 {
				if out, err := exec.Command(bin, "-v").Output(); err == nil {
					coreVersion = strings.TrimSpace(string(out))
				}
			}
		}
		info := map[string]any{
			"app_dir": d, "core_dir": cd, "core_bin": bin,
			"version": shortVersion(), "is_root": core.IsElevated(),
			"core_version": coreVersion, "core_size": coreSize,
		}
		b, _ := json.Marshal(info)
		bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true, Data: b})

	case "ensure_core":
		cd, err := coreDir()
		if err != nil {
			bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false, Error: err.Error()})
		} else {
			bin, err := core.EnsureBinary(cd, "")
			if err != nil {
				bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false, Error: err.Error()})
			} else {
				d, _ := json.Marshal(map[string]any{"core_bin": bin})
				bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true, Data: d})
			}
		}

	case "vpn_nodes":
		// Return the cached VPN Gate pool + derived country list (fast, for UI startup).
		// Normalize nil to empty slices so the JSON reads as [] rather than null.
		nodes, at := loadVPNGateCache()
		// Hand the picker a list that is already in "what would be tried
		// first" order: measured latency, then the API's ping, then class.
		// Without this the menu shows whatever order the last refresh wrote.
		sortVPNGateNodesByLatency(nodes)
		countries := vpnGateCountries(nodes)
		if nodes == nil {
			nodes = []vpnGateNode{}
		}
		if countries == nil {
			countries = []vpnGateCountry{}
		}
		d, _ := json.Marshal(map[string]any{
			"nodes": nodes, "countries": countries, "at": at.Unix(),
			"count": len(nodes),
		})
		bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true, Data: d})

	case "sub_fetch":
		// Pull a Clash subscription, parse it, and measure each node so the
		// picker can show something more useful than a name. `url` comes from
		// opts so the same struct shape carries it; `force` bypasses the cache
		// when the user asks for a refresh.
		id := m.ID
		var sopt struct {
			URL   string `json:"url"`
			Force bool   `json:"force"`
		}
		_ = json.Unmarshal(m.Opts, &sopt)
		go func() {
			bridgeSend(bridgeEvent{Event: "stage", Text: "正在拉取订阅…"})
			nodes, err := fetchSubscription(sopt.URL, sopt.Force)
			if err != nil {
				bridgeSend(bridgeEvent{Event: "result", ID: id, OK: false, Error: err.Error()})
				return
			}
			bridgeSend(bridgeEvent{Event: "stage", Text: fmt.Sprintf("订阅解析成功：%d 个节点，正在测速…", len(nodes))})
			lat := subscription.Latencies(nodes, 3*time.Second, 12)
			type row struct {
				Name    string `json:"name"`
				Type    string `json:"type"`
				Server  string `json:"server"`
				Port    int    `json:"port"`
				Latency int64  `json:"latency_ms"`
			}
			rows := make([]row, 0, len(nodes))
			reachable := 0
			for _, n := range nodes {
				ms := lat[n.Name]
				if ms > 0 {
					reachable++
				}
				rows = append(rows, row{Name: n.Name, Type: n.Type, Server: n.Server, Port: n.Port, Latency: ms})
			}
			// Best first: the picker's default is "fastest", and an unreachable
			// node at the top of the list reads as if it were the best one.
			sort.SliceStable(rows, func(i, j int) bool {
				a, b := rows[i].Latency, rows[j].Latency
				if a == 0 {
					return false
				}
				if b == 0 {
					return true
				}
				return a < b
			})
			d, _ := json.Marshal(map[string]any{
				"nodes": rows, "count": len(rows), "reachable": reachable,
			})
			bridgeSend(bridgeEvent{Event: "data", Text: "sub_nodes", Data: d})
			bridgeSend(bridgeEvent{Event: "result", ID: id, OK: true})
		}()

	case "vpn_refresh":
		// Force a fresh VPN Gate fetch: direct HTTPS -> parse -> classify ->
		// probe latency -> sort -> cache. Emits stage events as it progresses.
		id := m.ID
		go func() {
			bridgeSend(bridgeEvent{Event: "stage", Text: "正在获取 VPN Gate 节点…"})
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			raw, err := fetchVPNGateDirect(ctx)
			if err != nil {
				bridgeSend(bridgeEvent{Event: "result", ID: id, OK: false, Error: err.Error()})
				return
			}
			nodes := parseVPNGateCSV(raw)
			if len(nodes) == 0 {
				bridgeSend(bridgeEvent{Event: "result", ID: id, OK: false, Error: "VPN Gate 返回的列表为空"})
				return
			}
			bridgeSend(bridgeEvent{Event: "stage", Text: "正在识别家宽/机房节点…"})
			enrichCtx, ecancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, _ = enrichVPNGateClasses(enrichCtx, &http.Client{Timeout: 15 * time.Second}, nodes)
			ecancel()
			bridgeSend(bridgeEvent{Event: "stage", Text: "正在测量节点延迟…"})
			measureVPNGateLatency(ctx, nodes)
			sortVPNGateNodesByLatency(nodes)
			saveVPNGateCache(nodes)
			countries := vpnGateCountries(nodes)
			d, _ := json.Marshal(map[string]any{
				"nodes": nodes, "countries": countries, "at": time.Now().Unix(),
				"count": len(nodes),
			})
			bridgeSend(bridgeEvent{Event: "data", Text: "vpn_nodes", Data: d})
			bridgeSend(bridgeEvent{Event: "stage", Text: fmt.Sprintf("VPN Gate 节点获取成功：%d 个节点，%d 个国家", len(nodes), len(countries))})
			// Terminal result resolves the pending callback. The data event
			// above is the UI payload; no early "started" result is sent.
			bridgeSend(bridgeEvent{Event: "result", ID: id, OK: true, Data: d})
		}()

	case "scan_endpoints":
		// Force a fresh WARP endpoint scan (Nodes page refresh).
		id := m.ID
		var b struct {
			Proto   string `json:"proto"`
			IPv6    bool   `json:"ipv6"`
			Timeout int    `json:"timeout_sec"`
		}
		if len(m.Opts) > 0 {
			_ = json.Unmarshal(m.Opts, &b)
		}
		if b.Proto == "" {
			b.Proto = protoAWG
		}
		if b.Timeout <= 0 {
			b.Timeout = 2
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()
			opts := defaultConnectOptions(b.Proto, false, true)
			opts.ipv6 = b.IPv6
			opts.timeoutSec = b.Timeout
			results, _, err := doScan(ctx, opts)
			if err != nil {
				bridgeSend(bridgeEvent{Event: "result", ID: id, OK: false, Error: err.Error()})
				return
			}
			// Cache the fresh scan so connect + Nodes list pick it up.
			if store, e := cache.Open(cache.Options{TTL: scanTTL}); e == nil {
				cs := cachedScan{Proto: b.Proto, IPv6: b.IPv6, At: time.Now(), Results: results}
				if raw, e := json.Marshal(cs); e == nil {
					_ = store.Put(scanCacheKey(b.Proto, b.IPv6), raw)
				}
			}
			d, _ := json.Marshal(results)
			bridgeSend(bridgeEvent{Event: "data", Text: "endpoints", Data: d})
			bridgeSend(bridgeEvent{Event: "result", ID: id, OK: true, Data: d})
		}()

	case "quit":
		bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: true})
		return true

	default:
		bridgeSend(bridgeEvent{Event: "result", ID: m.ID, OK: false, Error: "unknown cmd: " + m.Cmd})
	}
	return false
}

func scanLines(r io.Reader, fn func(bridgeMsg) bool) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m bridgeMsg
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			bridgeSend(bridgeEvent{Event: "result", OK: false, Error: "bad json: " + err.Error()})
			continue
		}
		if fn(m) {
			return
		}
	}
}

// runBridge is the bridge command entry point. With --socket PATH it serves a
// Unix domain socket (used for the elevated TUN session); otherwise it uses
// stdin/stdout.
func runBridge() int {
	ensurePortableHome()
	adoptDataFiles()
	// Repair a resolver takeover left by a previous crash before anything
	// else: the machine cannot resolve names until it is undone.
	healStaleHostDNS()
	defer bridgeExitCleanup()
	sock := ""
	for i, a := range os.Args {
		if a == "--socket" && i+1 < len(os.Args) {
			sock = os.Args[i+1]
		}
	}
	sess := newBridgeSession()
	defer func() { connectStage = nil }()

	if sock != "" {
		_ = os.Remove(sock)
		ln, err := net.Listen("unix", sock)
		if err != nil {
			return 1
		}
		// This listener is created by the elevated (root) process under umask
		// 022, which leaves the node 0755: the desktop user can see it but not
		// write to it, and connecting to a Unix socket requires write permission.
		// The GUI runs as that user, so nc failed instantly and every command was
		// silently dropped (connect spun forever with no stage output). 0666 keeps
		// the node usable by the desktop session without widening anything else.
		_ = os.Chmod(sock, 0o666)
		defer os.Remove(sock)
		conn, err := ln.Accept()
		if err != nil {
			return 1
		}
		defer conn.Close()
		setBridgeOut(conn)
		scanLines(conn, sess.handle)
		return 0
	}

	setBridgeOut(os.Stdout)
	scanLines(os.Stdin, sess.handle)
	return 0
}
