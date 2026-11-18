//go:build !windows

package core

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProxySnapshot captures the pre-session proxy state of every active macOS
// network service so disconnect can restore it exactly. networksetup exposes
// web (HTTP), secure web (HTTPS), SOCKS proxies plus their bypass lists and
// enabled flags; we snapshot the ones we touch.
type ProxySnapshot struct {
	Services map[string]serviceProxy `json:"services"`
}

type serviceProxy struct {
	WebEnable     bool   `json:"web_enable"`
	WebServer     string `json:"web_server"`
	WebPort       string `json:"web_port"`
	SecureEnable  bool   `json:"secure_enable"`
	SecureServer  string `json:"secure_server"`
	SecurePort    string `json:"secure_port"`
	SocksEnable   bool   `json:"socks_enable"`
	SocksServer   string `json:"socks_server"`
	SocksPort     string `json:"socks_port"`
	BypassDomains string `json:"bypass_domains,omitempty"`
}

var proxyMu sync.Mutex

// networkServices returns the list of network services macOS exposes
// (Wi-Fi, Ethernet, Thunderbolt ...), excluding the header line and services
// marked inactive with a trailing asterisk.
func networkServices() ([]string, error) {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var svcs []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		name := strings.TrimSuffix(line, " *")
		name = strings.TrimSpace(name)
		if name != "" {
			svcs = append(svcs, name)
		}
	}
	return svcs, nil
}

// ns runs a networksetup subcommand against a service.
func ns(args ...string) (string, error) {
	cmd := exec.Command("/usr/sbin/networksetup", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("networksetup %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// proxyStateOf reads one service's current proxy settings.
func proxyStateOf(svc string) serviceProxy {
	p := serviceProxy{}
	if out, err := ns("-getwebproxy", svc); err == nil {
		p.WebEnable, p.WebServer, p.WebPort = parseProxy(out)
	}
	if out, err := ns("-getsecurewebproxy", svc); err == nil {
		p.SecureEnable, p.SecureServer, p.SecurePort = parseProxy(out)
	}
	if out, err := ns("-getsocksfirewallproxy", svc); err == nil {
		p.SocksEnable, p.SocksServer, p.SocksPort = parseProxy(out)
	}
	if out, err := ns("-getproxybypassdomains", svc); err == nil {
		p.BypassDomains = strings.TrimSpace(out)
	}
	return p
}

// parseProxy parses `Enabled: Yes/No`, `Server: ...`, `Port: ...` blocks.
func parseProxy(out string) (bool, string, string) {
	var enabled bool
	var server, port string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(strings.ToLower(line), "enabled:"):
			v := strings.TrimSpace(line[len("Enabled:"):])
			enabled = strings.EqualFold(v, "yes") || v == "1" || strings.EqualFold(v, "true")
		case strings.HasPrefix(strings.ToLower(line), "server:"):
			server = strings.TrimSpace(line[len("Server:"):])
		case strings.HasPrefix(strings.ToLower(line), "port:"):
			port = strings.TrimSpace(line[len("Port:"):])
		}
	}
	return enabled, server, port
}

// activeNetworkService names the service macOS is actually routing through
// (Wi-Fi, Ethernet, ...). Everything else in the list is decoration: pointing a
// proxy at a service no traffic uses looks like success and leaves the browser
// with no proxy at all, because the enabled flag only matters on the primary
// service.
func activeNetworkService() string {
	out, err := exec.Command("/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	dev := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			dev = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			break
		}
	}
	if dev == "" {
		return ""
	}
	order, err := exec.Command("/usr/sbin/networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return ""
	}
	svc := ""
	for _, line := range strings.Split(string(order), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "(") && strings.Contains(line, ") ") {
			if i := strings.Index(line, ") "); i >= 0 {
				svc = strings.TrimSpace(line[i+2:])
			}
			continue
		}
		if strings.Contains(line, "Device: "+dev+")") || strings.Contains(line, "Device: "+dev+",") {
			return svc
		}
	}
	return ""
}

// applyProxyToService points one service's HTTP/HTTPS/SOCKS proxies at
// host:port and switches them on.
func applyProxyToService(svc, host, port string) error {
	var firstErr error
	for _, pair := range [][2]string{
		{"-setwebproxy", "-setwebproxystate"},
		{"-setsecurewebproxy", "-setsecurewebproxystate"},
		{"-setsocksfirewallproxy", "-setsocksfirewallproxystate"},
	} {
		if _, e := ns(pair[0], svc, host, port); e != nil && firstErr == nil {
			firstErr = e
		}
		if _, e := ns(pair[1], svc, "on"); e != nil && firstErr == nil {
			firstErr = e
		}
	}
	return firstErr
}

// proxyPointsAt reports whether svc currently sends web traffic through
// host:port.
func proxyPointsAt(svc, host, port string) bool {
	for _, get := range []string{"-getwebproxy", "-getsecurewebproxy"} {
		out, err := ns(get, svc)
		if err != nil {
			continue
		}
		enabled, server, sport := parseProxy(out)
		if enabled && server == host && sport == port {
			return true
		}
	}
	return false
}

// SetSystemProxy points every active service's HTTP/HTTPS/SOCKS proxies at the
// local mixed port and returns a snapshot for exact restoration on disconnect.
func SetSystemProxy(port int) (*ProxySnapshot, error) {
	proxyMu.Lock()
	defer proxyMu.Unlock()

	svcs, err := networkServices()
	if err != nil {
		return nil, err
	}
	snap := &ProxySnapshot{Services: make(map[string]serviceProxy, len(svcs))}
	host := "127.0.0.1"
	p := strconv.Itoa(port)
	for _, svc := range svcs {
		snap.Services[svc] = proxyStateOf(svc)
		// Errors on a dormant service (a disabled dock, a bridge with no link)
		// are not the user's problem: only the live one decides whether the
		// host is proxied at all.
		_ = applyProxyToService(svc, host, p)
	}
	// The primary service is the only one browsers obey. Re-assert it after the
	// sweep: networksetup silently drops a state flip on a service that is not
	// yet primary, and a session that "set the proxy" without touching Wi-Fi
	// leaves the user online-but-blocked.
	svc := activeNetworkService()
	if svc == "" {
		// Without routing information there is nothing to verify against; keep
		// the old behaviour and let the caller warn only on a hard failure.
		return snap, nil
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if proxyPointsAt(svc, host, p) {
			return snap, nil
		}
		lastErr = applyProxyToService(svc, host, p)
		// networksetup applies asynchronously; give it a beat before the
		// read-back that decides whether to retry.
		time.Sleep(250 * time.Millisecond)
	}
	if proxyPointsAt(svc, host, p) {
		return snap, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("系统代理未在 %s 上生效", svc)
	}
	return snap, lastErr
}

// ActiveServiceName names the network service macOS routes through, for log
// lines the user can act on ("系统代理已生效（Wi-Fi）").
func ActiveServiceName() string {
	if svc := activeNetworkService(); svc != "" {
		return svc
	}
	return "未知网络服务"
}

// SystemProxyActiveAt reports whether the interface macOS routes through is
// pointing at our mixed port. It is the check that matters after a set: the
// other services can carry our address while the live one lost it.
func SystemProxyActiveAt(port int) bool {
	svc := activeNetworkService()
	if svc == "" {
		return SystemProxyEnabledAt(port)
	}
	return proxyPointsAt(svc, "127.0.0.1", strconv.Itoa(port))
}

// ReassertSystemProxy re-points the active service at port without touching the
// snapshot. Used when something (another VPN client, a network change, the
// user's own proxy toggle) cleared it mid-session.
func ReassertSystemProxy(port int) error {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	svc := activeNetworkService()
	if svc == "" {
		return errors.New("找不到当前活动网络服务")
	}
	p := strconv.Itoa(port)
	if proxyPointsAt(svc, "127.0.0.1", p) {
		return nil
	}
	if err := applyProxyToService(svc, "127.0.0.1", p); err != nil {
		return err
	}
	if !proxyPointsAt(svc, "127.0.0.1", p) {
		return errors.New("系统代理未能生效（" + svc + "）")
	}
	return nil
}

// UnsetSystemProxy restores the exact pre-session proxy state from snap.
// An empty/nil snapshot means "turn our proxies off".
func UnsetSystemProxy(snap *ProxySnapshot) error {
	proxyMu.Lock()
	defer proxyMu.Unlock()

	svcs, err := networkServices()
	if err != nil {
		return err
	}
	if snap == nil || len(snap.Services) == 0 {
		var firstErr error
		for _, svc := range svcs {
			for _, state := range []string{"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"} {
				if _, e := ns(state, svc, "off"); e != nil && firstErr == nil {
					firstErr = e
				}
			}
		}
		return firstErr
	}

	var firstErr error
	for _, svc := range svcs {
		sp, ok := snap.Services[svc]
		if !ok {
			continue
		}
		restore := func(server, port string, enable bool, setCmd, stateCmd string) {
			if server != "" && port != "" {
				if _, e := ns(setCmd, svc, server, port); e != nil && firstErr == nil {
					firstErr = e
				}
			}
			state := "off"
			if enable {
				state = "on"
			}
			if _, e := ns(stateCmd, svc, state); e != nil && firstErr == nil {
				firstErr = e
			}
		}
		restore(sp.WebServer, sp.WebPort, sp.WebEnable, "-setwebproxy", "-setwebproxystate")
		restore(sp.SecureServer, sp.SecurePort, sp.SecureEnable, "-setsecurewebproxy", "-setsecurewebproxystate")
		restore(sp.SocksServer, sp.SocksPort, sp.SocksEnable, "-setsocksfirewallproxy", "-setsocksfirewallproxystate")
	}
	return firstErr
}

// SystemProxyEnabledAt reports whether any service's proxy still points at our
// mixed port (used to clean up a leftover proxy after a crash).
func SystemProxyEnabledAt(port int) bool {
	svcs, err := networkServices()
	if err != nil {
		return false
	}
	p := strconv.Itoa(port)
	for _, svc := range svcs {
		for _, get := range []string{"-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy"} {
			out, err := ns(get, svc)
			if err != nil {
				continue
			}
			enabled, server, sport := parseProxy(out)
			if enabled && server == "127.0.0.1" && sport == p {
				return true
			}
		}
	}
	return false
}

// ClearSystemProxy switches off all proxies on all services.
func ClearSystemProxy() error {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	svcs, err := networkServices()
	if err != nil {
		return err
	}
	var firstErr error
	for _, svc := range svcs {
		for _, state := range []string{"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"} {
			if _, e := ns(state, svc, "off"); e != nil && firstErr == nil {
				firstErr = e
			}
		}
	}
	return firstErr
}

// DetectProxyBlocker reports a human-readable reason if the proxy cannot be
// set. Returns empty when the path looks clear.
func DetectProxyBlocker() string {
	if _, err := exec.LookPath("/usr/sbin/networksetup"); err != nil {
		return "networksetup 不可用"
	}
	return ""
}

// IsElevated reports whether the process runs as root — required for TUN
// (utun device creation + route changes) on macOS.
func IsElevated() bool {
	return os.Geteuid() == 0
}

// macOS needs no separate UAC helper: TUN sessions are launched through an
// elevated `osascript ... with administrator privileges` wrapper from the GUI.
func SetSystemProxyElevated(port int) error {
	return errors.New("macOS: proxy edits run in-process; TUN needs an elevated launch")
}
func RestoreSystemProxyElevated(*ProxySnapshot) error { return nil }
func RunProxyHelper([]string) int                     { return 2 }
