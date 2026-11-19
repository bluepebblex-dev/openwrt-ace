package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// LAN 数据面保底 —— 2026-11-19 第三次断网事故的直接产物。
//
// 事故链：connect 首次运行要先下载 12 MB geo 数据，TUN 设备出现得比 init.d
// post_up 的 180 秒窗口晚了几十秒；post_up 放弃后防火墙 zone 永远不会再加，
// 而 TUN 的 auto-route 已经把整屋默认路由吸进 ace0 —— fw4 没有 ace zone 的
// 放行规则，LAN→TUN 的 FORWARD 全部被丢弃。路由器自己的流量走 OUTPUT 链
// 不经过 FORWARD，本机探测全绿；guard 探 localhost 代理端口也全绿。于是
// 「明明连上了，访问不了」可以无限期挂着，直到有人手点停止。
//
// 这里的探测模拟的是局域网客户端视角：源地址绑定 LAN IP 发真实请求。
// 路由器本机发起的流量仍走 OUTPUT 而非 FORWARD，防火墙层测不到 —— 所以
// 接管层（fw zone + dnsmasq 上游）的落地由 init.d 的就绪标记
// /var/run/ace-ready 负责（post_up 加完 zone 后 touch，引擎 adoptTun 等它），
// 本文件负责持续验证 TUN 数据面与全屋 DNS 链路活着，死了就自动下线还原。

// probeURL 是探测端点：204 无内容，响应极小，且域名按分流规则出国 ——
// 在 bypass 模式下走 WARP，正好验证「出国流量走代理」这条路本身。
const probeURL = "https://www.gstatic.com/generate_204"

// lanIPv4 returns the router's LAN address (br-lan 192.168.50.1 on the
// reference hardware), or "" when nothing private can be found. The router
// case asks `ip` directly: a plain interface scan would just as happily return
// the WAN address (also RFC1918 behind a double NAT), which makes every
// downstream probe test the wrong interface.
func lanIPv4() string {
	if out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", "br-lan").Output(); err == nil {
		if ip := firstIPv4(string(out)); ip != "" {
			return ip
		}
	}
	// Off the reference router (macOS/Windows GUI): first private v4 on any
	// non-loopback interface. GUI TUN sessions probe through the tunnel just
	// the same; a wrong interface here costs accuracy, not safety.
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			if ipn.IP.IsPrivate() {
				return ipn.IP.String()
			}
		}
	}
	return ""
}

func firstIPv4(s string) string {
	for _, f := range strings.Fields(s) {
		if i := strings.LastIndex(f, "/"); i >= 0 {
			f = f[:i]
		}
		if ip := net.ParseIP(f); ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.String()
		}
	}
	return ""
}

// lanPlaneProbe does one real request through whatever route the kernel picks
// for unbound local traffic. When the TUN session owns the default route,
// mihomo's auto-route rule `from 0.0.0.0 iif lo lookup 2022` captures exactly
// this kind of packet, so the probe rides the tunnel end to end: TUN plane,
// split rules, WARP exit and the DNS chain all surface here.
//
// 曾经的错误设计（2026-11-19 v1.10.1 真机事故）：把源地址绑定到 LAN IP 想模拟
// 局域网客户端。绑定源的包不匹配任何 auto-route 规则，直接走主表从 WAN 明文
// 出去访问被墙的 gstatic —— 必然超时，保底把每个好端点都误杀回滚，connect
// 无限循环。绑定 ≠ 模拟客户端：客户端流量走 FORWARD 进 TUN，本机怎么绑都
// 不走 FORWARD，模拟不出来。防火墙转发层的落地由 init.d 就绪标记保证
// （waitRouterReadyFlag），DNS 链路由 dnsPlaneProbe 单独盯。
func lanPlaneProbe(ctx context.Context, timeout time.Duration) error {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("探测端点 %d", resp.StatusCode)
	}
	return nil
}

// dnsPlaneProbe asks the LAN resolver (dnsmasq, whose upstream is our core in
// dns-leak mode) for a name that must come back through the tunnel. The domain
// choice is load-bearing:
//
// www.gstatic.com is GEOSITE geolocation-!cn, so in bypass mode its answer is
// produced by the core resolver's tunneled upstream — exactly the chain this
// watchdog exists to guard. A domestic name would test the ISP's *direct*
// upstream instead, the one link ace does not own: the first v1.11.0 router
// run (2026-11-19 21:12) killed perfectly good sessions because
// lookup www.baidu.com came back NXDOMAIN from an evening-hour ISP hiccup.
// A dead tunnel fails this lookup too, so the watchdog still sees what it
// must; a flaky WAN link no longer murders healthy sessions.
const dnsProbeName = "www.gstatic.com"

func dnsPlaneProbe(ctx context.Context, timeout time.Duration) error {
	lan := lanIPv4()
	if lan == "" {
		return nil
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", net.JoinHostPort(lan, "53"))
		},
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err := r.LookupHost(wctx, dnsProbeName)
	return err
}

// routerDeployed reports whether the OpenWrt service script exists, i.e. this
// binary is running on the router where init.d owns the takeover layers.
func routerDeployed() bool {
	_, err := exec.LookPath("/etc/init.d/ace")
	return err == nil
}

// serviceManaged reports whether this connect was started by the OpenWrt
// init script (which injects ACE_LAN_BYPASS=1). Only a service-managed
// session has the post_up hook that touches the ready flag, so only such a
// session should wait for it.
func serviceManaged() bool {
	return os.Getenv("ACE_LAN_BYPASS") == "1"
}

// routerReadyFlagPath is touched by init.d post_up once DNS takeover and the
// firewall zone are in place for this session.
const routerReadyFlagPath = "/var/run/ace-ready"

// waitRouterReadyFlag blocks until the service script signals the takeover
// layers are live, or the timeout expires. connect-time adoption must not
// declare success before the firewall zone exists: auto-route has already
// captured the default route by then, and every forwarded LAN packet is
// dropped by fw4 until the zone lands.
func waitRouterReadyFlag(ctx context.Context, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(routerReadyFlagPath); err == nil {
			return true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		sleepCtx(ctx, time.Second)
	}
}

// stopRouterService hands the teardown to init.d, which restores dnsmasq,
// removes the firewall zone and sweeps routes unconditionally. This is the
// fallback the user asked for: whatever breaks, ace must take ITSELF offline
// so the LAN comes back and the admin page stays reachable.
func stopRouterService(logf func(string)) {
	if !routerDeployed() {
		return
	}
	logf("LAN 数据面持续不通，触发 init.d stop 自动还原（保底生效）")
	go func() {
		// Stop kills this guard process too; give the reply a beat to drain.
		time.Sleep(500 * time.Millisecond)
		_ = exec.Command("/etc/init.d/ace", "stop").Run()
	}()
}
