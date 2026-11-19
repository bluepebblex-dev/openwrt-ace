package main

import (
	"net"
	"testing"
	"time"
)

func TestFirstIPv4(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"2: br-lan    inet 192.168.50.1/24 scope global br-lan\\       valid_lft forever", "192.168.50.1"},
		{"inet 10.0.0.2/8 brd 10.255.255.255 scope global", "10.0.0.2"},
		{"inet 127.0.0.1/8 scope host lo", ""},
		{"", ""},
		{"inet6 fe80::1/64 scope link", ""},
	}
	for _, c := range cases {
		if got := firstIPv4(c.in); got != c.want {
			t.Errorf("firstIPv4(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLanIPv4LocalhostFallback(t *testing.T) {
	// 真机形态无法在 CI 断言（br-lan 不存在），只验证：函数总能返回或返回空，
	// 且非空时是合法 IPv4。
	ip := lanIPv4()
	if ip == "" {
		return
	}
	if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
		t.Fatalf("lanIPv4 返回非法地址 %q", ip)
	}
}

func TestRouterDeployedShape(t *testing.T) {
	// 不断言真假（CI 机器上不存在 init.d），只确保调用不会 panic 且耗时可控。
	start := time.Now()
	routerDeployed()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("routerDeployed 耗时异常: %v", d)
	}
}
