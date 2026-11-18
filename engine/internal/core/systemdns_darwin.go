//go:build darwin

package core

import (
	"errors"
	"os/exec"
	"strings"
)

// System DNS takeover for TUN mode.
//
// TUN routes traffic, not name resolution. The system resolver keeps asking the
// DHCP-provided LAN gateway (192.168.x.1, fe80::1), and that query travels out
// of the physical interface — the gateway address is directly reachable, so the
// TUN default route never sees it and dns-hijack cannot intercept it. The
// gateway then answers blocked domains with poisoned addresses (observed:
// youtube.com -> a Facebook IP, google.com -> a Twitter IP, then a single
// blackhole IP shared by every blocked name). The tunnel faithfully connects
// to those addresses and hangs: the classic "connected, but YouTube will not
// load" report.
//
// Pointing the resolver at mihomo closes the loop: mihomo resolves through the
// tunnel, so answers match the exit the traffic uses. This is the ONLY host
// setting TUN mode touches on macOS — the system/browser proxy stays untouched
// by design (see proxy_policy.go).

// SetSystemDNS points one network service's resolver at servers.
func SetSystemDNS(service string, servers []string) error {
	if service == "" || len(servers) == 0 {
		return errors.New("core: no DNS service/servers given")
	}
	args := append([]string{"-setdnsservers", service}, servers...)
	if out, err := exec.Command("/usr/sbin/networksetup", args...).CombinedOutput(); err != nil {
		return errors.New("networksetup setdns: " + strings.TrimSpace(string(out)))
	}
	FlushDNSCache()
	return nil
}

// RestoreSystemDNS drops the manual override so the service goes back to the
// resolvers DHCP hands out. "Empty" is networksetup's spelling of that.
func RestoreSystemDNS(service string) error {
	if service == "" {
		return errors.New("core: no DNS service given")
	}
	if out, err := exec.Command("/usr/sbin/networksetup", "-setdnsservers", service, "Empty").CombinedOutput(); err != nil {
		return errors.New("networksetup setdns Empty: " + strings.TrimSpace(string(out)))
	}
	FlushDNSCache()
	return nil
}

// SystemDNSServers returns the manual resolvers configured on a service. An
// empty slice means "uses DHCP", which is what restore has to aim back at.
func SystemDNSServers(service string) []string {
	if service == "" {
		return nil
	}
	out, err := exec.Command("/usr/sbin/networksetup", "-getdnsservers", service).Output()
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "aren't any DNS Servers") {
			continue
		}
		servers = append(servers, line)
	}
	return servers
}

// DNSPointsAtLocal reports whether a service already resolves via mihomo.
func DNSPointsAtLocal(service string) bool {
	for _, s := range SystemDNSServers(service) {
		if s == LocalDNSAddr {
			return true
		}
	}
	return false
}

// FlushDNSCache drops the system resolver cache. Without it the answers cached
// before the takeover keep being served — the resolver changed but the browser
// still gets the poisoned IP for minutes.
func FlushDNSCache() {
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}
