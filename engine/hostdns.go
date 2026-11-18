package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/bluepebblex-dev/openwrt-ace/engine/internal/core"
)

// Resolver takeover lifecycle.
//
// TUN mode points the host resolver at the core (internal/core/systemdns).
// That is the one host setting which, if left behind, breaks the machine
// outright: with the core gone, 127.0.0.1:53 accepts nothing and every name
// lookup fails while the network "looks" connected. These two helpers cover
// the two ways a session can end without a clean disconnect:
//
//   - bridgeExitCleanup — the process that owns the rights is exiting
//     (GUI quit, GUI crash, socket EOF, cable pulled).
//   - healStaleHostDNS — a previous crash already left it behind; repair it
//     before doing anything else.
//
// Both are gated on being elevated: a non-root engine cannot run networksetup,
// and must not pretend it did.

// bridgeExitCleanup restores the host resolver when the bridge session ends
// with a dead core behind it. A session whose core is still alive is left
// alone — the tunnel still serves, and the resolver is still correct.
func bridgeExitCleanup() {
	if runtime.GOOS != "darwin" || !core.IsElevated() {
		return
	}
	st, err := loadState()
	if err != nil {
		return
	}
	if st.Connected && st.CorePID > 0 && processAlive(st.CorePID) {
		return // the session is still serving; nothing to undo
	}
	// The resolver only needs restoring when this session took it over, but
	// the recorded session must be cleared either way: leaving connected:true
	// behind makes the UI offer to disconnect a connection that is gone.
	if st.DNSService != "" {
		restoreHostDNS(st)
	}
	if st.Connected || st.DNSService != "" || st.CorePID != 0 {
		_ = mutateState(func(cur *clientState) error {
			cur.Connected = false
			cur.CorePID = 0
			cur.DNSService = ""
			cur.DNSSnap = nil
			return nil
		})
	}
}

// healStaleHostDNS repairs a takeover left by a crash. Without it the machine
// has no working resolver until someone opens System Settings and clears the
// DNS field by hand — which is why this runs before any connect, on the very
// first elevated process that starts.
func healStaleHostDNS() {
	if runtime.GOOS != "darwin" || !core.IsElevated() {
		return
	}
	st, err := loadState()
	if err == nil && st.Connected && st.CorePID > 0 && processAlive(st.CorePID) {
		return // a live session owns the resolver
	}
	svc := core.ActiveServiceName()
	if svc == "" || svc == "未知网络服务" || !core.DNSPointsAtLocal(svc) {
		return
	}
	var snap []string
	if err == nil && st.DNSService == svc {
		snap = st.DNSSnap
	}
	var rerr error
	if len(snap) > 0 {
		rerr = core.SetSystemDNS(svc, snap)
	} else {
		rerr = core.RestoreSystemDNS(svc)
	}
	if rerr != nil {
		fmt.Fprintln(os.Stderr, "heal stale DNS: "+rerr.Error())
		return
	}
	fmt.Fprintln(os.Stderr, "已修复上次异常退出遗留的系统 DNS（"+svc+" 恢复为自动获取）")
	_ = mutateState(func(cur *clientState) error {
		cur.DNSService = ""
		cur.DNSSnap = nil
		return nil
	})
}

// withoutLocalDNS drops our own resolver from a snapshot. On a reconnect the
// service already points at the core, so reading it back would record
// 127.0.0.1 as the "original" value; restoring that after disconnect points
// the machine at a listener that died with the core and takes DNS down with it.
// Filtering to empty makes the restore fall back to DHCP, which is what the
// service was on before we ever touched it.
func withoutLocalDNS(servers []string) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		if s == core.LocalDNSAddr {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
