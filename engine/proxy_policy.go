package main

import "runtime"

// proxyManagedOn reports whether a build on goos may edit the host's proxy
// settings at all. macOS is TUN-only by product decision: utun captures every
// packet at layer 3, so the system/browser proxy is never part of the tunnel —
// and editing it would clobber the user's own proxy settings, killing domestic
// access until they found and undid the change by hand.
//
// The guard is deliberately in one place and checked on every write, restore,
// clear and reassert path: "we never set it" is not enough when a crash, an old
// state file or a stale watchdog could still take it away.
func proxyManagedOn(goos string) bool {
	return goos != "darwin"
}

func hostProxyManaged() bool { return proxyManagedOn(runtime.GOOS) }
