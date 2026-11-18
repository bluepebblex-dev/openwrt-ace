package main

import "testing"

// The user's explicit requirement: on macOS the app must never touch the
// system proxy, the active network service, or the browser's proxy. Every path
// that can write/restore/clear/reassert the host proxy goes through this
// predicate, so pin the whole platform matrix here.
func TestProxyManagedOn(t *testing.T) {
	for _, tc := range []struct {
		goos string
		want bool
	}{
		{"darwin", false},
		{"windows", true},
		{"linux", true},
		{"android", true},
	} {
		if got := proxyManagedOn(tc.goos); got != tc.want {
			t.Errorf("proxyManagedOn(%q) = %v, want %v", tc.goos, got, tc.want)
		}
	}
}
