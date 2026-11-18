package main

import (
	"os"
	"testing"
)

// The exit picker is only useful if the installed core can actually carry an
// openvpn outbound. mihomo gained it as a native outbound (no external openvpn
// binary), but a user sitting on an older core would otherwise get a connect
// that fails at config load with nothing pointing at the cause.
//
// Skipped unless WARP_TEST_MIHOMO points at a mihomo executable.
func TestInstalledCoreSupportsOpenVPNOutbound(t *testing.T) {
	bin := os.Getenv("WARP_TEST_MIHOMO")
	if bin == "" {
		t.Skip("set WARP_TEST_MIHOMO=<path to mihomo>")
	}
	cDir := os.Getenv("WARP_TEST_CORE_DIR")
	if cDir == "" {
		t.Skip("set WARP_TEST_CORE_DIR=<dir with geo files>")
	}
	if !protoSupportedBy(bin, cDir, probeOpenVPNProto) {
		t.Fatalf("core %s does not accept an openvpn outbound config", bin)
	}
}
