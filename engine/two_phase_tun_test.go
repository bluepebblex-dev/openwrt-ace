package main

import (
	"strings"
	"testing"
)

// TestProbeRenderHasNoTunInbound pins the safety property the two-phase
// connect depends on: the probe configuration must not create a TUN device,
// insert routes or hijack DNS. That is what makes a failing candidate free for
// the LAN — before the split, the TUN came up with the core and a -hold retry
// loop kept the whole house behind a tunnel that was still being tested
// (2026-11-18 outage).
//
// The full render is asserted too, so this test fails if the real session ever
// silently loses its TUN inbound: the split must not turn into "TUN never
// enabled".
func TestProbeRenderHasNoTunInbound(t *testing.T) {
	base := options{
		mixedPort: 7890,
		apiPort:   9090,
		mtu:       1280,
		dns:       "223.5.5.5, 1.1.1.1",
		tunMode:   true,
		dnsLeak:   true,
	}
	ce := cachedEndpoint{Endpoint: "162.159.192.1:2408"}
	run := protoRun{kind: kindWG, name: protoWG}

	full, err := renderClientConfig(base, ce, run)
	if err != nil {
		t.Fatalf("full render: %v", err)
	}
	fullYAML := string(full)
	for _, want := range []string{"tun:\n", "enable: true", "auto-route: true"} {
		if !strings.Contains(fullYAML, want) {
			t.Fatalf("TUN render lost %q:\n%s", want, fullYAML)
		}
	}

	probe := base
	probe.tunMode = false
	probeYAMLbytes, err := renderClientConfig(probe, ce, run)
	if err != nil {
		t.Fatalf("probe render: %v", err)
	}
	probeYAML := string(probeYAMLbytes)

	// Anything that would move the LAN's traffic belongs to the adoption phase.
	for _, forbidden := range []string{"tun:", "auto-route", "auto-detect-interface", "dns-hijack", "device: ace0"} {
		if strings.Contains(probeYAML, forbidden) {
			t.Errorf("probe config must not contain %q:\n%s", forbidden, probeYAML)
		}
	}
	// The probe still has to be able to carry traffic: the mixed port is the
	// only way its verification can succeed.
	if !strings.Contains(probeYAML, "mixed-port: 7890") {
		t.Errorf("probe config lost the mixed port:\n%s", probeYAML)
	}
	if !strings.Contains(probeYAML, "127.0.0.1:9090") {
		t.Errorf("probe config lost the controller port:\n%s", probeYAML)
	}
	// The resolver listener is TUN-only; binding it during the probe would put
	// a live listener on 7874 that the init script must then be careful about.
	if strings.Contains(probeYAML, "listen: ") {
		t.Errorf("probe config must not open the TUN resolver listener:\n%s", probeYAML)
	}
}
