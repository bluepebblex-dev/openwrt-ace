package main

import (
	"context"
	"os"
	"testing"
)

// Sanity check against the cache actually sitting in this machine's data
// directory: it was written by an older build, so it is the exact upgrade case
// the aliases above exist for. Skipped when no cache is present.
func TestLoadRealVPNGateCacheIfPresent(t *testing.T) {
	nodes, at := loadVPNGateCache()
	if len(nodes) == 0 {
		t.Skip("no VPN Gate cache in this data directory")
	}
	withCC := 0
	for _, n := range nodes {
		if n.CountryShort != "" && n.IP != "" {
			withCC++
		}
	}
	t.Logf("cache: %d nodes, %d with country, at=%s", len(nodes), withCC, at.Format("2006-01-02 15:04"))
	if withCC == 0 {
		t.Fatalf("every node lost its country (%d nodes): legacy fields not mapped", len(nodes))
	}
	cs := vpnGateCountries(nodes)
	t.Logf("countries: %d", len(cs))
	for i, c := range cs {
		if i >= 5 {
			break
		}
		t.Logf("  %s %s count=%d minLat=%d", c.CC, c.Name, c.Count, c.MinLatency)
	}
	if len(cs) == 0 {
		t.Fatal("no country derived from the cache")
	}
	withProfile := 0
	for _, n := range nodes {
		if n.Profile != "" {
			withProfile++
		}
	}
	t.Logf("profiles: %d/%d nodes carry an .ovpn body", withProfile, len(nodes))
	if withProfile == 0 {
		t.Fatal("migrated nodes have no OpenVPN profile: every relay would be filtered out as unusable")
	}
	// The exit picker filters on profile, so the JP pool the user sees must be
	// non-empty after migration.
	jp := vpnGateCandidates(context.Background(), nodes, "JP", "", 10)
	t.Logf("JP candidates: %d", len(jp))
	if len(jp) == 0 {
		t.Fatal("no JP candidates after migration")
	}
	_ = os.Getenv("WARP_CLIENT_HOME")
}
