package main

import (
	"encoding/json"
	"testing"
)

// A data directory upgraded from an older build still holds a cache written
// with cc/host/pingMS/speedBps. If those names do not map onto the current
// struct, every node loads with a blank country and zero latency: the pool
// looks empty in the OpenVPN exit picker even though the file is full.
func TestVPNGateNodeReadsLegacyCacheFields(t *testing.T) {
	legacy := `{"id":"jp-119.175.43.134-1258","host":"vpn267521680","ip":"119.175.43.134",
		"port":1258,"proto":"tcp","cc":"JP","country":"Japan","operator":"oni0281's owner",
		"pingMS":32,"speedBps":188896497,"sessions":16,"latencyMS":185,"class":"residential"}`
	var n vpnGateNode
	if err := json.Unmarshal([]byte(legacy), &n); err != nil {
		t.Fatalf("unmarshal legacy node: %v", err)
	}
	if n.CountryShort != "JP" {
		t.Errorf("CountryShort = %q, want JP", n.CountryShort)
	}
	if n.CountryLong != "Japan" {
		t.Errorf("CountryLong = %q, want Japan", n.CountryLong)
	}
	if n.HostName != "vpn267521680" {
		t.Errorf("HostName = %q", n.HostName)
	}
	if n.PingMS != 32 {
		t.Errorf("PingMS = %d, want 32", n.PingMS)
	}
	if n.Speed != 188896497 {
		t.Errorf("Speed = %d", n.Speed)
	}
	if n.IP != "119.175.43.134" || n.Port != 1258 || n.Proto != "tcp" {
		t.Errorf("core fields lost: %+v", n)
	}
}

// The current spelling must keep working unchanged — the alias pass must not
// overwrite values that are already present.
func TestVPNGateNodeReadsCurrentCacheFields(t *testing.T) {
	cur := `{"host_name":"vpn1","ip":"203.0.113.9","port":443,"proto":"udp",
		"country_long":"Korea","country_short":"KR","score":1000,"speed":5000000,
		"ping_ms":41,"sessions":3}`
	var n vpnGateNode
	if err := json.Unmarshal([]byte(cur), &n); err != nil {
		t.Fatalf("unmarshal current node: %v", err)
	}
	if n.CountryShort != "KR" || n.CountryLong != "Korea" || n.HostName != "vpn1" {
		t.Errorf("current fields mis-read: %+v", n)
	}
	if n.PingMS != 41 || n.Speed != 5000000 || n.Score != 1000 {
		t.Errorf("numeric fields mis-read: %+v", n)
	}
}

// A whole legacy cache file must load, and its countries must be derivable —
// that is exactly what the settings UI calls vpn_nodes for.
func TestVPNGateCacheFileLoadsLegacyNodes(t *testing.T) {
	raw := `{"at":"2026-11-14T23:50:00Z","nodes":[
		{"host":"vpn1","ip":"119.175.43.134","port":1258,"proto":"tcp","cc":"JP","country":"Japan","pingMS":32},
		{"host":"vpn2","ip":"45.152.19.83","port":992,"proto":"tcp","cc":"FR","country":"France","pingMS":60}
	]}`
	var f vpnGateCacheFile
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("unmarshal cache file: %v", err)
	}
	if len(f.Nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(f.Nodes))
	}
	countries := vpnGateCountries(f.Nodes)
	if len(countries) != 2 {
		t.Fatalf("want 2 countries, got %d (%+v)", len(countries), countries)
	}
	got := map[string]bool{}
	for _, c := range countries {
		got[c.CC] = true
	}
	if !got["JP"] || !got["FR"] {
		t.Errorf("missing countries: %+v", countries)
	}
}

// The cache has carried three timestamp shapes. Any of them must yield a real
// age: an unreadable timestamp makes a fresh cache look permanently stale and
// triggers a full VPN Gate refetch on every launch.
func TestParseCacheTimeForms(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int64 // unix seconds, 0 = zero time
	}{
		{"rfc3339", `"2026-11-14T23:50:00+08:00"`, 1794671400},
		{"unix seconds", `1794671428`, 1794671428},
		{"unix millis", `1794671428048`, 1794671428},
		{"null", `null`, 0},
		{"empty string", `""`, 0},
		{"garbage", `"not-a-time"`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCacheTime(json.RawMessage(tc.raw))
			if tc.want == 0 {
				if !got.IsZero() {
					t.Fatalf("want zero time, got %v", got)
				}
				return
			}
			if got.Unix() != tc.want {
				t.Fatalf("got %v (unix %d), want unix %d", got, got.Unix(), tc.want)
			}
		})
	}
}

// End to end: the pre-rename file shape (fetchedAt millis) must load through
// the normal cache path, age included.
func TestVPNGateCacheFileReadsLegacyTimestamp(t *testing.T) {
	raw := `{"fetchedAt":1794671428048,"nodes":[{"host":"vpn1","ip":"119.175.43.134","port":1258,"proto":"tcp","cc":"JP","country":"Japan"}]}`
	var f vpnGateCacheFile
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.At.IsZero() {
		t.Fatal("legacy fetchedAt was not parsed")
	}
	if len(f.Nodes) != 1 || f.Nodes[0].CountryShort != "JP" {
		t.Fatalf("nodes not loaded: %+v", f.Nodes)
	}
}
