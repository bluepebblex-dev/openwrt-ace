package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bluepebblex-dev/openwrt-ace/engine/internal/cache"
)

// seedScanCache writes a cachedScan into the cache file, optionally already
// stale (StoredAt backdated past scanTTL but within or beyond staleMaxAge).
func seedScanCache(t *testing.T, home string, at time.Time, results []cachedEndpoint) {
	t.Helper()
	store, err := cache.Open(cache.Options{TTL: scanTTL})
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	cs := cachedScan{Proto: protoWG, IPv6: false, At: at, Results: results}
	raw, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	key := scanCacheKey(protoWG, false)
	if err := store.Put(key, raw); err != nil {
		t.Fatalf("put: %v", err)
	}
	// PutTTL normalizes non-positive TTLs, so staleness comes from backdating
	// the entry on disk — exactly how real staleness appears (time passing).
	if age := time.Since(at); age > 0 {
		backdateEngineCache(t, home, key, age)
	}
}

// backdateEngineCache rewinds one entry's StoredAt/ExpiresAt by delta.
func backdateEngineCache(t *testing.T, home, key string, delta time.Duration) {
	t.Helper()
	p := filepath.Join(home, "cache.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var entries map[string]cache.Entry
	if json.Unmarshal(raw, &entries) != nil {
		t.Fatalf("unmarshal cache: %v", err)
	}
	e, ok := entries[key]
	if !ok {
		t.Fatalf("key %q missing", key)
	}
	e.StoredAt = e.StoredAt.Add(-delta)
	e.ExpiresAt = e.ExpiresAt.Add(-delta)
	entries[key] = e
	out, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}
}

func withCacheHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("WARP_CLIENT_HOME", home)
	return home
}

func mkCE(ep string, working bool) cachedEndpoint {
	return cachedEndpoint{Endpoint: ep, IP: "1.2.3.4", Working: working}
}

// A scan stored within scanTTL reads back fresh; the same scan backdated past
// scanTTL but within staleMaxAge reads back only through staleScanFor.
func TestStaleScanForFreshVsExpired(t *testing.T) {
	home := withCacheHome(t)
	seedScanCache(t, home, time.Now(), []cachedEndpoint{mkCE("a:1", true)})

	if _, ok := staleScanFor(protoWG, false, staleMaxAge); !ok {
		t.Fatal("fresh scan must be readable through staleScanFor")
	}

	// Re-seed backdated 8h (past scanTTL, within staleMaxAge).
	home2 := withCacheHome(t)
	seedScanCache(t, home2, time.Now().Add(-8*time.Hour), []cachedEndpoint{mkCE("a:1", true)})
	if _, ok := cachedScanFor(protoWG, false); ok {
		t.Fatal("8h-old scan must not read as fresh")
	}
	if _, ok := staleScanFor(protoWG, false, staleMaxAge); !ok {
		t.Fatal("8h-old scan must read as stale")
	}

	// Beyond staleMaxAge it is garbage: neither path returns it.
	home3 := withCacheHome(t)
	seedScanCache(t, home3, time.Now().Add(-8*24*time.Hour), []cachedEndpoint{mkCE("a:1", true)})
	if _, ok := staleScanFor(protoWG, false, staleMaxAge); ok {
		t.Fatal("8-day-old scan must be rejected by staleScanFor")
	}
}

func TestStaleFastCandidatesFilterAndCap(t *testing.T) {
	results := []cachedEndpoint{
		mkCE("dead:1", false),
		mkCE("a:1", true),
		mkCE("b:2", true),
		{Endpoint: "", Working: true}, // empty endpoint is unusable
		mkCE("c:3", true),
	}
	got := staleFastCandidates(results, 2)
	if len(got) != 2 || got[0].Endpoint != "a:1" || got[1].Endpoint != "b:2" {
		t.Fatalf("want [a:1 b:2] (order kept, capped), got %+v", got)
	}
	if all := staleFastCandidates(results, 0); len(all) != 3 {
		t.Fatalf("limit<=0 must not cap, got %d", len(all))
	}
	if n := len(staleFastCandidates(nil, 5)); n != 0 {
		t.Fatalf("nil results must give no candidates, got %d", n)
	}
}

// refreshStaleCache leads with the verified endpoint, marks this connect's
// failures dead, keeps everything else in order — and the entry reads back
// fresh afterwards, so the next cold start is a cache hit again.
func TestRefreshStaleCacheShape(t *testing.T) {
	withCacheHome(t)
	results := []cachedEndpoint{
		mkCE("old-best:1", true),
		mkCE("broken:2", true),  // will fail this connect
		mkCE("mid:3", true),
		mkCE("alsodead:4", true),
	}
	verified := mkCE("mid:3", true)
	failed := map[string]bool{"broken:2": true, "alsodead:4": true}

	refreshStaleCache(options{proto: protoWG}, results, verified, failed)

	cs, ok := cachedScanFor(protoWG, false)
	if !ok {
		t.Fatal("re-freshened cache must read as fresh")
	}
	if len(cs.Results) != 4 {
		t.Fatalf("all endpoints kept (order + dead marks), got %d", len(cs.Results))
	}
	if cs.Results[0].Endpoint != "mid:3" {
		t.Fatalf("verified endpoint must lead, got %s", cs.Results[0].Endpoint)
	}
	want := []struct {
		ep      string
		working bool
	}{
		{"mid:3", true},      // verified leads
		{"old-best:1", true}, // untouched keep cached order
		{"broken:2", false},  // failed this connect → dead
		{"alsodead:4", false},
	}
	for i, w := range want {
		if cs.Results[i].Endpoint != w.ep || cs.Results[i].Working != w.working {
			t.Fatalf("result[%d] = %s working=%v, want %s working=%v",
				i, cs.Results[i].Endpoint, cs.Results[i].Working, w.ep, w.working)
		}
	}
}

// A fast path that fails entirely must leave the cache exactly as it was:
// the rescan-retry path and any concurrent scan rely on P1 not writing on
// failure.
func TestRefreshStaleCacheNotCalledOnFailureIsPreservedBySeed(t *testing.T) {
	home := withCacheHome(t)
	seedScanCache(t, home, time.Now().Add(-8*time.Hour), []cachedEndpoint{mkCE("a:1", true)})
	before, err := os.ReadFile(filepath.Join(home, "cache.json"))
	if err != nil {
		t.Fatalf("seed file: %v", err)
	}
	// Simulate the failure path: nothing wrote; the seed file is unchanged and
	// the store still refuses the entry as fresh (so the next connect either
	// fast-paths again or rescans — same choices as without P1).
	after, err := os.ReadFile(filepath.Join(home, "cache.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("cache file must be untouched when no refresh runs")
	}
	if _, ok := cachedScanFor(protoWG, false); ok {
		t.Fatal("stale seed must still read as not-fresh")
	}
}
