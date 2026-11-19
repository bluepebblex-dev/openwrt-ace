package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPutGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	s, err := Open(Options{Path: path, TTL: time.Hour})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	type record struct {
		Endpoint string `json:"endpoint"`
		Country  string `json:"country"`
	}
	r := record{Endpoint: "162.159.192.1:2408", Country: "DE"}
	raw, _ := json.Marshal(r)
	if err := s.Put("scan-awg-v4", raw); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, ok := s.Get("scan-awg-v4")
	if !ok {
		t.Fatal("get: miss after put")
	}
	var back record
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != r {
		t.Fatalf("round-trip mismatch: got %+v want %+v", back, r)
	}
}

func TestExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	s, _ := Open(Options{Path: path, TTL: 50 * time.Millisecond})
	_ = s.PutTTL("k", []byte("v"), 20*time.Millisecond)
	if _, ok := s.Get("k"); !ok {
		t.Fatal("expected fresh hit")
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok := s.Get("k"); ok {
		t.Fatal("expected expiry miss")
	}
}

func TestTwoStoreInstancesDoNotLoseEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	a, _ := Open(Options{Path: path, TTL: time.Hour})
	b, _ := Open(Options{Path: path, TTL: time.Hour})

	// Two engine processes each hold their own Store instance. A whole-map
	// write from b used to drop a's entry; mutate merges under the file lock.
	if err := a.Put("from-a", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := b.Put("from-b", []byte("2")); err != nil {
		t.Fatal(err)
	}

	c, err := Open(Options{Path: path, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"from-a", "from-b"} {
		if _, ok := c.Get(key); !ok {
			t.Fatalf("entry %q was lost across two store instances", key)
		}
	}
}

func TestSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	s, _ := Open(Options{Path: path, TTL: time.Hour})
	_ = s.Put("k", []byte("payload"))
	// Reopen from the same file: a fresh process should see the entry.
	s2, err := Open(Options{Path: path, TTL: time.Hour})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, ok := s2.Get("k"); !ok || string(got) != "payload" {
		t.Fatalf("reload lost entry: got=%q ok=%v", got, ok)
	}
	// Corrupt file must not break Open.
	_ = s2.Put("k2", []byte("v2"))
	_ = os.WriteFile(path, []byte("{not json"), 0o600)
	s3, err := Open(Options{Path: path, TTL: time.Hour})
	if err != nil {
		t.Fatalf("open corrupt: %v", err)
	}
	if _, ok := s3.Get("k2"); ok {
		t.Fatal("corrupt file should yield empty store")
	}
}

// TestDefaultPathHonoursPortableHome pins the portable contract: a client run
// with WARP_CLIENT_HOME keeps its cache beside its other files, not in the OS
// config dir. Mixing the two meant a test (and a portable install) read the
// machine-wide cache, and an elevated writer left root-only files there.
func TestDefaultPathHonoursPortableHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("WARP_CLIENT_HOME", home)
	got, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	want := filepath.Join(home, "cache.json")
	if got != want {
		t.Fatalf("DefaultPath = %q, want %q", got, want)
	}
}

// GetStale reads an entry past its fresh TTL as long as it is within maxAge,
// and refuses anything older — the contract the stale fast path relies on.
func TestStoreGetStale(t *testing.T) {
	home := t.TempDir()
	t.Setenv("WARP_CLIENT_HOME", home)
	store, err := Open(Options{TTL: time.Hour})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.PutTTL("k", []byte("v"), time.Hour); err != nil {
		t.Fatalf("put: %v", err)
	}
	// PutTTL normalizes non-positive TTLs to the default, so backdate the
	// entry on disk instead: past the fresh TTL, within maxAge.
	backdateCacheFile(t, home, "k", 90*time.Minute) // past the 1h TTL, within a 2h maxAge
	store2, err := Open(Options{TTL: time.Hour}) // re-read: stale entries only live on disk
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	store = store2
	if _, ok := store.Get("k"); ok {
		t.Fatal("expired entry must not read as fresh")
	}
	if _, ok := store.GetStale("k", 2*time.Hour); !ok {
		t.Fatal("expired-but-within-maxAge entry must read via GetStale")
	}
	if _, ok := store.GetStale("k", 30*time.Minute); ok {
		t.Fatal("entry older than maxAge must be refused")
	}
	if _, ok := store.GetStale("missing", time.Hour); ok {
		t.Fatal("missing key must be refused")
	}
}

// backdateCacheFile rewinds one entry's StoredAt/ExpiresAt by delta, the way
// real staleness appears (time passing after a normal Put).
func backdateCacheFile(t *testing.T, home, key string, delta time.Duration) {
	t.Helper()
	p := filepath.Join(home, "cache.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var entries map[string]Entry
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
