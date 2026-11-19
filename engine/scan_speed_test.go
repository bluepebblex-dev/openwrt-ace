package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/bluepebblex-dev/openwrt-ace/engine/internal/cache"
)

func mkRes(ep string, pingMS int) endpointResult {
	return endpointResult{
		endpoint: ep,
		epPing:   time.Duration(pingMS) * time.Millisecond,
		ok:       true,
		exit:     metaResult{colo: "LAX", coloISO: "US"},
	}
}

// orderFastFirst promotes only positively measured endpoints, sorted by
// throughput; unmeasured and zero-measured ones keep their ping order.
func TestOrderFastFirst(t *testing.T) {
	working := []endpointResult{
		mkRes("a:1", 10), // ping-best, measured slow
		mkRes("b:2", 20), // measured fastest
		mkRes("c:3", 30), // measured 0 (handshake ok, sample failed) → stays
		mkRes("d:4", 40), // unmeasured
	}
	speeds := map[string]float64{"a:1": 2.5, "b:2": 9.9, "c:3": 0}
	got, ok := orderFastFirst(working, speeds)
	if !ok {
		t.Fatal("expected a successful reorder")
	}
	want := []string{"b:2", "a:1", "c:3", "d:4"}
	for i, r := range got {
		if r.endpoint != want[i] {
			t.Fatalf("order[%d] = %s, want %s (full: %v)", i, r.endpoint, want[i], got)
		}
	}

	// Nothing positively measured → no reorder, caller keeps the ping order.
	if got, ok := orderFastFirst(working, map[string]float64{"a:1": 0}); ok {
		t.Fatalf("zero-only speeds must not reorder, got %v", got)
	}
	if _, ok := orderFastFirst(working, nil); ok {
		t.Fatal("empty speeds must not reorder")
	}
}

// projectOrderedEndpoints projects the caller's order verbatim — workingSorted
// must not sneak back in and re-sort by ping.
func TestProjectOrderedEndpointsKeepsOrder(t *testing.T) {
	ordered := []endpointResult{mkRes("fast:1", 50), mkRes("slow:2", 10)}
	got := projectOrderedEndpoints(ordered)
	if len(got) != 2 || got[0].Endpoint != "fast:1" || got[1].Endpoint != "slow:2" {
		t.Fatalf("order not preserved: %+v", got)
	}
}

// The refined order survives the cache roundtrip, including the measured
// speed, so a later fresh-cache connect reuses it without re-measuring.
func TestSpeedRefineSurvivesCacheRoundtrip(t *testing.T) {
	withCacheHome(t)
	r1 := mkRes("fast:1", 50)
	r1.speed = 12.3
	ordered := []endpointResult{r1, mkRes("slow:2", 10)}

	ces := projectOrderedEndpoints(ordered)
	cs := cachedScan{Proto: protoWG, IPv6: false, At: time.Now(), Results: ces}
	raw, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	store, err := cache.Open(cache.Options{TTL: scanTTL})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Put(scanCacheKey(protoWG, false), raw); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok := cachedScanFor(protoWG, false)
	if !ok {
		t.Fatal("cache miss")
	}
	if len(got.Results) != 2 || got.Results[0].Endpoint != "fast:1" {
		t.Fatalf("cache order not preserved: %+v", got.Results)
	}
	if got.Results[0].Speed != 12.3 {
		t.Fatalf("speed lost in roundtrip: %v", got.Results[0].Speed)
	}
	if !reflect.DeepEqual(got.Results[0].Working, true) {
		t.Fatalf("working flag lost: %+v", got.Results[0])
	}
}
