package main

import (
	"context"
	"testing"
)

// The user's requirement: start from the node they picked, and only if that
// fails move on to the rest of the pool in latency order. This pins the first
// half (ordering); the connect loop already walks the list in order.
func TestPinnedNodeIsFirstCandidate(t *testing.T) {
	nodes, _ := loadVPNGateCache()
	if len(nodes) == 0 {
		t.Skip("no VPN Gate cache in this data directory")
	}
	// Pick a pin from the pool itself so the test never depends on a literal IP.
	var pin string
	for _, n := range nodes {
		if n.CountryShort == "JP" && n.Profile != "" {
			pin = n.id()
			break
		}
	}
	if pin == "" {
		t.Skip("no JP node with a profile in the cache")
	}
	relays := vpnGateCandidates(context.Background(), nodes, "JP", pin, 6)
	if len(relays) == 0 {
		t.Fatal("no candidates returned")
	}
	if relays[0].id() != pin {
		t.Fatalf("first candidate is %s, want the pinned %s (order: %v)",
			relays[0].id(), pin, firstIDs(relays))
	}
	// The rest must still be there so a failed pin can fall through.
	if len(relays) < 2 {
		t.Fatalf("only %d candidate(s): a failed pin would leave nothing to fall back to", len(relays))
	}
	t.Logf("candidates: %v", firstIDs(relays))
}

// The fallback order is produced by sortVPNGateNodesByLatency, and latency is
// only its last resort: class (residential before the datacenter fleet), then
// this client's measured throughput tier, then throughput, and only then the
// handshake time. Pinning the comparator on synthetic nodes keeps the test
// honest — a monotonic check over a real pool asserts an order the code never
// promised, because the candidate builder deliberately concatenates
// country/class sub-pools.
func TestSortVPNGateNodesByLatency(t *testing.T) {
	mk := func(cc, class string, lat int64, bps int64) vpnGateNode {
		n := vpnGateNode{CountryShort: cc, IP: "203.0.113.9", Port: 443, Profile: "x", Class: class, LatencyMS: lat}
		n.MeasuredBps = bps
		return n
	}
	t.Run("latency decides within the same class and tier", func(t *testing.T) {
		nodes := []vpnGateNode{mk("JP", "residential", 180, 0), mk("JP", "residential", 40, 0),
			mk("JP", "residential", 0, 0), mk("JP", "residential", 90, 0)}
		sortVPNGateNodesByLatency(nodes)
		got := []int64{nodes[0].LatencyMS, nodes[1].LatencyMS, nodes[2].LatencyMS, nodes[3].LatencyMS}
		// Measured ascending, unmeasured (0) last: it has nothing to compare.
		want := []int64{40, 90, 180, 0}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("order = %v, want %v", got, want)
			}
		}
	})
	t.Run("residential outranks datacenter even when slower", func(t *testing.T) {
		nodes := []vpnGateNode{mk("JP", "datacenter", 10, 0), mk("JP", "residential", 300, 0)}
		sortVPNGateNodesByLatency(nodes)
		if nodes[0].Class != "residential" {
			t.Fatalf("datacenter relay ranked first: %+v", firstIDs(nodes))
		}
	})
	t.Run("known throughput outranks raw latency", func(t *testing.T) {
		// Same class and tier: the relay this client measured as faster wins
		// even if its handshake was slower.
		nodes := []vpnGateNode{mk("JP", "residential", 20, 2_000_000), mk("JP", "residential", 200, 8_000_000)}
		if vpnGateSpeedTier(nodes[0].MeasuredBps) != vpnGateSpeedTier(nodes[1].MeasuredBps) {
			t.Skip("the two throughputs fall in different tiers by design")
		}
		sortVPNGateNodesByLatency(nodes)
		if nodes[0].MeasuredBps != 8_000_000 {
			t.Fatalf("slower relay ranked first: %d vs %d", nodes[0].MeasuredBps, nodes[1].MeasuredBps)
		}
	})
}

func firstIDs(ns []vpnGateNode) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		out = append(out, n.id())
	}
	return out
}
