package main

import (
	"os"
	"strconv"
	"sync"
	"testing"
)

// A pid no real host is expected to hand out; processAlive must reject it for
// the stale-claim tests to mean anything.
const deadOwnerPID = 2_000_000_000

func requireDeadPID(t *testing.T) {
	t.Helper()
	if processAlive(deadOwnerPID) {
		t.Skipf("pid %d unexpectedly alive on this host", deadOwnerPID)
	}
}

func writeOwnerClaim(t *testing.T, pid int) {
	t.Helper()
	p, err := ownerClaimPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClaimHealthOwnerRespectsLivingOwner(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	requireDeadPID(t)
	me := os.Getpid()
	if !claimHealthOwner(me) {
		t.Fatal("first claim failed")
	}
	if claimHealthOwner(deadOwnerPID) {
		t.Fatal("another pid took the claim from a living owner")
	}
	owner, alive := currentHealthOwner()
	if !alive || owner != me {
		t.Fatalf("claim changed: owner=%d alive=%v, want %d/true", owner, alive, me)
	}
	// Idempotent for the owner itself (GUI ticking every two seconds).
	if !claimHealthOwner(me) {
		t.Fatal("owner's own renewal failed")
	}
}

func TestClaimHealthOwnerTakesOverStaleClaim(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	requireDeadPID(t)
	writeOwnerClaim(t, deadOwnerPID)
	me := os.Getpid()
	if !claimHealthOwner(me) {
		t.Fatal("failed to take over a claim naming a dead pid")
	}
	owner, alive := currentHealthOwner()
	if !alive || owner != me {
		t.Fatalf("stale takeover failed: owner=%d alive=%v, want %d/true", owner, alive, me)
	}
}

func TestReleaseHealthOwnerOnlyReleasesOurs(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	requireDeadPID(t)
	me := os.Getpid()
	if !claimHealthOwner(me) {
		t.Fatal("first claim failed")
	}
	releaseHealthOwner(deadOwnerPID)
	owner, alive := currentHealthOwner()
	if !alive || owner != me {
		t.Fatalf("another pid's release removed our claim: owner=%d alive=%v", owner, alive)
	}
	releaseHealthOwner(me)
	owner, alive = currentHealthOwner()
	if alive || owner != 0 {
		t.Fatalf("claim still present after release: owner=%d alive=%v", owner, alive)
	}
}

// Two processes that both see an unclaimed session must not both end up
// believing they own it. The companion lock is what decides the single winner.
func TestClaimHealthOwnerConcurrentSingleWinner(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	a, b := os.Getpid(), os.Getppid()
	if a == b || !processAlive(a) || !processAlive(b) {
		t.Skip("need two living, distinct pids")
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var winners []int
	start := make(chan struct{})
	for _, pid := range []int{a, b} {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			<-start
			if claimHealthOwner(pid) {
				mu.Lock()
				winners = append(winners, pid)
				mu.Unlock()
			}
		}(pid)
	}
	close(start)
	wg.Wait()

	if len(winners) != 1 {
		t.Fatalf("want exactly one owner, got %v", winners)
	}
	owner, alive := currentHealthOwner()
	if !alive || owner != winners[0] {
		t.Fatalf("winner lost the claim: winner=%d owner=%d alive=%v", winners[0], owner, alive)
	}
}

// A release racing a takeover must never delete the new owner's claim: check
// and remove are one locked step.
func TestReleaseRacingTakeoverKeepsNewClaim(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	a, b := os.Getpid(), os.Getppid()
	if a == b || !processAlive(a) || !processAlive(b) {
		t.Skip("need two living, distinct pids")
	}
	if !claimHealthOwner(a) {
		t.Fatal("first claim failed")
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		releaseHealthOwner(a)
	}()
	go func() {
		defer wg.Done()
		<-start
		claimHealthOwner(b)
	}()
	close(start)
	wg.Wait()

	owner, alive := currentHealthOwner()
	if alive && owner != b {
		t.Fatalf("stale release deleted the new claim: owner=%d, want none or %d", owner, b)
	}
	// The lock file must survive even when the claim itself is gone; replacing
	// or unlinking it is what would split the lock across inodes.
	p, err := ownerClaimPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".lock"); err != nil {
		t.Fatalf("companion lock file was removed: %v", err)
	}
}
