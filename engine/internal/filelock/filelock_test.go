package filelock

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireExcludesAnotherHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	first, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}

	acquired := make(chan *Handle, 1)
	errs := make(chan error, 1)
	go func() {
		h, err := Acquire(path)
		if err != nil {
			errs <- err
			return
		}
		acquired <- h
	}()

	select {
	case <-acquired:
		t.Fatal("second Acquire succeeded while the first lock was held")
	case err := <-errs:
		t.Fatalf("second Acquire failed instead of waiting: %v", err)
	case <-time.After(150 * time.Millisecond):
		// expected: still blocked
	}

	if err := first.Release(); err != nil {
		t.Fatal(err)
	}

	select {
	case h := <-acquired:
		if err := h.Release(); err != nil {
			t.Fatal(err)
		}
	case err := <-errs:
		t.Fatalf("second Acquire failed after release: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("second Acquire did not proceed after release")
	}
}
