package main

import (
	"os"
	"path/filepath"
	"testing"
)

// mutateState must re-read the persisted snapshot under the lock: callers use
// it after slow work, and another bridge may have updated the session meanwhile.
func TestMutateStateUsesLatestSnapshot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("WARP_CLIENT_HOME", home)

	// Simulate the other engine writing a newer state between our old load and
	// our commit: only MixedPort changes in our callback, Connected must survive.
	if err := os.WriteFile(filepath.Join(home, "state.json"), []byte(`{"connected":true,"mixed_port":7890}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mutateState(func(s *clientState) error {
		s.MixedPort = 9999
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Connected || st.MixedPort != 9999 {
		t.Fatalf("mutateState lost the other writer's fields: %+v", st)
	}
}
