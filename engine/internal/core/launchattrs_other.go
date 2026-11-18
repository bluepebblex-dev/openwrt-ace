//go:build !darwin

package core

// clearLaunchAttrs is a no-op off macOS: no provenance/quarantine attribute
// blocks execution there.
func clearLaunchAttrs(string) {}
