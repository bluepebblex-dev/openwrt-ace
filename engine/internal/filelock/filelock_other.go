//go:build !unix && !windows

package filelock

import "errors"

// Acquire is unsupported on platforms without advisory file locks. Callers
// keep working in-process; they simply do not get cross-process exclusion.
func Acquire(path string) (*Handle, error) {
	return nil, errors.New("filelock: unsupported platform")
}
