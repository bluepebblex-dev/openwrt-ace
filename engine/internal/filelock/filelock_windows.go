//go:build windows

package filelock

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Acquire blocks until an exclusive lock on the first byte of path+".lock"
// is held. UnlockFileEx must use the same offset and length.
func Acquire(path string) (*Handle, error) {
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Handle{close: func() error {
		var ol windows.Overlapped
		unlockErr := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
		closeErr := f.Close()
		if unlockErr != nil {
			return unlockErr
		}
		return closeErr
	}}, nil
}
