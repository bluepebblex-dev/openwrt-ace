// Package filelock provides an advisory cross-process lock for files that are
// read-modify-written by more than one engine process (e.g. the normal bridge
// and the elevated TUN bridge).
//
// The lock lives in a companion <path>.lock file, never in the target itself:
// state.json and friends are written with rename, so locking the target inode
// would silently stop working the moment it is replaced. Lock files are not
// removed on release — unlinking a locked file lets another process lock a
// different inode and defeats mutual exclusion.
package filelock

// Handle is an acquired exclusive lock. Call Release exactly once.
type Handle struct {
	close func() error
}

// Release frees the lock. Calling it more than once is a programmer error.
func (h *Handle) Release() error {
	if h == nil || h.close == nil {
		return nil
	}
	close := h.close
	h.close = nil
	return close()
}

// WithLock runs fn while holding the lock for path, releasing it afterwards.
func WithLock(path string, fn func() error) error {
	h, err := Acquire(path)
	if err != nil {
		return err
	}
	defer h.Release()
	return fn()
}
