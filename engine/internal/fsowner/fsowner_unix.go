//go:build !windows

package fsowner

import (
	"os"
	"syscall"
)

// ownerOf reports the uid/gid that owns dir.
func ownerOf(dir string) (int, int, bool) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
