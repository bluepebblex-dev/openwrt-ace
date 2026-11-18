// Package fsowner keeps files written by an elevated process usable by the
// desktop user who owns the data directory.
//
// macOS runs the GUI as the logged-in user but the TUN/proxy session runs as
// root (osascript elevates it), and both share one WARP_CLIENT_HOME. Root's
// umask plus the 0600 mode we want for credentials makes every file it writes
// root-owned and unreadable to the GUI: state.json then reads as "no session"
// and the traffic counter stays at zero while the tunnel is perfectly fine.
//
// Adopt gives such a file back to the directory's owner, keeping 0600 so the
// contents stay private.
package fsowner

import (
	"os"
	"path/filepath"
)

// Adopt hands path to the owner of dir when the current process runs as root.
// It is a no-op for unprivileged processes (they already own what they write)
// and for platforms without POSIX ownership.
func Adopt(path, dir string) {
	if os.Geteuid() != 0 {
		return
	}
	uid, gid, ok := ownerOf(dir)
	if !ok {
		return
	}
	// A failed chown must not break the write that just succeeded: the file is
	// still readable by root, and the next write retries.
	_ = os.Chown(path, uid, gid)
}

// AdoptSibling adopts path to whoever owns its own directory.
func AdoptSibling(path string) {
	Adopt(path, filepath.Dir(path))
}
