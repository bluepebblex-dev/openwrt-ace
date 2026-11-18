//go:build darwin

package core

import "os/exec"

// clearLaunchAttrs removes extended attributes from a downloaded core before
// it is executed. macOS attaches com.apple.provenance (and sometimes
// quarantine) to binaries fetched or unpacked by a GUI process; with that
// attribute present the kernel kills mihomo with SIGKILL before main() runs,
// which surfaces to the user as an unexplained "内核进程崩溃" on connect.
//
// xattr -c is idempotent and cheap. Errors are ignored: an unreadable binary
// will fail loudly at exec, and we do not want to block a working core just
// because xattr was momentarily unavailable.
func clearLaunchAttrs(path string) {
	if path == "" {
		return
	}
	_ = exec.Command("/usr/bin/xattr", "-c", path).Run()
}
