//go:build darwin

package core

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// ensureExecutable checks that the core binary can actually start, and heals
// the one failure mode that no amount of xattr cleaning fixes: macOS can pin a
// "do not execute" decision to a specific inode (seen after a core download or
// a XProtect/Gatekeeper update). The process is killed with SIGKILL before
// main() runs, so there is no stderr, no exit status to parse, and the UI just
// reports an unexplained "内核进程崩溃".
//
// A byte-for-byte copy to a fresh inode is accepted again — the decision is
// about the inode, not the bytes or the directory. We therefore probe with
// `-v` and, only when the child was SIGKILLed, replace the file through a
// temporary copy. The probe is cheap (~10ms) and runs once per Core; a healthy
// core never pays the copy cost.
func ensureExecutable(path string) {
	for attempt := 0; attempt < 2; attempt++ {
		cmd := exec.Command(path, "-v")
		hideConsole(cmd)
		_, err := cmd.CombinedOutput()
		if err == nil {
			return
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return // missing file, bad exec format, etc. - not our case
		}
		ws, ok := ee.Sys().(syscall.WaitStatus)
		if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			return
		}
		if !renewCoreBinary(path) {
			return
		}
	}
}

// renewCoreBinary copies a binary onto a fresh inode and atomically replaces
// the original. Extended attributes are dropped on the copy: provenance and
// quarantine are exactly the kind of metadata that can re-trigger the block.
func renewCoreBinary(path string) bool {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".mihomo-renew-*")
	if err != nil {
		return false
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	src, err := os.Open(path)
	if err != nil {
		_ = f.Close()
		return false
	}
	_, err = io.Copy(f, src)
	_ = src.Close()
	if err != nil {
		_ = f.Close()
		return false
	}
	if err := f.Chmod(0o755); err != nil {
		_ = f.Close()
		return false
	}
	if err := f.Close(); err != nil {
		return false
	}
	clearLaunchAttrs(tmp)
	return os.Rename(tmp, path) == nil
}
