//go:build darwin

package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The macOS execute blocker is pinned to an inode, not to the file's bytes.
// renewCoreBinary is the escape hatch, so pin its contract here: same content,
// new inode, still executable, no inherited extended attributes.
func TestRenewCoreBinaryReplacesInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mihomo")
	content := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/xattr", "-w", "test.marker", "1", path).CombinedOutput(); err != nil {
		t.Skipf("cannot set test xattr: %v (%s)", err, out)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeIno := before.Sys().(*syscall.Stat_t).Ino

	if !renewCoreBinary(path) {
		t.Fatal("renewCoreBinary returned false")
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if ino := after.Sys().(*syscall.Stat_t).Ino; ino == beforeIno {
		t.Fatalf("inode unchanged (%d): the execute blocker would persist", ino)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("content changed: %q", got)
	}
	if after.Mode().Perm()&0o111 == 0 {
		t.Fatalf("lost executable bit: %v", after.Mode())
	}
	if out, _ := exec.Command("/usr/bin/xattr", "-l", path).Output(); strings.Contains(string(out), "test.marker") {
		t.Fatalf("xattr survived: %s", out)
	}
}
