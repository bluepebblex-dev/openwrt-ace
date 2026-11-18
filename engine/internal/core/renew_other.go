//go:build !darwin

package core

// ensureExecutable is a no-op off macOS. Other platforms do not pin execute
// decisions to an inode, and a needless `-v` probe on every Core creation
// would slow down startup (and spawn a child the Windows GUI cannot show).
func ensureExecutable(string) {}
