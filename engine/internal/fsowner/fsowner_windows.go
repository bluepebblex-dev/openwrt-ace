//go:build windows

package fsowner

// ownerOf has no POSIX ownership to report on Windows: the elevated process
// runs as the same desktop account, so files are already usable.
func ownerOf(dir string) (int, int, bool) { return 0, 0, false }
