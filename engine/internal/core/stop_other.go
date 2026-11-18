//go:build !windows

package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func hideConsole(*exec.Cmd) {}

// spawnWatchdog is a no-op off Windows: the GUI ties the core lifetime to the
// client through a different mechanism, and there is no job object to attach.
func spawnWatchdog(corePID int) {}

// WaitClientOrCore is only used by the Windows watchdog.
func WaitClientOrCore(clientPID, corePID int) (bool, error) {
	return false, fmt.Errorf("core: watchdog is not supported on %s", runtime.GOOS)
}

// processName returns the executable path/name for a PID via ps.
func processName(pid int) string {
	out, err := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// lsofPath finds lsof: /usr/sbin on macOS, /usr/bin on Linux, PATH as the last
// resort (a GUI-launched process often has a thinner PATH than a shell).
func lsofPath() string {
	for _, p := range []string{"/usr/sbin/lsof", "/usr/bin/lsof"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("lsof"); err == nil {
		return p
	}
	return ""
}

// portListeners maps pid -> command name for every process listening on a TCP
// port. lsof is used instead of ps because it is the one process query that
// keeps working when `ps` is unavailable (some hosts and security tools block
// it outright), and a leftover core is by definition a listener.
func portListeners(port int) map[int]string {
	if port <= 0 {
		return nil
	}
	return lsofListeners("-iTCP:" + strconv.Itoa(port))
}

// allListeners is portListeners for every TCP port at once: one lsof call to
// find any stale core by name, whatever port it grabbed.
func allListeners() map[int]string {
	return lsofListeners("-iTCP")
}

func lsofListeners(selector string) map[int]string {
	bin := lsofPath()
	if bin == "" {
		return nil
	}
	out, err := exec.Command(bin, "-nP", selector, "-sTCP:LISTEN", "-F", "pc").Output()
	if err != nil {
		// lsof exits 1 when nothing matches; that is not an error here.
		return nil
	}
	res := map[int]string{}
	pid := 0
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			if v, e := strconv.Atoi(line[1:]); e == nil {
				pid = v
			}
		case 'c':
			// Command name; lsof truncates it to 9 characters, which the
			// matcher accounts for.
			if pid > 0 {
				res[pid] = line[1:]
			}
		}
	}
	return res
}

// KillByPID terminates pid if its executable matches expectExe (base name),// KillByPID terminates pid if its executable matches expectExe (base name),
// then waits briefly for it to exit. The match guard prevents killing an
// unrelated process that reused the PID.
func KillByPID(pid int, expectExe string) error {
	if pid <= 0 {
		return fmt.Errorf("core: invalid pid %d", pid)
	}
	name := processName(pid)
	if expectExe != "" && name != "" {
		want := filepath.Base(expectExe)
		if filepath.Base(name) != want && name != want {
			return fmt.Errorf("core: pid %d is %s, expected %s", pid, name, want)
		}
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	for i := 0; i < 20; i++ {
		if processName(pid) == "" {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = proc.Signal(syscall.SIGKILL)
	return nil
}

// KillStaleCores kills any running core whose executable base name matches exe
// and lives in the same directory. A previous session's core may still hold
// the mixed/API ports; reaping it lets the new core bind cleanly.
func KillStaleCores(exe string) int {
	want := filepath.Base(exe)
	if want == "" || want == "." {
		return 0
	}
	exeDir := filepath.Dir(exe)
	killed := 0
	seen := map[int]bool{}
	out, _ := exec.Command("/bin/ps", "-Ao", "pid=,comm=").Output()
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		comm := fields[1]
		if !sameExeName(comm, want) {
			continue
		}
		if filepath.IsAbs(comm) && exeDir != "" && filepath.Dir(comm) != exeDir {
			continue
		}
		seen[pid] = true
		if KillByPID(pid, want) == nil {
			killed++
		}
	}
	// Second pass over TCP listeners: catches leftovers that `ps` cannot report
	// (blocked, or owned by another user) and cores started from a different
	// directory than the one we are about to use.
	self := os.Getpid()
	for pid, name := range allListeners() {
		if pid == self || seen[pid] || !sameExeName(name, want) {
			continue
		}
		seen[pid] = true
		if KillByPID(pid, want) == nil {
			killed++
		}
	}
	return killed
}
