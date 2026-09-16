package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shirou/gopsutil/v4/process"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const (
	// maxCmdline is how much of a command line the console is sent.
	maxCmdline = 512
	// procSampleWindow is the gap between the two readings of every process's
	// CPU time. Long enough that a short-lived spike is visible, short enough
	// that the operator's click still feels immediate.
	procSampleWindow = 400 * time.Millisecond
)

func listProcesses() ([]protocol.Process, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}
	// gopsutil's CPUPercent is CPU time over the process's whole LIFETIME and
	// is not divided by the core count: a process that burned an hour of CPU
	// this morning outranks the one pegging the machine right now, and one
	// thread per core reads as 2000%. The console labels the column "CPU %"
	// and sorts by it descending, so read every process twice instead and
	// report the share of the machine it used in between.
	before := sampleCPUTime(procs)
	at := time.Now()
	time.Sleep(procSampleWindow)
	elapsed := time.Since(at).Seconds()
	cores := runtime.NumCPU()

	out := make([]protocol.Process, 0, len(procs))
	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}
		pp := protocol.Process{PID: p.Pid, Name: name}
		if ppid, err := p.Ppid(); err == nil {
			pp.PPID = ppid
		}
		if u, err := p.Username(); err == nil {
			pp.User = u
		}
		if now, ok := cpuTime(p); ok {
			if prev, seen := before[p.Pid]; seen {
				pp.CPUPct = round1(cpuPercentOver(prev, now, elapsed, cores))
			}
		}
		if mi, err := p.MemoryInfo(); err == nil && mi != nil {
			pp.MemRSS = mi.RSS
		}
		if cl, err := p.Cmdline(); err == nil {
			pp.Cmdline = truncateRunes(cl, maxCmdline)
		}
		if ct, err := p.CreateTime(); err == nil {
			pp.Started = ct / 1000
		}
		out = append(out, pp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MemRSS > out[j].MemRSS })
	return out, nil
}

// sampleCPUTime reads every process's CPU time in one pass, as close together
// as the API allows.
func sampleCPUTime(procs []*process.Process) map[int32]float64 {
	out := make(map[int32]float64, len(procs))
	for _, p := range procs {
		if t, ok := cpuTime(p); ok {
			out[p.Pid] = t
		}
	}
	return out
}

// cpuTime is the CPU seconds a process has consumed, user plus system. The
// other fields of a TimesStat describe a whole CPU, not a process.
func cpuTime(p *process.Process) (float64, bool) {
	t, err := p.Times()
	if err != nil || t == nil {
		return 0, false
	}
	return t.User + t.System, true
}

// cpuPercentOver turns two readings of a process's CPU seconds into the share
// of the machine it used in between: 100 means every logical core was busy
// with it, which is what an operator reads a "CPU %" column as. A reading that
// went backwards (a pid reused between the samples) reports 0 rather than a
// spike nobody can explain.
func cpuPercentOver(prev, now, elapsed float64, cores int) float64 {
	if elapsed <= 0 || cores <= 0 || now <= prev {
		return 0
	}
	pct := 100 * (now - prev) / (elapsed * float64(cores))
	if pct > 100 {
		return 100
	}
	return pct
}

// truncateRunes cuts s to at most max BYTES without splitting a character.
// len() and a byte slice cut mid-rune, and encoding/json then replaces the
// orphaned bytes with U+FFFD - so the command line the console shows, and the
// CSV it exports, stopped being a faithful prefix of the real one.
func truncateRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max] + "..."
}

// protectedProcessNames are the processes the operating system does not
// survive losing. Windows marks most of them critical, and terminating one
// bugchecks the machine with CRITICAL_PROCESS_DIED - an unplanned reboot with
// data loss, one console click away. The names are matched without case and
// without a ".exe" suffix.
var protectedProcessNames = map[string]bool{
	// Windows
	"system": true, "system idle process": true, "idle": true, "registry": true,
	"smss": true, "csrss": true, "wininit": true, "winlogon": true,
	"services": true, "lsass": true, "lsaiso": true, "memory compression": true,
	// Linux
	"init": true, "systemd": true,
}

// isProtectedProcessName reports whether a process is one the machine is held
// up by.
func isProtectedProcessName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".exe")
	return protectedProcessNames[n]
}

// killProcess ends a process for the console's Kill button. Everything it
// refuses, it refuses on the device: the server forwards whatever pid it was
// given, and the listing marks none of these rows as special.
func killProcess(pid int32) error {
	// 0 and 4 are System Idle Process and System on Windows, and pid 1 is
	// init on Linux.
	if pid <= 4 {
		return errors.New("refusing to kill a system process")
	}
	if pid == int32(os.Getpid()) {
		return errors.New("refusing to kill the RMM agent itself")
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		return err
	}
	if name, err := p.Name(); err == nil && isProtectedProcessName(name) {
		return fmt.Errorf("refusing to kill %s: the operating system depends on it", name)
	}
	// The desktop helper runs from the same image in the user's session and
	// outlives a service restart; killing it drops the remote desktop, and
	// killing the service itself drops the device off the console.
	if isOwnImage(p) {
		return errors.New("refusing to kill the RMM agent itself")
	}
	if isCriticalProcess(pid) {
		return errors.New("refusing to kill a process the operating system marks critical; terminating it would crash the device")
	}
	return p.Kill()
}

// isOwnImage reports whether a process runs the same executable we do.
func isOwnImage(p *process.Process) bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	exe, err := p.Exe()
	if err != nil || exe == "" {
		return false
	}
	return samePath(exe, self)
}

// samePath compares two file paths the way the platform does.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
