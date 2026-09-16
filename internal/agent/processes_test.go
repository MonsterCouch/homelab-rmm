package agent

import (
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// A byte slice at 512 cuts a multi-byte character in half, and encoding/json
// then writes U+FFFD in its place - so the command line the console shows and
// the CSV it exports stopped being a prefix of the real one (proc-02).
func TestTruncateRunesNeverSplitsACharacter(t *testing.T) {
	// A 2-byte Cyrillic ZHE straddling the cut: the lead byte lands at 511
	// and its continuation at 512.
	s := strings.Repeat("x", 511) + "Ж" + strings.Repeat("y", 100)
	got := truncateRunes(s, 512)
	if !utf8.ValidString(got) {
		t.Errorf("truncated command line is not valid UTF-8: %q", got[len(got)-8:])
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("a truncated command line must say so: %q", got[len(got)-8:])
	}
	if body := strings.TrimSuffix(got, "..."); !strings.HasPrefix(s, body) {
		t.Error("the truncation is not a prefix of the real command line")
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Error("the truncation emitted a replacement character")
	}

	// A clean boundary keeps the whole character, and a short string is
	// returned untouched with no ellipsis.
	if got := truncateRunes(strings.Repeat("x", 510)+"ЖЖ", 512); !strings.HasSuffix(got, "Ж...") {
		t.Errorf("a character that fits was dropped: %q", got[len(got)-8:])
	}
	for _, s := range []string{"", "short", strings.Repeat("x", 512)} {
		if got := truncateRunes(s, 512); got != s {
			t.Errorf("truncateRunes(%d bytes) changed a string that fits", len(s))
		}
	}
}

// gopsutil's CPUPercent is CPU time over the process's whole lifetime and is
// never divided by the core count, so it neither tracks current usage nor
// stays inside 0-100 (proc-01).
func TestCPUPercentOverIsAShareOfTheWholeMachine(t *testing.T) {
	// Two seconds of CPU in one second of wall clock on four cores is half
	// of the machine, not 200%.
	if got := cpuPercentOver(10, 12, 1, 4); got != 50 {
		t.Errorf("cpuPercentOver = %v, want 50", got)
	}
	// One core fully busy on a 20-core box is 5%.
	if got := cpuPercentOver(0, 1, 1, 20); got != 5 {
		t.Errorf("cpuPercentOver = %v, want 5", got)
	}
	// Every core busy is the ceiling, and jitter does not push it past it.
	if got := cpuPercentOver(0, 4.4, 1, 4); got != 100 {
		t.Errorf("cpuPercentOver = %v, want 100", got)
	}
	// A pid reused between the two samples reads backwards; that is not a
	// spike, it is a different process.
	for _, c := range []struct{ prev, now, elapsed float64 }{
		{10, 9, 1}, {0, 1, 0}, {0, 1, -1},
	} {
		if got := cpuPercentOver(c.prev, c.now, c.elapsed, 4); got != 0 {
			t.Errorf("cpuPercentOver(%v) = %v, want 0", c, got)
		}
	}
	if got := cpuPercentOver(0, 1, 1, 0); got != 0 {
		t.Errorf("cpuPercentOver with no cores = %v, want 0", got)
	}
}

// `pid <= 4` is a Linux-shaped guard: on Windows it covers System Idle Process
// and System and nothing else, while csrss, wininit, winlogon, services and
// lsass are listed with ordinary pids and terminating any of them bugchecks
// the machine (proc-03).
func TestKillProcessRefusesTheProcessesTheMachineNeeds(t *testing.T) {
	for _, name := range []string{
		"csrss.exe", "CSRSS.EXE", "wininit.exe", "winlogon.exe", "services.exe",
		"lsass.exe", "smss.exe", "System", "System Idle Process", "init", "systemd",
	} {
		if !isProtectedProcessName(name) {
			t.Errorf("%s must not be killable from the console", name)
		}
	}
	for _, name := range []string{"notepad.exe", "chrome.exe", "svchost.exe", "sshd", "nginx", ""} {
		if isProtectedProcessName(name) {
			t.Errorf("%s is an ordinary process an operator may need to end", name)
		}
	}

	for _, pid := range []int32{0, 1, 4} {
		if err := killProcess(pid); err == nil {
			t.Errorf("pid %d must be refused", pid)
		}
	}
	// Killing the agent takes the device off the console; the service would
	// come back, but the operator gets no answer and no idea why.
	err := killProcess(int32(os.Getpid()))
	if err == nil {
		t.Fatal("the agent killed itself")
	}
	if !strings.Contains(err.Error(), "itself") {
		t.Errorf("the refusal must say what it refused, got %v", err)
	}
}
