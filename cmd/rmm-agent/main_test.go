package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kardianos/service"

	"github.com/MonsterCouch/homelab-rmm/internal/agent"
)

// The service is started by the service manager, not by the shell that ran
// `install`, so a config directory that only exists in this process's
// environment is lost the moment install returns. These three say the
// directory reaches the service definition instead.

func TestSpecPinsANonDefaultConfigDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(agent.EnvConfigDir, dir)
	args := spec().Args
	want := []string{"run", "--config-dir", dir}
	if len(args) != len(want) {
		t.Fatalf("args = %q, want %q", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %q, want %q", args, want)
		}
	}
}

func TestSpecLeavesTheDefaultConfigDirImplicit(t *testing.T) {
	t.Setenv(agent.EnvConfigDir, "")
	if args := spec().Args; len(args) != 1 || args[0] != "run" {
		t.Fatalf("args = %q, want [run]", args)
	}
}

func TestSpecMakesARelativeConfigDirAbsolute(t *testing.T) {
	// A service starts from / (or C:\Windows\system32): "./tmp/agent" in the
	// unit would name a different directory than the one install wrote to.
	t.Setenv(agent.EnvConfigDir, filepath.Join("tmp", "agent"))
	args := spec().Args
	if len(args) != 3 {
		t.Fatalf("args = %q, want the directory pinned", args)
	}
	if !filepath.IsAbs(args[2]) {
		t.Fatalf("pinned %q, which is not absolute", args[2])
	}
	if !strings.HasSuffix(filepath.ToSlash(args[2]), "tmp/agent") {
		t.Fatalf("pinned %q, which is not the directory asked for", args[2])
	}
}

func TestApplyConfigDirPinsItForThisProcessAndItsChildren(t *testing.T) {
	t.Setenv(agent.EnvConfigDir, "")
	dir := t.TempDir()
	applyConfigDir(dir)
	if got := os.Getenv(agent.EnvConfigDir); got != dir {
		// The environment is how the desktop helper is told, so it matters
		// that the pin lands there and not only in a package variable.
		t.Fatalf("%s = %q, want %q", agent.EnvConfigDir, got, dir)
	}
	if got, want := agent.ConfigPath(), filepath.Join(dir, "agent.json"); got != want {
		t.Fatalf("ConfigPath() = %q, want %q", got, want)
	}
}

// ---- install's "did it really start?" check ----

const (
	fatalLine = `time=2026-09-15T10:00:00.000Z level=ERROR msg="cannot load config" path=/etc/homelab-rmm/agent.json err="no such file"`
	warnLine  = `time=2026-09-15T10:00:01.000Z level=WARN msg="session ended" err="connection refused" retry_in=1m4s`
	infoLine  = `time=2026-09-15T10:00:02.000Z level=INFO msg="agent connected" server=https://rmm.lan:8443`
)

func writeLog(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.log")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func appendLog(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		t.Fatal(err)
	}
}

func TestStartupFailureFindsTheFatalLine(t *testing.T) {
	path := writeLog(t, infoLine, fatalLine)
	if got := startupFailure(path, 0); !strings.Contains(got, "cannot load config") {
		t.Fatalf("startupFailure = %q", got)
	}
}

func TestStartupFailureIgnoresWarningsAndOlderFailures(t *testing.T) {
	path := writeLog(t, fatalLine) // last month's failed install
	from := logSize(path)
	appendLog(t, path, infoLine, warnLine) // this one only warns: the server is down
	if got := startupFailure(path, from); got != "" {
		t.Fatalf("startupFailure = %q, want nothing", got)
	}
	appendLog(t, path, fatalLine)
	if got := startupFailure(path, from); got == "" {
		t.Fatal("startupFailure missed the failure written after the offset")
	}
}

func TestStartupFailureRereadsALogThatShrank(t *testing.T) {
	// The service rotates agent.log to agent.log.1 when it starts, so the
	// offset taken a moment earlier can be past the end of the new file.
	path := writeLog(t, infoLine, infoLine, fatalLine)
	from := logSize(path) + 4096
	if got := startupFailure(path, from); !strings.Contains(got, "cannot load config") {
		t.Fatalf("startupFailure = %q, want the failure from a rotated log", got)
	}
}

func TestStartupFailureIsSilentWithoutALog(t *testing.T) {
	if got := startupFailure(filepath.Join(t.TempDir(), "nope.log"), 0); got != "" {
		t.Fatalf("startupFailure = %q, want nothing", got)
	}
}

func stopped() (service.Status, error) { return service.StatusStopped, nil }
func running() (service.Status, error) { return service.StatusRunning, nil }
func unknowable() (service.Status, error) {
	return service.StatusUnknown, errors.New("no service system detected")
}

func TestConfirmStartedFailsWhenTheManagerSaysStopped(t *testing.T) {
	path := writeLog(t, infoLine)
	err := confirmStarted(path, logSize(path), stopped, time.Second, 2*time.Second)
	if err == nil {
		t.Fatal("a stopped service passed the install check")
	}
}

func TestConfirmStartedFailsOnTheAgentsOwnFatalLine(t *testing.T) {
	// systemd calls a unit that is crash-looping under Restart=always
	// "activating", which kardianos maps to running: the log is the only
	// witness that the service cannot load its config.
	path := writeLog(t, infoLine)
	from := logSize(path)
	appendLog(t, path, fatalLine)
	err := confirmStarted(path, from, running, 50*time.Millisecond, time.Second)
	if err == nil || !strings.Contains(err.Error(), "cannot load config") {
		t.Fatalf("err = %v, want the logged failure", err)
	}
}

func TestConfirmStartedAcceptsAHealthyService(t *testing.T) {
	path := writeLog(t, infoLine)
	from := logSize(path)
	appendLog(t, path, warnLine) // a warning is not a failed install
	if err := confirmStarted(path, from, running, 20*time.Millisecond, time.Second); err != nil {
		t.Fatalf("err = %v, want a healthy install", err)
	}
}

func TestConfirmStartedAcceptsAStatusItCannotRead(t *testing.T) {
	// Not every platform can answer "is it running?"; a question we could not
	// put is not an install failure.
	path := writeLog(t, infoLine)
	if err := confirmStarted(path, logSize(path), unknowable, 20*time.Millisecond, time.Second); err != nil {
		t.Fatalf("err = %v, want the unanswerable status tolerated", err)
	}
}

func TestConfirmStartedGivesUpAtTheDeadline(t *testing.T) {
	path := writeLog(t, infoLine)
	start := time.Now()
	if err := confirmStarted(path, logSize(path), func() (service.Status, error) {
		return service.StatusUnknown, nil // never running, never stopped
	}, 10*time.Millisecond, 600*time.Millisecond); err != nil {
		t.Fatalf("err = %v, want the undecidable case tolerated", err)
	}
	if took := time.Since(start); took < 500*time.Millisecond || took > 5*time.Second {
		t.Fatalf("waited %s, want about the timeout", took)
	}
}

func TestConfirmStartedFailsWhenSystemdSaysFailed(t *testing.T) {
	// systemd reports a unit in "failed" through an error rather than a
	// Status, and that is still a definite no.
	path := writeLog(t, infoLine)
	err := confirmStarted(path, logSize(path), func() (service.Status, error) {
		return service.StatusUnknown, errors.New("service in failed state")
	}, 20*time.Millisecond, time.Second)
	if err == nil {
		t.Fatal("a failed unit passed the install check")
	}
}
