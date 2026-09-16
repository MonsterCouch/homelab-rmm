package main

import (
	"errors"
	"io"
	"log/slog"
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

// ---- the log the service actually writes ----

// brokenStderr is os.Stderr in a process the Windows Service Control Manager
// started: GetStdHandle hands back 0 and every write fails.
type brokenStderr struct{ writes int }

func (b *brokenStderr) Write(p []byte) (int, error) {
	b.writes++
	return 0, errors.New("write /dev/stderr: The handle is invalid.")
}

// TestLoggingReachesTheFileOverABrokenStderr pins svc-01: the handler was
// io.MultiWriter(os.Stderr, f), which returns on the first writer's error and
// never reaches the file, and slog throws that error away - so agent.log was
// created and then left at 0 bytes on every Windows service install, taking
// every diagnostic the agent has with it.
func TestLoggingReachesTheFileOverABrokenStderr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stderr := &brokenStderr{}
	setupHandler(stderr, f)
	// The service never closes its log; this test must, or Windows will not
	// let the temporary directory go.
	t.Cleanup(func() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) })

	slog.Info("connected", "server", "https://rmm.lan:8443", "agent_id", "5f022bf5de64ee0d")
	slog.Warn("agent key rejected, re-enrolling with stored token")
	f.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"msg=connected", "re-enrolling with stored token"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("agent.log is missing %q; it has:\n%s", want, b)
		}
	}
	if stderr.writes == 0 {
		t.Error("stderr was dropped from the handler even before it failed")
	}
}

func TestLoggingStillWorksWithNoFileAtAll(t *testing.T) {
	// openLog returns nil when nothing writable was found; the process still
	// runs, and logging must not panic.
	setupHandler(io.Discard, nil)
	t.Cleanup(func() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) })
	slog.Info("still here")
}

// TestStartTimeoutOutlastsTheServiceControlManager: the Windows SCM waits 30 s
// for a service to connect to it before it calls the start a failure, so a
// deadline shorter than that returns "it never said stopped either" for a
// service the SCM is about to declare dead.
func TestStartTimeoutOutlastsTheServiceControlManager(t *testing.T) {
	const scmStartTimeout = 30 * time.Second
	if startTimeout <= scmStartTimeout {
		t.Fatalf("startTimeout = %s, want more than the SCM's %s", startTimeout, scmStartTimeout)
	}
	if startSettle >= startTimeout {
		t.Fatalf("startSettle = %s does not fit inside startTimeout = %s", startSettle, startTimeout)
	}
}

// The remediation line is the last thing the operator reads, so it has to name
// every place the reason could be - the agent's log, and the service manager's
// own record of a process that died before it could log anything.
func TestStartFailureHintNamesWhereToLook(t *testing.T) {
	win := startFailureHint(`C:\ProgramData\HomelabRMM\agent.log`, "windows")
	if !strings.Contains(win, `C:\ProgramData\HomelabRMM\agent.log`) {
		t.Errorf("the Windows hint does not name the log: %q", win)
	}
	if !strings.Contains(win, "event log") || !strings.Contains(win, agent.ServiceName) {
		t.Errorf("the Windows hint does not name the event log: %q", win)
	}
	unix := startFailureHint("/etc/homelab-rmm/agent.log", "linux")
	if !strings.Contains(unix, "/etc/homelab-rmm/agent.log") || !strings.Contains(unix, "journalctl") {
		t.Errorf("the Linux hint does not name the log and the journal: %q", unix)
	}
}
