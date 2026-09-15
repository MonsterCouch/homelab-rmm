//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/UserExistsError/conpty"
	"golang.org/x/sys/windows"
)

// conptySession wraps a ConPTY-backed shell as a ptySession. Close is
// idempotent because the read pump (on EOF), the exit watcher (when the
// shell quits by itself) and the manager (on a close request) all call it.
type conptySession struct {
	pty *conpty.ConPty
	pid int
	// job is a kill-on-close job object holding the shell and everything it
	// spawned; 0 when the process could not be placed in one.
	job windows.Handle
	// waitCancel stops the exit watcher once the session is closed, so it
	// never polls a process handle whose value the OS has since recycled.
	waitCancel context.CancelFunc
	once       sync.Once
	err        error
}

// shellCommandLine resolves the requested shell to a full command line.
// PowerShell prefers pwsh 7 when installed and falls back to Windows
// PowerShell 5.1; -NoLogo only drops the banner. The executable path is
// quoted with the same rules CreateProcess parses it with.
func shellCommandLine(shell string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(shell)) {
	case "", "powershell", "pwsh":
		if p, err := exec.LookPath("pwsh.exe"); err == nil {
			return syscall.EscapeArg(p) + " -NoLogo", nil
		}
		return syscall.EscapeArg(powershellPath()) + " -NoLogo", nil
	case "cmd":
		return syscall.EscapeArg(systemExe("cmd.exe")), nil
	}
	return "", fmt.Errorf("unsupported shell %q on Windows (use powershell or cmd)", shell)
}

// shellWorkDir is the user profile when it exists (SYSTEM has one under
// system32\config) and the system drive's root otherwise.
func shellWorkDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if st, err := os.Stat(home); err == nil && st.IsDir() {
			return home
		}
	}
	if d := os.Getenv("SystemDrive"); d != "" {
		return d + `\`
	}
	return `C:\`
}

// clampPTYSize keeps the console size inside what the console host accepts;
// ConPTY takes int16 coordinates and misbehaves at zero.
func clampPTYSize(cols, rows int) (int, int) {
	return min(max(cols, 10), 1000), min(max(rows, 2), 1000)
}

// startPTY launches the shell attached to a pseudo console.
func startPTY(shell string, cols, rows int) (ptySession, error) {
	if !conpty.IsConPtyAvailable() {
		return nil, errors.New("interactive shell needs Windows 10 1809 / Server 2019 or later (ConPTY is not available)")
	}
	cmdline, err := shellCommandLine(shell)
	if err != nil {
		return nil, err
	}
	cols, rows = clampPTYSize(cols, rows)
	p, err := conpty.Start(cmdline, conpty.ConPtyDimensions(cols, rows), conpty.ConPtyWorkDir(shellWorkDir()))
	if err != nil {
		return nil, fmt.Errorf("start %s: %w", cmdline, err)
	}
	waitCtx, waitCancel := context.WithCancel(context.Background())
	s := &conptySession{pty: p, pid: p.Pid(), waitCancel: waitCancel}
	// The shell goes into a kill-on-close job so Close ends it and every
	// process it spawned with one handle close, instead of a taskkill round
	// trip on the dispatcher goroutine that serves every other frame on the
	// socket. conpty offers no hook before the process runs, so the
	// assignment lands a moment after creation; children inherit the job
	// from then on, and the taskkill fallback covers the rest.
	if job, err := newKillJob(s.pid); err == nil {
		s.job = job
	} else {
		slog.Debug("shell: job object unavailable, falling back to taskkill", "err", err)
	}
	// When the shell exits by itself (the user typed exit) nothing else
	// closes the pseudo console and the output pipe would stay open for
	// ever; reap it so the read pump sees EOF and the session is torn down.
	go func() {
		p.Wait(waitCtx)
		s.Close()
	}()
	return s, nil
}

// newKillJob creates a job object that terminates all its processes when
// its last handle closes and places pid in it. The agent needs
// PROCESS_SET_QUOTA and PROCESS_TERMINATE on the shell, which it has as the
// shell's parent.
func newKillJob(pid int) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(proc)
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return job, nil
}

func (s *conptySession) Read(p []byte) (int, error)  { return s.pty.Read(p) }
func (s *conptySession) Write(p []byte) (int, error) { return s.pty.Write(p) }

func (s *conptySession) Resize(cols, rows int) error {
	cols, rows = clampPTYSize(cols, rows)
	return s.pty.Resize(cols, rows)
}

// Close kills the shell and everything it spawned, then releases the
// pseudo console and its pipes. The tree goes first: ClosePseudoConsole
// waits for the console host to drain, which never happens while a child
// keeps writing and nobody reads.
func (s *conptySession) Close() error {
	s.once.Do(func() {
		s.waitCancel()
		if s.job != 0 {
			// The last handle to a kill-on-close job terminates every process
			// in it; there is nothing to wait for.
			windows.CloseHandle(s.job)
			s.job = 0
		} else {
			_ = killPIDTree(s.pid)
		}
		s.err = s.pty.Close()
	})
	return s.err
}
