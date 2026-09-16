//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
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
	// waitCancel stops the exit watcher once the session is closed, and
	// watchDone is closed once that watcher has actually left conpty's
	// WaitForSingleObject loop. Close waits for watchDone before releasing
	// the pseudo console, because the handle ConPty.Close frees is the one
	// the watcher polls - cancelling alone is only observed between polls,
	// so it left a window of up to a second in which the OS could recycle
	// the handle value under a live wait.
	waitCancel context.CancelFunc
	watchDone  chan struct{}
	once       sync.Once
	err        error
}

// Both shells below start with a command that puts the session on UTF-8.
// The pseudo console is created on the machine OEM code page (437 on an
// English install), and cmd.exe and Windows PowerShell encode their output
// to that page before it ever reaches the console buffer - so a file name,
// an event-log message or a service description containing anything outside
// it is destroyed upstream of the agent, and no decoding in Go can bring it
// back. Code page 65001 makes the session the byte-accurate UTF-8 pipe the
// browser expects, the same thing shell_linux.go buys with LANG=C.UTF-8.
//
// psUTF8Prelude sets both console encodings (assigning them calls
// SetConsoleOutputCP/SetConsoleCP, i.e. chcp) plus $OutputEncoding, which
// PowerShell 5.1 uses when it pipes to a native command. UTF8Encoding::new()
// is the BOM-less one. It deliberately contains no spaces so it stays one
// CreateProcess argument, and it is wrapped in try/catch so a host that
// refuses one of the assignments still drops the operator at a prompt.
const psUTF8Prelude = `try{$u=[Text.UTF8Encoding]::new();[Console]::OutputEncoding=$u;$OutputEncoding=$u;[Console]::InputEncoding=$u}catch{}`

// shellCommandLine resolves the requested shell to a full command line.
// PowerShell prefers pwsh 7 when installed and falls back to Windows
// PowerShell 5.1; -NoLogo only drops the banner and -NoExit keeps the
// session interactive after the UTF-8 prelude has run. The executable path
// is absolute and quoted with the same rules CreateProcess parses it with.
func shellCommandLine(shell string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(shell)) {
	case "", "powershell", "pwsh":
		return syscall.EscapeArg(interactivePowerShell()) + " -NoLogo -NoExit -Command " + syscall.EscapeArg(psUTF8Prelude), nil
	case "cmd":
		// chcp by absolute path for the same reason as the shell itself, and
		// with its "Active code page: 65001" line suppressed so the operator
		// still gets a clean first prompt. The leading @ keeps cmd from
		// stripping the quotes EscapeArg may have added (with /k it removes
		// the outer pair when the line STARTS with one) as well as echoing
		// the command.
		return syscall.EscapeArg(systemExe("cmd.exe")) + " /k @" + syscall.EscapeArg(system32("chcp.com")) + " 65001>nul", nil
	}
	return "", fmt.Errorf("unsupported shell %q on Windows (use powershell or cmd)", shell)
}

// interactivePowerShell picks the PowerShell the terminal launches: pwsh 7
// when it is installed in a place only administrators can write, Windows
// PowerShell in System32 otherwise. The shell runs as SYSTEM, so this must
// not be a bare PATH search - the same rule systemExe applies to the helper
// tools and docs/SECURITY.md states for the agent as a whole.
func interactivePowerShell() string {
	if p := pwshPath(); p != "" {
		return p
	}
	return system32(`WindowsPowerShell\v1.0\powershell.exe`)
}

// system32 is the absolute path of a file under %SystemRoot%\System32.
// systemExe next door does the same for a bare tool name, but it assumes a
// .exe leaf and falls back to PATH, which is exactly what must not happen
// for the binaries this file hands SYSTEM to.
func system32(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", name)
}

// pwshPath returns an absolute pwsh.exe from a directory an unprivileged
// user cannot write to, or "" when there is no such pwsh. The known install
// root comes first; a PATH hit is accepted only after its directory has
// been checked, so appending a writable directory to the machine PATH
// cannot decide which binary the agent starts as SYSTEM.
func pwshPath() string {
	for _, root := range programRoots() {
		p := filepath.Join(root, "PowerShell", "7", "pwsh.exe")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("pwsh.exe"); err == nil {
		if abs, err := filepath.Abs(p); err == nil && underAnyDir(trustedExeRoots(), abs) {
			return abs
		}
	}
	return ""
}

// programRoots are the Program Files directories, which only administrators
// and TrustedInstaller can write to. ProgramW6432 is the 64-bit root as seen
// from a 32-bit process.
func programRoots() []string {
	var roots []string
	for _, v := range []string{"ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"} {
		if d := os.Getenv(v); d != "" {
			roots = append(roots, d)
		}
	}
	return roots
}

// trustedExeRoots are the directories a binary the agent launches as SYSTEM
// may live in.
func trustedExeRoots() []string {
	roots := programRoots()
	if root := os.Getenv("SystemRoot"); root != "" {
		roots = append(roots, root)
	} else {
		roots = append(roots, `C:\Windows`)
	}
	return roots
}

// underAnyDir reports whether path sits in one of dirs. Windows paths are
// case-insensitive, so the comparison is; both sides are cleaned first so a
// ".." segment cannot walk out of a trusted root.
func underAnyDir(dirs []string, path string) bool {
	if path == "" {
		return false
	}
	p := strings.ToLower(filepath.Clean(path))
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		d := strings.ToLower(filepath.Clean(dir))
		if p == d {
			return true
		}
		if !strings.HasSuffix(d, `\`) {
			d += `\`
		}
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
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

// shellEnv is the environment the terminal's shell runs with: the service's
// own, plus the variables that tell a program it is on a colour-capable
// terminal. A Windows service environment has no TERM at all, so
// cross-platform tools shipped on Windows (git, node, python, less) fall
// back to their non-TTY behaviour inside what is a real console. Mirrors
// shellEnv in shell_linux.go.
func shellEnv() []string { return withTerminalEnv(os.Environ()) }

// withTerminalEnv sets TERM and COLORTERM in a copy of env. Variable names
// are case-insensitive on Windows, so an entry that is already there is
// replaced whatever its spelling.
func withTerminalEnv(env []string) []string {
	out := append([]string(nil), env...)
	set := func(k, v string) {
		for i, e := range out {
			if name, _, ok := strings.Cut(e, "="); ok && strings.EqualFold(name, k) {
				out[i] = k + "=" + v
				return
			}
		}
		out = append(out, k+"="+v)
	}
	set("TERM", "xterm-256color")
	set("COLORTERM", "truecolor")
	return out
}

// Console size bounds. ConPTY takes int16 coordinates and misbehaves at
// zero, hence the floor; the ceiling is well under that 32767 because the
// console host allocates a real screen buffer for whatever it is told, and
// a size frame must not be able to make the device allocate gigabytes.
const (
	minPTYCols = 10
	minPTYRows = 2
	maxPTYAxis = 1000
)

// clampPTYSize keeps the size the session STARTS at inside those bounds: an
// operator's first frame is not something to refuse a whole terminal over.
// A later resize is validated instead of clamped - see validPTYSize.
func clampPTYSize(cols, rows int) (int, int) {
	return min(max(cols, minPTYCols), maxPTYAxis), min(max(rows, minPTYRows), maxPTYAxis)
}

// validPTYSize rejects a resize no caller can have meant. Clamping one into
// range and applying it silently corrupted a working session: a viewer that
// measured a hidden container sent 0x0 and the operator's console collapsed
// to the 10x2 floor with no error anywhere. Linux refuses such a frame and
// keeps the current size (shell_linux.go); so does this.
func validPTYSize(cols, rows int) error {
	if cols <= 0 || rows <= 0 || cols > maxPTYAxis || rows > maxPTYAxis {
		return fmt.Errorf("invalid terminal size %dx%d (each axis must be 1..%d)", cols, rows, maxPTYAxis)
	}
	return nil
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
	p, err := conpty.Start(cmdline,
		conpty.ConPtyDimensions(cols, rows),
		conpty.ConPtyWorkDir(shellWorkDir()),
		conpty.ConPtyEnv(shellEnv()))
	if err != nil {
		return nil, fmt.Errorf("start %s: %w", cmdline, err)
	}
	waitCtx, waitCancel := context.WithCancel(context.Background())
	s := &conptySession{pty: p, pid: p.Pid(), waitCancel: waitCancel, watchDone: make(chan struct{})}
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
		// Announce that the process handle is no longer being waited on
		// BEFORE closing the session: Close blocks on watchDone, and this
		// goroutine is one of the callers that reaches it.
		close(s.watchDone)
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
	if err := validPTYSize(cols, rows); err != nil {
		return err
	}
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
		// The shell is dead by now, so the watcher's WaitForSingleObject is
		// already satisfied and this costs microseconds. The bound only
		// matters when the tree could not be killed at all, where blocking
		// the agent's dispatcher for ever would be the worse failure.
		select {
		case <-s.watchDone:
		case <-time.After(2 * time.Second):
			slog.Warn("shell: exit watcher still waiting on the shell process, closing anyway", "pid", s.pid)
		}
		s.err = s.pty.Close()
	})
	return s.err
}
