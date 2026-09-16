//go:build windows

package agent

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// prepareCommand applies the Windows process attributes every child of the
// agent needs: no console window (the service has no desktop, and an
// interactive `rmm-agent run` should not flash cmd windows), its own process
// group, a Cancel that kills the whole tree, and - like proc_linux.go - a
// default WaitDelay, so a descendant that inherited our pipes cannot keep
// Wait blocked for ever. cmd must have been created with exec.CommandContext:
// exec.Cmd refuses to Start with a Cancel and no context, and every caller in
// this package passes one.
//
// The tree kill is only as good as what it can reach, so callers should also
// call superviseCommand once the command has started.
func prepareCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NEW_PROCESS_GROUP
	cmd.Cancel = func() error {
		if jobFor(cmd).terminate() {
			// The job took the whole tree down; there is nothing left for
			// taskkill to find, and os/exec turns a nil error here into the
			// context's own error, which is what the caller reports.
			return nil
		}
		return killProcessTree(cmd.Process)
	}
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = 5 * time.Second
	}
}

// killJob is the kill-on-close job object a started command runs in.
// Terminating a job ends every process in it, including a descendant whose
// own parent has already exited - which taskkill, walking the live parent
// chain, cannot reach. A zero handle means the job could not be created and
// the taskkill fallback is all there is.
type killJob struct {
	mu     sync.Mutex
	handle windows.Handle
}

// terminate kills the whole job and reports whether it could. A job that was
// never created, or one already terminated or released, answers false so the
// caller falls back to taskkill.
func (j *killJob) terminate() bool {
	if j == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.handle == 0 {
		return false
	}
	h := j.handle
	j.handle = 0
	err := windows.TerminateJobObject(h, 1)
	windows.CloseHandle(h)
	return err == nil
}

// release detaches a job whose command finished on its own: the kill-on-close
// limit is cleared first, so a process the command deliberately left running
// (a background task a script started) outlives the run exactly as it does on
// Linux, where nothing signals the process group unless the run is cancelled.
func (j *killJob) release() {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.handle == 0 {
		return
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if _, err := windows.SetInformationJobObject(j.handle, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		slog.Debug("could not clear the kill-on-close limit before releasing a job", "err", err)
	}
	windows.CloseHandle(j.handle)
	j.handle = 0
}

// cmdJobs holds the job of every command currently being supervised. The job
// has to be created after CreateProcess (the pid is the only way to assign a
// process to one) but cmd.Cancel is installed before it, so the two halves
// find each other here rather than through a field exec.Cmd does not have.
var (
	cmdJobsMu sync.Mutex
	cmdJobs   = map[*exec.Cmd]*killJob{}
)

func jobFor(cmd *exec.Cmd) *killJob {
	cmdJobsMu.Lock()
	defer cmdJobsMu.Unlock()
	return cmdJobs[cmd]
}

// superviseCommand puts a command that has just started into a kill-on-close
// job object, so cancelling it reaches every descendant: job membership is
// inherited by grandchildren, survives a re-parenting and cannot be broken
// away from unless the job allows it, none of which is true of taskkill's
// walk of the live parent chain. It matters most for a script run, whose
// stdout pipe an escaped descendant would otherwise hold open long after the
// timeout, wedging the run.
//
// The caller must call the returned release when the command is done (defer
// it next to Wait); it detaches the job without killing anything.
//
// exec.Cmd offers no hook between CreateProcess and Start returning, so the
// assignment lands a moment after the process was created and a child that
// spawns a grandchild in its very first instants could still escape - the
// same window the ConPTY shell accepts in shell_windows.go. cmd.Cancel's
// taskkill fallback covers that case, and a job object the OS refused to
// create.
func superviseCommand(cmd *exec.Cmd) (release func()) {
	if cmd == nil || cmd.Process == nil {
		return func() {}
	}
	j := &killJob{}
	if h, err := newKillJob(cmd.Process.Pid); err == nil {
		j.handle = h
	} else {
		slog.Debug("job object unavailable, cancellation falls back to taskkill", "pid", cmd.Process.Pid, "err", err)
	}
	cmdJobsMu.Lock()
	cmdJobs[cmd] = j
	cmdJobsMu.Unlock()
	return func() {
		cmdJobsMu.Lock()
		delete(cmdJobs, cmd)
		cmdJobsMu.Unlock()
		j.release()
	}
}

// killProcessTree ends p and every descendant. os.Process.Kill only
// terminates the direct child; a PowerShell script that spawned msiexec
// would otherwise keep running after its timeout.
func killProcessTree(p *os.Process) error {
	if p == nil {
		return os.ErrProcessDone
	}
	if err := killPIDTree(p.Pid); err == nil {
		return nil
	}
	// taskkill could not do it (already exited, or a protected process):
	// fall back to the plain kill, whose os.ErrProcessDone lets exec.Cmd
	// report the context error instead of a bogus kill failure.
	return p.Kill()
}

// killPIDTree runs "taskkill /T /F /PID <pid>" hidden, with its own short
// deadline so a wedged taskkill cannot stall the caller's cancellation.
func killPIDTree(pid int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tk := exec.CommandContext(ctx, systemExe("taskkill"), "/T", "/F", "/PID", strconv.Itoa(pid))
	tk.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return tk.Run()
}
