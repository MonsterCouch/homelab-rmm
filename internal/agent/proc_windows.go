//go:build windows

package agent

import (
	"context"
	"fmt"
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

const (
	defaultMaxMemoryMB     uint64 = 1024
	defaultCPULimitPercent uint32 = 80

	// Job Object CPU rate control flags from winnt.h:
	jobObjectCPURateControlEnable  uint32 = 0x1
	jobObjectCPURateControlHardCap uint32 = 0x4
)

// jobObjectCPURateControlInformation matches the Win32 API struct
// JOBOBJECT_CPU_RATE_CONTROL_INFORMATION for SetInformationJobObject with
// JobObjectCpuRateControlInformation (class 15).
type jobObjectCPURateControlInformation struct {
	ControlFlags uint32
	CpuRate      uint32
}

// newSandboxedJob creates a job object that terminates all child processes when
// its last handle closes, enforces a memory ceiling (default 1024 MB), and
// caps CPU utilization (default 80%), placing pid in it.
func newSandboxedJob(pid int, maxMemMB uint64, cpuPercent uint32) (windows.Handle, error) {
	if maxMemMB == 0 {
		maxMemMB = defaultMaxMemoryMB
	}
	if cpuPercent == 0 {
		cpuPercent = defaultCPULimitPercent
	}
	if cpuPercent > 100 {
		cpuPercent = 100
	}

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}

	// 1. Extended limit information: process and job memory limits plus kill-on-close.
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
		windows.JOB_OBJECT_LIMIT_JOB_MEMORY
	memBytes := uintptr(maxMemMB * 1024 * 1024)
	info.ProcessMemoryLimit = memBytes
	info.JobMemoryLimit = memBytes

	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject(ExtendedLimit): %w", err)
	}

	// 2. CPU rate control: hard cap on processor cycle proportion per 10,000.
	cpuInfo := jobObjectCPURateControlInformation{
		ControlFlags: jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
		CpuRate:      cpuPercent * 100,
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectCpuRateControlInformation,
		uintptr(unsafe.Pointer(&cpuInfo)),
		uint32(unsafe.Sizeof(cpuInfo)),
	); err != nil {
		slog.Debug("job object CPU rate control unavailable, proceeding with memory limits only", "err", err)
	}

	// 3. Open process and assign to job object.
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

// superviseSandboxedCommand puts a command that has just started into a sandboxed
// kill-on-close job object with process and job memory limits and CPU rate control.
// If maxMemMB is 0, it defaults to 1024 MB. If cpuPercent is 0, it defaults to 80%.
func superviseSandboxedCommand(cmd *exec.Cmd, maxMemMB uint64, cpuPercent uint32) (release func()) {
	if cmd == nil || cmd.Process == nil {
		return func() {}
	}
	j := &killJob{}
	if h, err := newSandboxedJob(cmd.Process.Pid, maxMemMB, cpuPercent); err == nil {
		j.handle = h
	} else {
		slog.Debug("sandboxed job object unavailable, cancellation falls back to taskkill", "pid", cmd.Process.Pid, "err", err)
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

// superviseCommand puts a command that has just started into a kill-on-close
// job object with default sandboxing limits (1024 MB RAM, 80% CPU).
func superviseCommand(cmd *exec.Cmd) (release func()) {
	return superviseSandboxedCommand(cmd, 0, 0)
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
