//go:build windows

package agent

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// prepareCommand applies the Windows process attributes every child of the
// agent needs: no console window (the service has no desktop, and an
// interactive `rmm-agent run` should not flash cmd windows), its own process
// group, and a Cancel that kills the whole tree. cmd must have been created
// with exec.CommandContext: exec.Cmd refuses to Start with a Cancel and no
// context, and every caller in this package passes one.
func prepareCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NEW_PROCESS_GROUP
	cmd.Cancel = func() error { return killProcessTree(cmd.Process) }
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
