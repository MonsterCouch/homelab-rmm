//go:build windows

package supervisor

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// configureWorkerProc applies Windows process attributes ensuring zero window flashing
// and isolated process group membership.
func configureWorkerProc(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP
}

// terminateWorkerProcess ends the worker process and its descendants cleanly without flashing windows.
func terminateWorkerProcess(p *os.Process) error {
	if p == nil {
		return nil
	}

	// 1. Attempt taskkill /T /F /PID with hidden window to kill process tree
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	tk := exec.CommandContext(ctx, "taskkill", "/T", "/F", "/PID", strconv.Itoa(p.Pid))
	tk.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	if err := tk.Run(); err == nil {
		return nil
	}

	// 2. Direct process kill fallback (TerminateProcess)
	return p.Kill()
}
