//go:build linux

package supervisor

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// configureWorkerProc sets process group ID on Linux for clean signal management.
func configureWorkerProc(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// terminateWorkerProcess sends SIGTERM to the process group, falling back to SIGKILL.
func terminateWorkerProcess(p *os.Process) error {
	if p == nil {
		return nil
	}

	pgid, err := syscall.Getpgid(p.Pid)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
	} else {
		_ = p.Signal(syscall.SIGTERM)
	}

	// Wait briefly for clean exit
	done := make(chan struct{})
	go func() {
		for i := 0; i < 20; i++ {
			if err := syscall.Kill(p.Pid, 0); err != nil {
				close(done)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	select {
	case <-done:
		return nil
	case <-time.After(1 * time.Second):
		// Force kill process group or individual process
		if pgid, err := syscall.Getpgid(p.Pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			_ = p.Kill()
		}
		return nil
	}
}
