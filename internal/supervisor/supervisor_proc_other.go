//go:build !windows && !linux

package supervisor

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
)

// configureWorkerProc is the fallback for other POSIX platforms.
func configureWorkerProc(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// terminateWorkerProcess ends the worker process on other POSIX platforms.
func terminateWorkerProcess(p *os.Process) error {
	if p == nil {
		return nil
	}
	return p.Kill()
}

// ListenIPC is a fallback stub on other platforms for compilation compatibility.
func ListenIPC(path, sddl string) (net.Listener, error) {
	return nil, errors.New("native IPC is only supported on Windows and Linux")
}
