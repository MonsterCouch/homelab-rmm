//go:build linux

package agent

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// prepareCommand puts the child in its own process group and makes context
// cancellation kill that whole group, so a timed-out script cannot leave
// grandchildren holding our stdout pipe (or running) behind it.
func prepareCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid addresses the group. The child is its leader thanks to
		// Setpgid, so this reaches everything it spawned that did not setsid.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return cmd.Process.Kill()
		}
		return nil
	}
	// A grandchild that escaped the group via setsid could still hold the
	// pipes open; give up on it rather than hang Wait forever.
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = 5 * time.Second
	}
}
