//go:build !windows

package supervisor

import (
	"syscall"
)

func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}
