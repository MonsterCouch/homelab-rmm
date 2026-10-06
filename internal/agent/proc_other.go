//go:build !windows && !linux

package agent

import "os/exec"

// superviseCommand is the Windows job-object hook, called once a command has
// started. Everywhere else prepareCommand's process group already covers the
// whole descendant tree at cancellation time, so there is nothing to attach
// and nothing to release.
func superviseCommand(cmd *exec.Cmd) (release func()) { return func() {} }

// superviseSandboxedCommand is a stub on non-Windows/non-Linux platforms where
// resource quotas are not supported. It returns an empty release func.
func superviseSandboxedCommand(cmd *exec.Cmd, maxMemMB uint64, cpuPercent uint32) (release func()) {
	return func() {}
}
