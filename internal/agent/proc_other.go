//go:build !windows

package agent

import "os/exec"

// superviseCommand is the Windows job-object hook, called once a command has
// started. Everywhere else prepareCommand's process group already covers the
// whole descendant tree at cancellation time, so there is nothing to attach
// and nothing to release.
func superviseCommand(cmd *exec.Cmd) (release func()) { return func() {} }
