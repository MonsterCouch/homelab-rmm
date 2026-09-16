//go:build windows

package agent

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestPrepareCommandDefaults pins the half of F078 that is pure bookkeeping:
// proc_linux.go has always given every child a default WaitDelay so an
// escaped descendant holding our pipes cannot block Wait for ever, and the
// Windows side must match. The creation flags matter too - a child without
// its own process group takes console signals meant for the agent.
func TestPrepareCommandDefaults(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "does-not-need-to-exist")
	prepareCommand(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.HideWindow {
		t.Error("HideWindow not set")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NEW_PROCESS_GROUP == 0 {
		t.Error("CREATE_NEW_PROCESS_GROUP not set")
	}
	if cmd.Cancel == nil {
		t.Error("Cancel not set: a timed-out command would leave its tree running")
	}
	if cmd.WaitDelay != 5*time.Second {
		t.Errorf("WaitDelay = %v, want 5s (proc_linux.go's default)", cmd.WaitDelay)
	}
	// A caller that wants a different bound keeps it (exec_windows.go asks
	// for 10 s after prepareCommand has run).
	cmd2 := exec.CommandContext(context.Background(), "x")
	cmd2.WaitDelay = time.Minute
	prepareCommand(cmd2)
	if cmd2.WaitDelay != time.Minute {
		t.Errorf("explicit WaitDelay overwritten: %v", cmd2.WaitDelay)
	}
}

// TestSuperviseCommandUnstarted covers the degenerate paths: no process to
// put in a job, and a job that was never created. Both must leave cancellation
// on the taskkill fallback rather than claim the tree is gone.
func TestSuperviseCommandUnstarted(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "x")
	prepareCommand(cmd)
	release := superviseCommand(cmd) // never started: cmd.Process is nil
	if release == nil {
		t.Fatal("release must never be nil")
	}
	if jobFor(cmd) != nil {
		t.Error("an unstarted command must not be registered")
	}
	release()
	release() // idempotent
}

// TestKillJobLifecycle checks the job wrapper's bookkeeping without creating
// a real job: terminate reports failure when there is nothing to terminate
// (so cmd.Cancel falls through to taskkill), and both operations are safe on
// a nil receiver and safe to repeat.
func TestKillJobLifecycle(t *testing.T) {
	var nilJob *killJob
	if nilJob.terminate() {
		t.Error("a nil job must not claim it killed anything")
	}
	nilJob.release()

	j := &killJob{}
	if j.terminate() {
		t.Error("a job with no handle must not claim it killed anything")
	}
	j.release()
	j.release()

	// A real job object, with nothing in it: terminating it succeeds and is
	// then unrepeatable, which is what stops Cancel and the deferred release
	// from closing the same handle twice.
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Skipf("CreateJobObject: %v", err)
	}
	j = &killJob{handle: h}
	if !j.terminate() {
		t.Error("terminating an empty job should succeed")
	}
	if j.terminate() {
		t.Error("second terminate must report nothing to do")
	}
	j.release() // must not close the handle again

	// Releasing instead of terminating clears the kill-on-close limit and
	// closes the handle, and leaves nothing to terminate afterwards. (The job
	// is empty on purpose: putting this process in a kill-on-close job would
	// make a bug in release fatal to the test run rather than visible.)
	h, err = windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Skipf("CreateJobObject: %v", err)
	}
	j = &killJob{handle: h}
	j.release()
	if j.terminate() {
		t.Error("a released job must not be terminated afterwards")
	}
}
