//go:build windows

package agent

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
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

// TestSuperviseSandboxedCommandUnstarted covers the degenerate case for the sandboxed supervisor.
func TestSuperviseSandboxedCommandUnstarted(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "does-not-exist")
	prepareCommand(cmd)
	release := superviseSandboxedCommand(cmd, 512, 50)
	if release == nil {
		t.Fatal("release must never be nil")
	}
	if jobFor(cmd) != nil {
		t.Error("an unstarted command must not be registered in cmdJobs")
	}
	release()
	release() // idempotent
}

// TestSandboxedJobCreation verifies that newSandboxedJob creates a job object with limits
// and successfully attaches a live child process.
func TestSandboxedJobCreation(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "cmd.exe", "/c", "timeout /t 5 >nul")
	prepareCommand(cmd)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	release := superviseSandboxedCommand(cmd, 1024, 80)
	if release == nil {
		t.Fatal("superviseSandboxedCommand returned nil release")
	}
	j := jobFor(cmd)
	if j == nil {
		t.Fatal("supervised command not found in cmdJobs")
	}
	if j.handle == 0 {
		t.Fatal("sandboxed job object handle is zero")
	}
	release()
	if jobFor(cmd) != nil {
		t.Error("command should be unregistered from cmdJobs after release")
	}
}

// TestJobObjectNormalExecution tests that a normal script allocating a modest amount
// of memory (10 MB) completes successfully with exit code 0 under the Job Object.
func TestJobObjectNormalExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping process execution test in short mode")
	}
	ps, err := powershellScriptExe()
	if err != nil {
		t.Skip("powershell not available on this machine:", err)
	}

	cmd := exec.CommandContext(context.Background(), ps,
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"[byte[]]$buf = New-Object byte[] 10485760; Write-Output 'ALLOC_10MB_OK'")
	prepareCommand(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	release := superviseSandboxedCommand(cmd, 1024, 80)
	defer release()

	if err := cmd.Wait(); err != nil {
		t.Fatalf("command failed under normal quota: %v (stderr: %q)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ALLOC_10MB_OK") {
		t.Errorf("stdout = %q, want ALLOC_10MB_OK", stdout.String())
	}
}

// TestJobObjectMemoryQuotaViolationDefault tests that a script attempting to allocate
// >1.5 GB RAM (under default 1024 MB limit) is terminated by the Job Object without
// affecting the host or agent process.
func TestJobObjectMemoryQuotaViolationDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory quota test in short mode")
	}
	ps, err := powershellScriptExe()
	if err != nil {
		t.Skip("powershell not available on this machine:", err)
	}

	// 20 iterations * 100 MB = 2000 MB (>1.5 GB).
	script := `$ErrorActionPreference = 'Stop'; $list = New-Object System.Collections.Generic.List[byte[]]; for ($i = 0; $i -lt 20; $i++) { $list.Add((New-Object byte[] 104857600)) }; Write-Output 'SURVIVED_ALLOC'`

	cmd := exec.CommandContext(context.Background(), ps,
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	prepareCommand(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	release := superviseSandboxedCommand(cmd, 0, 0) // default 1024 MB
	defer release()

	err = cmd.Wait()
	if err == nil {
		t.Fatal("expected script allocating >1.5 GB under 1024 MB ceiling to fail, but it exited 0")
	}
	if strings.Contains(stdout.String(), "SURVIVED_ALLOC") {
		t.Errorf("script survived memory quota violation: stdout=%q", stdout.String())
	}
	t.Logf("Process terminated as expected: err=%v, stderr=%q", err, stderr.String())
}

// TestJobObjectMemoryQuotaViolationCustom tests that a script with MaxMemoryMB = 100
// attempting to allocate 200 MB fails with a quota error.
func TestJobObjectMemoryQuotaViolationCustom(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory quota test in short mode")
	}
	ps, err := powershellScriptExe()
	if err != nil {
		t.Skip("powershell not available on this machine:", err)
	}

	// 200 MB byte array under a 100 MB ceiling.
	script := `$ErrorActionPreference = 'Stop'; $buf = New-Object byte[] 209715200; Write-Output 'SURVIVED_CUSTOM_ALLOC'`

	cmd := exec.CommandContext(context.Background(), ps,
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	prepareCommand(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	release := superviseSandboxedCommand(cmd, 100, 80) // 100 MB ceiling
	defer release()

	err = cmd.Wait()
	if err == nil {
		t.Fatal("expected script allocating 200 MB under 100 MB ceiling to fail, but it exited 0")
	}
	if strings.Contains(stdout.String(), "SURVIVED_CUSTOM_ALLOC") {
		t.Errorf("script survived custom memory quota violation: stdout=%q", stdout.String())
	}
	t.Logf("Custom quota terminated as expected: err=%v, stderr=%q", err, stderr.String())
}

// TestJobObjectCPURateControlConfiguration verifies the Job Object is properly configured
// with rate control without errors, and verifies the configuration via QueryInformationJobObject.
func TestJobObjectCPURateControlConfiguration(t *testing.T) {
	hJob, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Skipf("CreateJobObject: %v", err)
	}
	defer windows.CloseHandle(hJob)

	cases := []struct {
		name         string
		inputPercent uint32
		wantRate     uint32
	}{
		{"Default80", 0, 8000},
		{"Custom50", 50, 5000},
		{"Custom20", 20, 2000},
		{"Cap100", 100, 10000},
		{"Above100Capped", 150, 10000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rate := tc.inputPercent * 100
			if tc.inputPercent == 0 {
				rate = defaultCPULimitPercent * 100
			} else if tc.inputPercent > 100 {
				rate = 10000
			}

			cpuInfo := jobObjectCPURateControlInformation{
				ControlFlags: jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
				CpuRate:      rate,
			}
			_, err := windows.SetInformationJobObject(
				hJob,
				windows.JobObjectCpuRateControlInformation,
				uintptr(unsafe.Pointer(&cpuInfo)),
				uint32(unsafe.Sizeof(cpuInfo)),
			)
			if err != nil {
				t.Fatalf("SetInformationJobObject(CpuRateControl): %v", err)
			}

			var queried jobObjectCPURateControlInformation
			var retLen uint32
			err = windows.QueryInformationJobObject(
				hJob,
				windows.JobObjectCpuRateControlInformation,
				uintptr(unsafe.Pointer(&queried)),
				uint32(unsafe.Sizeof(queried)),
				&retLen,
			)
			if err != nil {
				t.Fatalf("QueryInformationJobObject(CpuRateControl): %v", err)
			}
			wantFlags := jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap
			if queried.ControlFlags != wantFlags {
				t.Errorf("ControlFlags = 0x%X, want 0x%X", queried.ControlFlags, wantFlags)
			}
			if queried.CpuRate != tc.wantRate {
				t.Errorf("CpuRate = %d, want %d", queried.CpuRate, tc.wantRate)
			}
		})
	}
}

// TestJobObjectExtendedMemoryLimitsQuery confirms memory limits configured in
// JOBOBJECT_EXTENDED_LIMIT_INFORMATION match the queried values.
func TestJobObjectExtendedMemoryLimitsQuery(t *testing.T) {
	hJob, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Skipf("CreateJobObject: %v", err)
	}
	defer windows.CloseHandle(hJob)

	memMB := uint64(256)
	memBytes := uintptr(memMB * 1024 * 1024)

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
		windows.JOB_OBJECT_LIMIT_JOB_MEMORY
	info.ProcessMemoryLimit = memBytes
	info.JobMemoryLimit = memBytes

	if _, err := windows.SetInformationJobObject(
		hJob,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		t.Fatalf("SetInformationJobObject(ExtendedLimit): %v", err)
	}

	var queried windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var retLen uint32
	if err := windows.QueryInformationJobObject(
		hJob,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&queried)),
		uint32(unsafe.Sizeof(queried)),
		&retLen,
	); err != nil {
		t.Fatalf("QueryInformationJobObject(ExtendedLimit): %v", err)
	}
	wantFlags := uint32(windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_JOB_MEMORY)
	if queried.BasicLimitInformation.LimitFlags != wantFlags {
		t.Errorf("LimitFlags = 0x%X, want 0x%X", queried.BasicLimitInformation.LimitFlags, wantFlags)
	}
	if queried.ProcessMemoryLimit != memBytes {
		t.Errorf("ProcessMemoryLimit = %d, want %d", queried.ProcessMemoryLimit, memBytes)
	}
	if queried.JobMemoryLimit != memBytes {
		t.Errorf("JobMemoryLimit = %d, want %d", queried.JobMemoryLimit, memBytes)
	}
}

// TestScriptRunnerEnforcesQuotas tests end-to-end script execution through
// scriptRunner with custom memory quota and normal execution.
func TestScriptRunnerEnforcesQuotas(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if _, err := powershellScriptExe(); err != nil {
		t.Skip("powershell not available on this machine:", err)
	}

	runner := newScriptRunner()

	// 1. Normal run: 10 MB allocation with 1024 MB quota should succeed
	normalReq := protocol.ScriptRun{
		RunID:           "test-normal-quota",
		Language:        "powershell",
		Body:            "[byte[]]$buf = New-Object byte[] 10485760; Write-Output 'RUNNER_10MB_OK'",
		Timeout:         30,
		MaxMemoryMB:     1024,
		CPULimitPercent: 80,
	}
	res := runner.run(context.Background(), normalReq, func(protocol.ScriptChunk) {})
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "RUNNER_10MB_OK") {
		t.Errorf("normal run failed: exit=%d, stdout=%q, stderr=%q, err=%q",
			res.ExitCode, res.Stdout, res.Stderr, res.Error)
	}

	// 2. Quota violation run: 200 MB allocation with 100 MB quota should fail
	violationReq := protocol.ScriptRun{
		RunID:           "test-violation-quota",
		Language:        "powershell",
		Body:            "$ErrorActionPreference = 'Stop'; $buf = New-Object byte[] 209715200; Write-Output 'RUNNER_SURVIVED_ALLOC'",
		Timeout:         30,
		MaxMemoryMB:     100,
		CPULimitPercent: 80,
	}
	resViol := runner.run(context.Background(), violationReq, func(protocol.ScriptChunk) {})
	if resViol.ExitCode == 0 || strings.Contains(resViol.Stdout, "RUNNER_SURVIVED_ALLOC") {
		t.Errorf("quota violation run should have failed: exit=%d, stdout=%q",
			resViol.ExitCode, resViol.Stdout)
	}
}
