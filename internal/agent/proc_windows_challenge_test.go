//go:build windows

package agent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"golang.org/x/sys/windows"
)

var (
	kernel32Challenge   = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessInJob = kernel32Challenge.NewProc("IsProcessInJob")
)

func isProcessInJob(hProcess, hJob windows.Handle) (bool, error) {
	var inJob int32
	r1, _, err := procIsProcessInJob.Call(
		uintptr(hProcess),
		uintptr(hJob),
		uintptr(unsafe.Pointer(&inJob)),
	)
	if r1 == 0 {
		return false, err
	}
	return inJob != 0, nil
}

// TestChallengeJobObjectRateControlAndMemoryQueries empirically calls newSandboxedJob
// on a live process and queries the actual Win32 Job Object information returned.
func TestChallengeJobObjectRateControlAndMemoryQueries(t *testing.T) {
	cases := []struct {
		name          string
		inputMemMB    uint64
		inputCPU      uint32
		wantMemBytes  uintptr
		wantCpuRate   uint32
		wantFlags     uint32
	}{
		{
			name:         "DefaultQuotas_0_0",
			inputMemMB:   0,
			inputCPU:     0,
			wantMemBytes: uintptr(1024 * 1024 * 1024), // 1024 MB
			wantCpuRate:  8000,                       // 80%
			wantFlags:    jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
		},
		{
			name:         "Custom_256MB_50CPU",
			inputMemMB:   256,
			inputCPU:     50,
			wantMemBytes: uintptr(256 * 1024 * 1024),
			wantCpuRate:  5000,
			wantFlags:    jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
		},
		{
			name:         "Boundary_1MB_100CPU",
			inputMemMB:   1,
			inputCPU:     100,
			wantMemBytes: uintptr(1 * 1024 * 1024),
			wantCpuRate:  10000,
			wantFlags:    jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
		},
		{
			name:         "Clamping_512MB_150CPU",
			inputMemMB:   512,
			inputCPU:     150,
			wantMemBytes: uintptr(512 * 1024 * 1024),
			wantCpuRate:  10000, // Clamped to 100%
			wantFlags:    jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
		},
		{
			name:         "Boundary_2048MB_1CPU",
			inputMemMB:   2048,
			inputCPU:     1,
			wantMemBytes: uintptr(2048 * 1024 * 1024),
			wantCpuRate:  100, // 1%
			wantFlags:    jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Spawn a temporary sleep process to attach
			cmd := exec.CommandContext(context.Background(), "cmd.exe", "/c", "ping -n 10 127.0.0.1 >nul")
			prepareCommand(cmd)
			if err := cmd.Start(); err != nil {
				t.Fatalf("failed to start dummy process: %v", err)
			}
			defer func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}()

			hJob, err := newSandboxedJob(cmd.Process.Pid, tc.inputMemMB, tc.inputCPU)
			if err != nil {
				t.Fatalf("newSandboxedJob(%d, %d, %d) failed: %v", cmd.Process.Pid, tc.inputMemMB, tc.inputCPU, err)
			}
			defer windows.CloseHandle(hJob)

			// 1. Query CPU rate control
			var cpuInfo jobObjectCPURateControlInformation
			var retLen uint32
			err = windows.QueryInformationJobObject(
				hJob,
				windows.JobObjectCpuRateControlInformation,
				uintptr(unsafe.Pointer(&cpuInfo)),
				uint32(unsafe.Sizeof(cpuInfo)),
				&retLen,
			)
			if err != nil {
				t.Fatalf("QueryInformationJobObject(CpuRateControl): %v", err)
			}
			if cpuInfo.ControlFlags != tc.wantFlags {
				t.Errorf("ControlFlags = 0x%X, want 0x%X", cpuInfo.ControlFlags, tc.wantFlags)
			}
			if cpuInfo.CpuRate != tc.wantCpuRate {
				t.Errorf("CpuRate = %d, want %d", cpuInfo.CpuRate, tc.wantCpuRate)
			}

			// 2. Query Extended Limits (Memory)
			var extInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
			err = windows.QueryInformationJobObject(
				hJob,
				windows.JobObjectExtendedLimitInformation,
				uintptr(unsafe.Pointer(&extInfo)),
				uint32(unsafe.Sizeof(extInfo)),
				&retLen,
			)
			if err != nil {
				t.Fatalf("QueryInformationJobObject(ExtendedLimit): %v", err)
			}
			wantLimitFlags := uint32(windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
				windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
				windows.JOB_OBJECT_LIMIT_JOB_MEMORY)
			if extInfo.BasicLimitInformation.LimitFlags != wantLimitFlags {
				t.Errorf("LimitFlags = 0x%X, want 0x%X", extInfo.BasicLimitInformation.LimitFlags, wantLimitFlags)
			}
			if extInfo.ProcessMemoryLimit != tc.wantMemBytes {
				t.Errorf("ProcessMemoryLimit = %d, want %d", extInfo.ProcessMemoryLimit, tc.wantMemBytes)
			}
			if extInfo.JobMemoryLimit != tc.wantMemBytes {
				t.Errorf("JobMemoryLimit = %d, want %d", extInfo.JobMemoryLimit, tc.wantMemBytes)
			}
		})
	}
}

// TestChallengeBoundaryInputsExecution stress-tests script execution under boundary conditions:
// 0 MB (default), 1 MB ceiling, 0% CPU (default 80%), 100% CPU, and >100% CPU.
func TestChallengeBoundaryInputsExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if _, err := powershellScriptExe(); err != nil {
		t.Skip("powershell not available on this machine:", err)
	}

	runner := newScriptRunner()

	// 1. Boundary: 0% CPU, 0 MB memory (defaults 80% CPU, 1024 MB RAM)
	t.Run("Boundary_Default_0MB_0CPU", func(t *testing.T) {
		req := protocol.ScriptRun{
			RunID:           "test-boundary-default",
			Language:        "powershell",
			Body:            "$sum = 0; for ($i=0; $i -lt 10000; $i++) { $sum += $i }; Write-Output \"SUM=$sum\"",
			Timeout:         15,
			MaxMemoryMB:     0,
			CPULimitPercent: 0,
		}
		res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "SUM=49995000") {
			t.Errorf("expected success with default 0/0: exit=%d, stdout=%q, err=%q", res.ExitCode, res.Stdout, res.Error)
		}
	})

	// 2. Boundary: 100% CPU
	t.Run("Boundary_100_CPU", func(t *testing.T) {
		req := protocol.ScriptRun{
			RunID:           "test-boundary-100cpu",
			Language:        "powershell",
			Body:            "Write-Output '100_PERCENT_CPU_OK'",
			Timeout:         15,
			MaxMemoryMB:     512,
			CPULimitPercent: 100,
		}
		res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "100_PERCENT_CPU_OK") {
			t.Errorf("expected success with 100%% CPU: exit=%d, stdout=%q, err=%q", res.ExitCode, res.Stdout, res.Error)
		}
	})

	// 3. Boundary: >100% CPU (e.g. 150%) clamped to 100%
	t.Run("Boundary_150_CPU_Clamped", func(t *testing.T) {
		req := protocol.ScriptRun{
			RunID:           "test-boundary-150cpu",
			Language:        "powershell",
			Body:            "Write-Output 'CLAMPED_CPU_OK'",
			Timeout:         15,
			MaxMemoryMB:     512,
			CPULimitPercent: 150,
		}
		res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "CLAMPED_CPU_OK") {
			t.Errorf("expected success with clamped 150%% CPU: exit=%d, stdout=%q, err=%q", res.ExitCode, res.Stdout, res.Error)
		}
	})

	// 4. Boundary: 1 MB memory limit
	// PowerShell consumes ~25-40 MB on startup. Under 1 MB ceiling, it should either
	// fail to allocate during CLR startup or terminate gracefully with exit code != 0.
	t.Run("Boundary_1MB_MemoryCeiling", func(t *testing.T) {
		req := protocol.ScriptRun{
			RunID:           "test-boundary-1mb",
			Language:        "powershell",
			Body:            "Write-Output 'SHOULD_NOT_SUCCEED'",
			Timeout:         15,
			MaxMemoryMB:     1,
			CPULimitPercent: 80,
		}
		res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
		t.Logf("1MB script result: exit=%d, stdout=%q, stderr=%q, err=%q",
			res.ExitCode, res.Stdout, res.Stderr, res.Error)
		// It must not succeed with normal output, or if it ran, it failed quota
		if res.ExitCode == 0 && strings.Contains(res.Stdout, "SHOULD_NOT_SUCCEED") {
			t.Errorf("expected 1MB limit to restrict powershell execution, but it succeeded")
		}
	})
}

// TestChallengeProcessTreeCleanupOnJobClose tests that when a parent process spawns
// child/grandchild processes and is assigned to newSandboxedJob, closing the job handle
// (with KILL_ON_JOB_CLOSE) terminates the entire process tree.
func TestChallengeProcessTreeCleanupOnJobClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping process tree test in short mode")
	}

	ps, err := powershellScriptExe()
	if err != nil {
		t.Skip("powershell not available:", err)
	}

	// The script will spawn a background sleep process and print its PID to stdout,
	// then sleep itself.
	script := `$child = Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -ArgumentList "-NoProfile -NonInteractive -Command Start-Sleep 100" -PassThru; Write-Output "CHILD_PID=$($child.Id)"; Start-Sleep 100`

	cmd := exec.CommandContext(context.Background(), ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	prepareCommand(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	parentPID := cmd.Process.Pid

	// Put parent in sandboxed job
	hJob, err := newSandboxedJob(parentPID, 512, 80)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("newSandboxedJob failed: %v", err)
	}

	// Wait for stdout to contain CHILD_PID=<pid>
	var childPID int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		out := stdout.String()
		if strings.Contains(out, "CHILD_PID=") {
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "CHILD_PID=") {
					pidStr := strings.TrimPrefix(line, "CHILD_PID=")
					if p, err := strconv.Atoi(pidStr); err == nil && p > 0 {
						childPID = p
						break
					}
				}
			}
			if childPID > 0 {
				break
			}
		}
	}

	if childPID == 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		windows.CloseHandle(hJob)
		t.Fatalf("did not receive child PID in time; stdout=%q, stderr=%q", stdout.String(), stderr.String())
	}
	t.Logf("Parent PID: %d, Child PID: %d", parentPID, childPID)

	// Verify both processes are alive and in the job
	hParent, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(parentPID))
	if err != nil {
		t.Fatalf("failed to open parent process: %v", err)
	}
	defer windows.CloseHandle(hParent)

	hChild, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(childPID))
	if err != nil {
		t.Fatalf("failed to open child process: %v", err)
	}
	defer windows.CloseHandle(hChild)

	// Check if child is in the job object
	inJob, err := isProcessInJob(hChild, hJob)
	if err != nil {
		t.Logf("isProcessInJob check failed: %v", err)
	} else {
		t.Logf("Child PID %d in Job Object: %v", childPID, inJob)
		if !inJob {
			t.Errorf("expected child process %d to inherit job object", childPID)
		}
	}

	// Close the job handle. With JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, the kernel must terminate
	// all processes in the job!
	t.Log("Closing job handle to trigger KILL_ON_JOB_CLOSE...")
	if err := windows.CloseHandle(hJob); err != nil {
		t.Fatalf("windows.CloseHandle(hJob) failed: %v", err)
	}

	// Wait up to 5 seconds for both parent and child to be terminated
	checkTerminated := func(h windows.Handle, name string, pid int) bool {
		event, err := windows.WaitForSingleObject(h, 5000)
		if err != nil {
			t.Errorf("WaitForSingleObject(%s %d) error: %v", name, pid, err)
			return false
		}
		if event == windows.WAIT_OBJECT_0 {
			var exitCode uint32
			_ = windows.GetExitCodeProcess(h, &exitCode)
			t.Logf("%s (PID %d) terminated successfully, exitCode=%d", name, pid, exitCode)
			return true
		}
		t.Errorf("%s (PID %d) did not terminate within 5s after job close (event=%v)", name, pid, event)
		return false
	}

	parentDead := checkTerminated(hParent, "Parent", parentPID)
	childDead := checkTerminated(hChild, "Child", childPID)

	_ = cmd.Wait()

	if !parentDead || !childDead {
		// Cleanup if failed
		_ = killPIDTree(parentPID)
		_ = killPIDTree(childPID)
		t.Fatalf("Process tree cleanup failed: parentDead=%v, childDead=%v", parentDead, childDead)
	}
}

// TestChallengeConPTYInteractiveShellIntegration tests that ConPTY interactive shells
// (startPTY) initialize, process commands, and close cleanly with their kill-on-close job object.
func TestChallengeConPTYInteractiveShellIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ConPTY test in short mode")
	}

	session, err := startPTY("cmd", 80, 24)
	if err != nil {
		t.Skipf("ConPTY not available or startPTY failed: %v", err)
	}
	defer session.Close()

	cs, ok := session.(*conptySession)
	if !ok {
		t.Fatalf("session is not *conptySession: %T", session)
	}
	if cs.pid <= 0 {
		t.Errorf("conptySession pid is invalid: %d", cs.pid)
	}
	if cs.job == 0 {
		t.Logf("conptySession job handle is 0 (job object creation fallback)")
	} else {
		t.Logf("conptySession running with Job Handle 0x%X for PID %d", cs.job, cs.pid)

		// Verify job has KILL_ON_JOB_CLOSE set
		var extInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		var retLen uint32
		err = windows.QueryInformationJobObject(
			cs.job,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&extInfo)),
			uint32(unsafe.Sizeof(extInfo)),
			&retLen,
		)
		if err != nil {
			t.Errorf("QueryInformationJobObject on ConPTY job failed: %v", err)
		} else {
			if extInfo.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
				t.Errorf("ConPTY job lacks JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag: 0x%X",
					extInfo.BasicLimitInformation.LimitFlags)
			}
		}
	}

	// Test writing to ConPTY and reading back output
	testMarker := "CONPTY_CHALLENGE_PING"
	input := fmt.Sprintf("echo %s\r\n", testMarker)
	if _, err := session.Write([]byte(input)); err != nil {
		t.Fatalf("session.Write failed: %v", err)
	}

	readCh := make(chan string, 50)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := session.Read(buf)
			if n > 0 {
				readCh <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	var readOutput string
	timeout := time.After(5 * time.Second)
readLoop1:
	for {
		select {
		case chunk := <-readCh:
			readOutput += chunk
			if strings.Contains(readOutput, testMarker) {
				break readLoop1
			}
		case <-timeout:
			break readLoop1
		}
	}

	if !strings.Contains(readOutput, testMarker) {
		t.Errorf("ConPTY did not echo expected output %q, got: %q", testMarker, readOutput)
	} else {
		t.Logf("ConPTY successfully processed command and output: matched %q", testMarker)
	}

	// Close session and verify shell process terminates
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(cs.pid))
	if err == nil {
		defer windows.CloseHandle(hProc)
	}

	if err := session.Close(); err != nil {
		t.Errorf("session.Close() failed: %v", err)
	}

	if hProc != 0 {
		event, err := windows.WaitForSingleObject(hProc, 5000)
		if err != nil {
			t.Errorf("WaitForSingleObject on ConPTY process failed: %v", err)
		} else if event != windows.WAIT_OBJECT_0 {
			t.Errorf("ConPTY shell process %d did not terminate within 5s after session.Close()", cs.pid)
		} else {
			t.Logf("ConPTY shell process %d terminated cleanly on Close()", cs.pid)
		}
	}
}

// TestChallengeConPTYChildProcessCleanup verifies that background child processes
// spawned within a ConPTY session are terminated when session.Close() closes the job object.
func TestChallengeConPTYChildProcessCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	session, err := startPTY("powershell", 80, 24)
	if err != nil {
		t.Skipf("ConPTY not available or startPTY failed: %v", err)
	}
	defer session.Close()

	cs, ok := session.(*conptySession)
	if !ok || cs.job == 0 {
		t.Skip("conptySession job object not available")
	}

	readCh := make(chan string, 50)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := session.Read(buf)
			if n > 0 {
				readCh <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Spawn background child process via powershell Start-Process
	cmdInput := "$c = Start-Process -FilePath powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -Command Start-Sleep 100' -PassThru; Write-Output ('CONPTY_BG_CHILD=' + $c.Id)\r\n"
	if _, err := session.Write([]byte(cmdInput)); err != nil {
		t.Fatalf("session.Write failed: %v", err)
	}

	var output string
	var bgChildPID int
	timeout := time.After(8 * time.Second)
readLoop2:
	for {
		select {
		case chunk := <-readCh:
			output += chunk
			re := regexp.MustCompile(`CONPTY_BG_CHILD=(\d+)`)
			if matches := re.FindAllStringSubmatch(output, -1); len(matches) > 0 {
				last := matches[len(matches)-1]
				if p, err := strconv.Atoi(last[1]); err == nil && p > 0 {
					bgChildPID = p
					break readLoop2
				}
			}
		case <-timeout:
			break readLoop2
		}
	}

	if bgChildPID == 0 {
		t.Skipf("Could not obtain background child PID from ConPTY output in time; output=%q", output)
	}
	t.Logf("ConPTY shell PID: %d, Background Child PID: %d", cs.pid, bgChildPID)

	hBgChild, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(bgChildPID))
	if err != nil {
		t.Fatalf("Failed to open background child process: %v", err)
	}
	defer windows.CloseHandle(hBgChild)

	// Close the ConPTY session
	t.Log("Closing ConPTY session...")
	if err := session.Close(); err != nil {
		t.Errorf("session.Close() failed: %v", err)
	}

	// Check if background child was killed by the job object
	event, err := windows.WaitForSingleObject(hBgChild, 5000)
	if err != nil {
		t.Errorf("WaitForSingleObject on background child failed: %v", err)
	} else if event != windows.WAIT_OBJECT_0 {
		_ = killPIDTree(bgChildPID)
		t.Fatalf("Background child %d survived ConPTY session closure!", bgChildPID)
	} else {
		t.Logf("CONFIRMED: Background child PID %d terminated when ConPTY job closed", bgChildPID)
	}
}

// TestChallengeSuperviseSandboxedCommandCancelOnContextTimeout tests that when a sandboxed
// command with child processes times out, cmd.Cancel() invokes jobFor(cmd).terminate()
// and reliably kills the entire process tree.
func TestChallengeSuperviseSandboxedCommandCancelOnContextTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ps, err := powershellScriptExe()
	if err != nil {
		t.Skip("powershell not available:", err)
	}

	// Context with short 2-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	script := `$child = Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -ArgumentList "-NoProfile -NonInteractive -Command Start-Sleep 100" -PassThru; Write-Output "TIMEOUT_CHILD_PID=$($child.Id)"; Start-Sleep 100`

	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	prepareCommand(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	parentPID := cmd.Process.Pid

	release := superviseSandboxedCommand(cmd, 512, 80)
	defer release()

	// Wait to capture child PID
	var childPID int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		out := stdout.String()
		if strings.Contains(out, "TIMEOUT_CHILD_PID=") {
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "TIMEOUT_CHILD_PID=") {
					pidStr := strings.TrimPrefix(line, "TIMEOUT_CHILD_PID=")
					if p, err := strconv.Atoi(pidStr); err == nil && p > 0 {
						childPID = p
						break
					}
				}
			}
			if childPID > 0 {
				break
			}
		}
	}

	if childPID == 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("failed to read child PID before timeout")
	}
	t.Logf("Timeout test: Parent PID: %d, Child PID: %d", parentPID, childPID)

	hChild, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(childPID))
	if err != nil {
		t.Fatalf("failed to open child process: %v", err)
	}
	defer windows.CloseHandle(hChild)

	// Wait for command to exit due to context timeout
	err = cmd.Wait()
	t.Logf("cmd.Wait returned: %v", err)

	// Check if child process was terminated by job termination
	event, err := windows.WaitForSingleObject(hChild, 5000)
	if err != nil {
		t.Errorf("WaitForSingleObject on child failed: %v", err)
	} else if event != windows.WAIT_OBJECT_0 {
		_ = killPIDTree(childPID)
		t.Fatalf("Child process %d survived context timeout / job termination!", childPID)
	} else {
		t.Logf("CONFIRMED: Child process %d terminated automatically on context timeout cancellation", childPID)
	}
}
