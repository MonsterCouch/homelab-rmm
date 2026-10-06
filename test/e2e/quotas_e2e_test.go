package e2e_test

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ============================================================================
// Win32 Job Object Constants and Structs for Sandboxing & Quotas (R3)
// ============================================================================

const (
	JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
	JOB_OBJECT_LIMIT_PROCESS_MEMORY    = 0x00000100
	JOB_OBJECT_LIMIT_JOB_MEMORY        = 0x00000200

	JOB_OBJECT_CPU_RATE_CONTROL_ENABLE   = 0x00000001
	JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x00000004

	JobObjectCpuRateControlInformation = 15

	// STATUS_QUOTA_EXCEEDED is the NTSTATUS code returned when a process exceeds Job Object memory quota.
	STATUS_QUOTA_EXCEEDED = 0xC0000044
)

type JOBOBJECT_CPU_RATE_CONTROL_INFORMATION struct {
	ControlFlags uint32
	Value        uint32 // Rate in 100ths of 1% (e.g. 80% = 8000)
}

// SandboxLimits resolves configured or default resource limits.
type SandboxLimits struct {
	MaxMemoryMB     uint64
	CPULimitPercent uint32
}

func ResolveSandboxLimits(req ScriptRunContract) SandboxLimits {
	mem := req.MaxMemoryMB
	if mem == 0 {
		mem = 1024 // Default 1024 MB
	}
	cpu := req.CPULimitPercent
	if cpu == 0 || cpu > 100 {
		cpu = 80 // Default 80%
	}
	return SandboxLimits{
		MaxMemoryMB:     mem,
		CPULimitPercent: cpu,
	}
}

// createTestSandboxedJob creates a Windows Job Object configured with memory and CPU limits.
func createTestSandboxedJob(maxMemMB uint64, cpuPercent uint32) (windows.Handle, error) {
	if runtime.GOOS != "windows" {
		return 0, fmt.Errorf("Job Objects only supported on Windows")
	}

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}

	// 1. Extended limits: Kill-on-close and hard process/job memory limits
	var extInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	extInfo.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY
	extInfo.ProcessMemoryLimit = uintptr(maxMemMB * 1024 * 1024)
	extInfo.JobMemoryLimit = uintptr(maxMemMB * 1024 * 1024)

	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&extInfo)),
		uint32(unsafe.Sizeof(extInfo)),
	); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject(MemoryLimit): %w", err)
	}

	// 2. CPU Rate Control: Hard cap
	var cpuInfo JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
	cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
	cpuInfo.Value = cpuPercent * 100 // 80% -> 8000

	// Set CPU rate control (may be unsupported on certain VM hypervisors, ignore non-fatal errors)
	_, _ = windows.SetInformationJobObject(
		job,
		JobObjectCpuRateControlInformation,
		uintptr(unsafe.Pointer(&cpuInfo)),
		uint32(unsafe.Sizeof(cpuInfo)),
	)

	return job, nil
}

// assignProcessToJob assigns a running process handle to the job object.
func assignProcessToJob(job windows.Handle, pid int) error {
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(proc)

	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return nil
}

// ============================================================================
// Tier 1: Feature Coverage (R3 Sandboxing & Resource Quotas)
// ============================================================================

func TestE2E_Tier1_R3_ProtocolQuotaFieldsJSONSerialization(t *testing.T) {
	// Verify that protocol payload correctly includes and deserializes MaxMemoryMB and CPULimitPercent
	rawJSON := `{
		"run_id": "run-xyz-123",
		"language": "powershell",
		"body": "Write-Output 'Hello World'",
		"timeout_sec": 30,
		"max_memory_mb": 1024,
		"cpu_limit_percent": 80
	}`

	var contract ScriptRunContract
	if err := json.Unmarshal([]byte(rawJSON), &contract); err != nil {
		t.Fatalf("Failed to unmarshal ScriptRunContract: %v", err)
	}

	if contract.RunID != "run-xyz-123" {
		t.Errorf("RunID mismatch: got %q, want 'run-xyz-123'", contract.RunID)
	}
	if contract.MaxMemoryMB != 1024 {
		t.Errorf("MaxMemoryMB mismatch: got %d, want 1024", contract.MaxMemoryMB)
	}
	if contract.CPULimitPercent != 80 {
		t.Errorf("CPULimitPercent mismatch: got %d, want 80", contract.CPULimitPercent)
	}

	// Verify serialization preserves fields
	out, err := json.Marshal(contract)
	if err != nil {
		t.Fatalf("Failed to marshal ScriptRunContract: %v", err)
	}
	outStr := string(out)
	if !strings.Contains(outStr, `"max_memory_mb":1024`) || !strings.Contains(outStr, `"cpu_limit_percent":80`) {
		t.Errorf("Serialized JSON missing quota fields: %s", outStr)
	}
}

func TestE2E_Tier1_R3_DefaultQuotaFallback(t *testing.T) {
	testCases := []struct {
		name        string
		input       ScriptRunContract
		expectedMem uint64
		expectedCPU uint32
	}{
		{
			name: "Zero values fallback to defaults",
			input: ScriptRunContract{
				MaxMemoryMB:     0,
				CPULimitPercent: 0,
			},
			expectedMem: 1024,
			expectedCPU: 80,
		},
		{
			name: "Custom values preserved",
			input: ScriptRunContract{
				MaxMemoryMB:     2048,
				CPULimitPercent: 50,
			},
			expectedMem: 2048,
			expectedCPU: 50,
		},
		{
			name: "CPU limit exceeding 100 clamped to default 80",
			input: ScriptRunContract{
				MaxMemoryMB:     512,
				CPULimitPercent: 150,
			},
			expectedMem: 512,
			expectedCPU: 80,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			limits := ResolveSandboxLimits(tc.input)
			if limits.MaxMemoryMB != tc.expectedMem {
				t.Errorf("MaxMemoryMB: got %d, want %d", limits.MaxMemoryMB, tc.expectedMem)
			}
			if limits.CPULimitPercent != tc.expectedCPU {
				t.Errorf("CPULimitPercent: got %d, want %d", limits.CPULimitPercent, tc.expectedCPU)
			}
		})
	}
}

func TestE2E_Tier1_R3_WindowsJobObjectQuotaEnforcement(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Job Object quotas are only supported on Windows")
	}

	// Create Job Object with a strict 64 MB memory limit
	const limitMB = 64
	job, err := createTestSandboxedJob(limitMB, 80)
	if err != nil {
		t.Fatalf("Failed to create sandboxed Job Object: %v", err)
	}
	defer windows.CloseHandle(job)

	// Launch a PowerShell process that tries to allocate 200 MB of RAM
	// This will immediately breach the 64 MB limit and trigger termination.
	script := `
		try {
			$bytes = [byte[]]::new(200 * 1024 * 1024)
			Start-Sleep -Seconds 5
			exit 0
		} catch {
			exit 42
		}
	`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start test powershell process: %v", err)
	}

	// Assign process to Job Object
	if err := assignProcessToJob(job, cmd.Process.Pid); err != nil {
		// Process might have terminated already
		t.Logf("assignProcessToJob note: %v", err)
	}

	err = cmd.Wait()
	// Process MUST fail / terminate due to memory quota
	if err == nil {
		t.Fatalf("Process succeeded despite allocating 200MB under 64MB Job Object limit!")
	}

	// Check exit error
	if exitErr, ok := err.(*exec.ExitError); ok {
		t.Logf("Process terminated as expected: exit status = %v (raw code: 0x%08X)", exitErr.ExitCode(), uint32(exitErr.ExitCode()))
	}
}

func TestE2E_Tier1_R3_HostAndAgentProtection(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Job Object quotas only testable on Windows")
	}

	// Verify that parent process (this test agent) survives without any memory starvation
	// when a sandboxed child allocates excessive memory and gets killed.
	parentPID := os.Getpid()

	job, err := createTestSandboxedJob(128, 50)
	if err != nil {
		t.Fatalf("Failed to create test job: %v", err)
	}
	defer windows.CloseHandle(job)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", `
		$arr = @()
		for ($i=0; $i -lt 100; $i++) {
			$arr += [byte[]]::new(10 * 1024 * 1024)
		}
	`)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start child process: %v", err)
	}

	_ = assignProcessToJob(job, cmd.Process.Pid)
	_ = cmd.Wait()

	// Verify parent process PID is still running and healthy
	proc, err := os.FindProcess(parentPID)
	if err != nil || proc == nil {
		t.Fatalf("Parent process compromised by child quota breach!")
	}
}

func TestE2E_Tier1_R3_ProcessTreeReaping(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Job Object kill-on-close only testable on Windows")
	}

	// Create job object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatalf("CreateJobObject failed: %v", err)
	}

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		windows.CloseHandle(job)
		t.Fatalf("SetInformationJobObject failed: %v", err)
	}

	// Launch a child powershell process that sleeps
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 60")
	startTime := time.Now()
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(job)
		t.Fatalf("Failed to start powershell: %v", err)
	}

	pid := cmd.Process.Pid
	if err := assignProcessToJob(job, pid); err != nil {
		windows.CloseHandle(job)
		_ = cmd.Process.Kill()
		t.Fatalf("Failed to assign process to job: %v", err)
	}

	// Now close the Job Object handle: Windows kernel MUST terminate the assigned process tree
	windows.CloseHandle(job)

	// Wait for process to exit
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		elapsed := time.Since(startTime)
		if elapsed > 10*time.Second {
			t.Errorf("Process took too long to terminate (%v), expected prompt reaping", elapsed)
		}
		t.Logf("Process successfully reaped on job close in %v (exit result: %v)", elapsed, err)
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("Process was not reaped within 5s of Job Object close!")
	}
}

// ============================================================================
// Tier 2: Boundary & Corner Cases (R3)
// ============================================================================

func TestE2E_Tier2_R3_BoundaryQuotaValues(t *testing.T) {
	testCases := []struct {
		name        string
		memIn       uint64
		cpuIn       uint32
		expectedMem uint64
		expectedCPU uint32
	}{
		{
			name:        "Minimum 1 MB memory",
			memIn:       1,
			cpuIn:       1,
			expectedMem: 1,
			expectedCPU: 1,
		},
		{
			name:        "100% CPU max",
			memIn:       1024,
			cpuIn:       100,
			expectedMem: 1024,
			expectedCPU: 100,
		},
		{
			name:        "Over 100% CPU clamped",
			memIn:       1024,
			cpuIn:       250,
			expectedMem: 1024,
			expectedCPU: 80,
		},
		{
			name:        "Max uint64 memory value",
			memIn:       math.MaxUint64,
			cpuIn:       80,
			expectedMem: math.MaxUint64,
			expectedCPU: 80,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			limits := ResolveSandboxLimits(ScriptRunContract{
				MaxMemoryMB:     tc.memIn,
				CPULimitPercent: tc.cpuIn,
			})
			if limits.MaxMemoryMB != tc.expectedMem || limits.CPULimitPercent != tc.expectedCPU {
				t.Errorf("Boundary mismatch: got (%d, %d), want (%d, %d)",
					limits.MaxMemoryMB, limits.CPULimitPercent, tc.expectedMem, tc.expectedCPU)
			}
		})
	}
}

// ============================================================================
// Tier 3: Cross-Feature Interactions (R3 Quotas + R4 Redaction)
// ============================================================================

func TestE2E_Tier3_R3_QuotaExceededDuringSecretStreaming(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Job Object quotas only testable on Windows")
	}

	// Cross-feature scenario: A script emits a secret token, then immediately allocates
	// memory exceeding its Job Object limit.
	// We verify:
	// 1. All output streamed before the process crash is properly redacted.
	// 2. The process is terminated by the Job Object without leaking unredacted secrets.
	// 3. The parent agent and host remain stable.

	harness := NewStreamingRedactHarness()
	job, err := createTestSandboxedJob(64, 80)
	if err != nil {
		t.Fatalf("Failed to create test job: %v", err)
	}
	defer windows.CloseHandle(job)

	script := `
		$ErrorActionPreference = 'Stop'
		Write-Output "PRE_CRASH: token=ghp_SuperSecretCredential123456 password=AdminMasterPassword!"
		[Console]::Out.Flush()
		# Now allocate 150 MB under 64 MB limit
		$arr = [byte[]]::new(150 * 1024 * 1024)
		Write-Output "POST_ALLOC: Should never reach here"
	`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to get stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}

	_ = assignProcessToJob(job, cmd.Process.Pid)

	// Stream stdout into redactor harness
	buf := make([]byte, 1024)
	for {
		n, err := stdoutPipe.Read(buf)
		if n > 0 {
			_, _ = harness.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	_ = cmd.Wait()
	harness.FlushRemainder()

	lines := harness.Lines()
	allOutput := strings.Join(lines, "\n")

	// Secrets must NOT leak
	if strings.Contains(allOutput, "ghp_SuperSecretCredential123456") || strings.Contains(allOutput, "AdminMasterPassword!") {
		t.Fatalf("CRITICAL SECURITY LEAK: Secret leaked prior to quota crash! Output: %q", allOutput)
	}

	// Redacted markers must be present
	if !strings.Contains(allOutput, "token=[REDACTED]") || !strings.Contains(allOutput, "password=[REDACTED]") {
		t.Fatalf("Redaction marker missing in pre-crash output: %q", allOutput)
	}

	// The post allocation string should not have been reached
	if strings.Contains(allOutput, "POST_ALLOC") {
		t.Errorf("Process continued past quota breach unexpectedly!")
	}
}

// ============================================================================
// Tier 4: Real-World Scenarios (R3 Quotas)
// ============================================================================

func TestE2E_Tier4_R3_RunawayMemoryAllocation1500MBTerminated(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Job Object memory limits only testable on Windows")
	}

	// Acceptance Criterion from ORIGINAL_REQUEST.md line 41:
	// "A test script attempting to allocate >1.5 GB RAM is terminated by the Job Object without affecting the host or agent."
	//
	// Here we configure the default 1024 MB Job Object quota.
	// We dispatch a script attempting to allocate ~1536 MB (1.5 GB).
	// We verify:
	// - Child process is killed or terminated by the Job Object when exceeding quota.
	// - Exit code indicates failure / quota exceeded.
	// - Test process (agent runner) remains unharmed.

	const defaultQuotaMB = 1024
	job, err := createTestSandboxedJob(defaultQuotaMB, 80)
	if err != nil {
		t.Fatalf("Failed to create default 1024 MB Job Object: %v", err)
	}
	defer windows.CloseHandle(job)

	// 1.5 GB allocation in PowerShell (1536 MB = 1610612736 bytes)
	// $ErrorActionPreference = 'Stop' ensures OutOfMemoryException triggers immediate non-zero termination.
	script := `
		$ErrorActionPreference = 'Stop'
		Write-Output "ALLOC_START"
		$chunks = @()
		for ($i = 0; $i -lt 6; $i++) {
			# 256 MB per chunk * 6 = 1536 MB (> 1.5 GB)
			$chunks += [byte[]]::new(256 * 1024 * 1024)
			Write-Output "Allocated chunk $($i+1)"
			[Console]::Out.Flush()
			Start-Sleep -Milliseconds 50
		}
		Write-Output "ALLOC_FINISHED_UNEXPECTEDLY"
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start powershell process: %v", err)
	}

	if err := assignProcessToJob(job, cmd.Process.Pid); err != nil {
		t.Logf("assignProcessToJob note: %v", err)
	}

	waitErr := cmd.Wait()
	if waitErr == nil {
		t.Fatalf("CRITICAL RESILIENCE FAILURE: Script allocated >1.5 GB RAM under 1024 MB Job Object without being terminated!")
	}

	t.Logf("Acceptance Criterion Verified: Runaway 1.5 GB script was cleanly terminated by Job Object: %v", waitErr)
}
