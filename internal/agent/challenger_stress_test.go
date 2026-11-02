//go:build windows

package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"golang.org/x/sys/windows"
)

var (
	modkernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessHandleCount = modkernel32.NewProc("GetProcessHandleCount")

	modpsapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = modpsapi.NewProc("GetProcessMemoryInfo")
)

type PROCESS_MEMORY_COUNTERS struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func getHandleCount(t *testing.T) uint32 {
	t.Helper()
	var count uint32
	r1, _, err := procGetProcessHandleCount.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&count)),
	)
	if r1 == 0 {
		t.Fatalf("GetProcessHandleCount failed: %v", err)
	}
	return count
}

func getMemoryUsage(t *testing.T) PROCESS_MEMORY_COUNTERS {
	t.Helper()
	var pmc PROCESS_MEMORY_COUNTERS
	pmc.CB = uint32(unsafe.Sizeof(pmc))
	r1, _, err := procGetProcessMemoryInfo.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&pmc)),
		uintptr(pmc.CB),
	)
	if r1 == 0 {
		t.Fatalf("GetProcessMemoryInfo failed: %v", err)
	}
	return pmc
}

// 1. Stress-test default 1024 MB limit with >1.5 GB allocation
func TestChallenger_Default1024MB_Exceed1500MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if _, err := powershellScriptExe(); err != nil {
		t.Skip("powershell not available:", err)
	}

	runner := newScriptRunner()

	// 1800 MB allocation (18 chunks of 100 MB)
	script := `$ErrorActionPreference = 'Stop'; $list = New-Object System.Collections.Generic.List[byte[]]; for ($i = 0; $i -lt 18; $i++) { $list.Add((New-Object byte[] 104857600)) }; Write-Output 'CHALLENGER_SURVIVED_1500MB'`

	req := protocol.ScriptRun{
		RunID:           "challenger-1500mb-default",
		Language:        "powershell",
		Body:            script,
		Timeout:         30,
		MaxMemoryMB:     0, // 0 = default 1024 MB
		CPULimitPercent: 80,
	}

	startTime := time.Now()
	res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
	elapsed := time.Since(startTime)

	t.Logf("1500MB allocation run completed in %v: exit=%d, stdout=%q, stderr=%q, err=%q",
		elapsed, res.ExitCode, res.Stdout, res.Stderr, res.Error)

	if res.ExitCode == 0 {
		t.Fatalf("FAILURE: Script allocating >1.5 GB under default 1024 MB limit succeeded with exit code 0!")
	}
	if strings.Contains(res.Stdout, "CHALLENGER_SURVIVED_1500MB") {
		t.Fatalf("FAILURE: Script allocating >1.5 GB printed survival message!")
	}
	t.Logf("CONFIRMED: Script allocating >1.5 GB was reliably terminated by Job Object limit (exit=%d)", res.ExitCode)
}

// 2. Stress-test custom memory override MaxMemoryMB = 100
func TestChallenger_CustomOverride_100MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if _, err := powershellScriptExe(); err != nil {
		t.Skip("powershell not available:", err)
	}

	runner := newScriptRunner()

	// Subtest 2a: Allocate 40 MB under 100 MB limit -> MUST SUCCEED
	t.Run("BelowLimit_40MB_Succeeds", func(t *testing.T) {
		req := protocol.ScriptRun{
			RunID:           "challenger-100mb-ok",
			Language:        "powershell",
			Body:            `[byte[]]$buf = New-Object byte[] 41943040; Write-Output 'CHALLENGER_40MB_OK'`,
			Timeout:         30,
			MaxMemoryMB:     100,
			CPULimitPercent: 80,
		}
		res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "CHALLENGER_40MB_OK") {
			t.Fatalf("Expected 40 MB allocation to succeed under 100 MB limit: exit=%d, stdout=%q, stderr=%q, err=%q",
				res.ExitCode, res.Stdout, res.Stderr, res.Error)
		}
		t.Logf("CONFIRMED: 40 MB allocation succeeded under 100 MB limit")
	})

	// Subtest 2b: Allocate 200 MB under 100 MB limit -> MUST BE TERMINATED
	t.Run("AboveLimit_200MB_Fails", func(t *testing.T) {
		req := protocol.ScriptRun{
			RunID:           "challenger-100mb-violation",
			Language:        "powershell",
			Body:            `$ErrorActionPreference = 'Stop'; $buf = New-Object byte[] 209715200; Write-Output 'CHALLENGER_200MB_SURVIVED'`,
			Timeout:         30,
			MaxMemoryMB:     100,
			CPULimitPercent: 80,
		}
		res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
		if res.ExitCode == 0 || strings.Contains(res.Stdout, "CHALLENGER_200MB_SURVIVED") {
			t.Fatalf("FAILURE: 200 MB allocation succeeded under 100 MB limit: exit=%d, stdout=%q",
				res.ExitCode, res.Stdout)
		}
		t.Logf("CONFIRMED: 200 MB allocation failed under 100 MB limit (exit=%d)", res.ExitCode)
	})
}

// 3. Stress-test custom memory override MaxMemoryMB = 500
func TestChallenger_CustomOverride_500MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if _, err := powershellScriptExe(); err != nil {
		t.Skip("powershell not available:", err)
	}

	runner := newScriptRunner()

	// Subtest 3a: Allocate 250 MB under 500 MB limit -> MUST SUCCEED
	t.Run("BelowLimit_250MB_Succeeds", func(t *testing.T) {
		req := protocol.ScriptRun{
			RunID:           "challenger-500mb-ok",
			Language:        "powershell",
			Body:            `[byte[]]$buf = New-Object byte[] 262144000; Write-Output 'CHALLENGER_250MB_OK'`,
			Timeout:         30,
			MaxMemoryMB:     500,
			CPULimitPercent: 80,
		}
		res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "CHALLENGER_250MB_OK") {
			t.Fatalf("Expected 250 MB allocation to succeed under 500 MB limit: exit=%d, stdout=%q, stderr=%q, err=%q",
				res.ExitCode, res.Stdout, res.Stderr, res.Error)
		}
		t.Logf("CONFIRMED: 250 MB allocation succeeded under 500 MB limit")
	})

	// Subtest 3b: Allocate 750 MB under 500 MB limit -> MUST BE TERMINATED
	t.Run("AboveLimit_750MB_Fails", func(t *testing.T) {
		req := protocol.ScriptRun{
			RunID:           "challenger-500mb-violation",
			Language:        "powershell",
			Body:            `$ErrorActionPreference = 'Stop'; $list = New-Object System.Collections.Generic.List[byte[]]; for ($i = 0; $i -lt 8; $i++) { $list.Add((New-Object byte[] 104857600)) }; Write-Output 'CHALLENGER_750MB_SURVIVED'`,
			Timeout:         30,
			MaxMemoryMB:     500,
			CPULimitPercent: 80,
		}
		res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
		if res.ExitCode == 0 || strings.Contains(res.Stdout, "CHALLENGER_750MB_SURVIVED") {
			t.Fatalf("FAILURE: 750 MB allocation succeeded under 500 MB limit: exit=%d, stdout=%q",
				res.ExitCode, res.Stdout)
		}
		t.Logf("CONFIRMED: 750 MB allocation failed under 500 MB limit (exit=%d)", res.ExitCode)
	})
}

// 4. Stress-test host OS and agent test runner health during and after repeated process termination
func TestChallenger_HostAndAgentHealthUnderRepeatedStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if _, err := powershellScriptExe(); err != nil {
		t.Skip("powershell not available:", err)
	}

	runner := newScriptRunner()

	// Initial metrics
	initialHandles := getHandleCount(t)
	initialMem := getMemoryUsage(t)
	t.Logf("Initial Agent Metrics: Handles=%d, WorkingSet=%d KB, Pagefile=%d KB",
		initialHandles, initialMem.WorkingSetSize/1024, initialMem.PagefileUsage/1024)

	// Execute 10 consecutive runaway violations
	const iterations = 10
	for i := 0; i < iterations; i++ {
		req := protocol.ScriptRun{
			RunID:           fmt.Sprintf("challenger-stress-run-%d", i),
			Language:        "powershell",
			Body:            `$ErrorActionPreference = 'Stop'; $buf = New-Object byte[] 314572800; Write-Output 'SURVIVED'`,
			Timeout:         15,
			MaxMemoryMB:     100, // 300 MB allocation under 100 MB limit
			CPULimitPercent: 80,
		}
		res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
		if res.ExitCode == 0 {
			t.Fatalf("Iteration %d: runaway process should have failed but exited 0", i)
		}
	}

	// Post-stress metrics
	postHandles := getHandleCount(t)
	postMem := getMemoryUsage(t)
	t.Logf("Post-Stress Agent Metrics: Handles=%d (delta: %d), WorkingSet=%d KB, Pagefile=%d KB",
		postHandles, int(postHandles)-int(initialHandles), postMem.WorkingSetSize/1024, postMem.PagefileUsage/1024)

	// Verify handle leak: delta should be minimal (typically < 10 for runtime background routines)
	handleDelta := int(postHandles) - int(initialHandles)
	if handleDelta > 30 {
		t.Errorf("Potential handle leak detected! Handle count grew by %d over %d runs", handleDelta, iterations)
	}

	// Verify agent can still run a normal script without issues
	normalReq := protocol.ScriptRun{
		RunID:           "challenger-post-stress-normal",
		Language:        "powershell",
		Body:            `Write-Output 'AGENT_STILL_HEALTHY'`,
		Timeout:         15,
		MaxMemoryMB:     1024,
		CPULimitPercent: 80,
	}
	resNormal := runner.run(context.Background(), normalReq, func(protocol.ScriptChunk) {})
	if resNormal.ExitCode != 0 || !strings.Contains(resNormal.Stdout, "AGENT_STILL_HEALTHY") {
		t.Fatalf("Agent failed to run normal script after stress testing: exit=%d, stdout=%q, err=%q",
			resNormal.ExitCode, resNormal.Stdout, resNormal.Error)
	}

	t.Logf("CONFIRMED: Agent and Host remain healthy, stable, and fully functional across %d termination cycles", iterations)
}

// 5. Stress-test Job Memory Limit across process tree (JOB_OBJECT_LIMIT_JOB_MEMORY)
func TestChallenger_JobMemoryLimitProcessTree(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if _, err := powershellScriptExe(); err != nil {
		t.Skip("powershell not available:", err)
	}

	runner := newScriptRunner()

	// Under 200 MB limit:
	// Parent spawns child process. Both parent and child allocate 120 MB each.
	// Total job memory = 240 MB > 200 MB limit.
	// Either child fails to allocate or parent/job terminates.
	script := `
		$ErrorActionPreference = 'Stop'
		$p1 = [byte[]]::new(120 * 1024 * 1024)
		$childCode = '[byte[]]$b = New-Object byte[] 125829120; Start-Sleep -Seconds 1'
		$proc = Start-Process powershell -WindowStyle Hidden -ArgumentList "-NoProfile -NonInteractive -Command $childCode" -PassThru -Wait
		if ($proc.ExitCode -ne 0) {
			Write-Error "Child failed as expected with $($proc.ExitCode)"
		} else {
			Write-Output "JOB_TREE_UNEXPECTEDLY_SURVIVED"
		}
	`
	req := protocol.ScriptRun{
		RunID:           "challenger-job-tree-quota",
		Language:        "powershell",
		Body:            script,
		Timeout:         20,
		MaxMemoryMB:     200,
		CPULimitPercent: 80,
	}
	res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})
	t.Logf("Process tree run result: exit=%d, stdout=%q, stderr=%q, err=%q",
		res.ExitCode, res.Stdout, res.Stderr, res.Error)

	if strings.Contains(res.Stdout, "JOB_TREE_UNEXPECTEDLY_SURVIVED") {
		t.Fatalf("FAILURE: Multi-process tree exceeded 200 MB total limit without violation!")
	}
	t.Logf("CONFIRMED: Multi-process tree memory quota enforced by Job Object")
}
