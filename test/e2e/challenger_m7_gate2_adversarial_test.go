//go:build windows
// +build windows

package e2e_test

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent"
	"golang.org/x/sys/windows"
)

// ============================================================================
// Adversarial Challenger M7 Gate 2: Quotas, Process Tree Reaping, & Redaction
// ============================================================================

// TestChallengerM7_Runaway1500MB_TerminatedUnder2Seconds verifies that a runaway
// memory allocating script attempting to allocate 1.5 GB under default 1024 MB
// limit is cleanly terminated strictly in under 2.0 seconds.
func TestChallengerM7_Runaway1500MB_TerminatedUnder2Seconds(t *testing.T) {
	job, err := createTestSandboxedJob(1024, 80)
	if err != nil {
		t.Fatalf("Failed to create 1024 MB Job Object: %v", err)
	}
	defer windows.CloseHandle(job)

	// Rapid 1.5 GB allocation in PowerShell without artificial sleep
	script := `
		$ErrorActionPreference = 'Stop'
		$chunks = [System.Collections.Generic.List[byte[]]]::new()
		for ($i = 0; $i -lt 15; $i++) {
			$chunks.Add([byte[]]::new(100 * 1024 * 1024))
		}
		Write-Output "ALLOCATION_UNEXPECTEDLY_SURVIVED"
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start powershell process: %v", err)
	}

	_ = assignProcessToJob(job, cmd.Process.Pid)

	waitErr := cmd.Wait()
	elapsed := time.Since(start)

	t.Logf("Empirical result: elapsed=%v, exitErr=%v, stdout=%q, stderr=%q",
		elapsed, waitErr, stdout.String(), stderr.String())

	// 1. Must terminate with non-zero exit or error
	if waitErr == nil {
		t.Fatalf("FAIL: Runaway 1.5 GB script succeeded without termination!")
	}
	if strings.Contains(stdout.String(), "ALLOCATION_UNEXPECTEDLY_SURVIVED") {
		t.Fatalf("FAIL: Runaway script printed survival marker!")
	}

	// 2. Must terminate in < 2 seconds
	if elapsed >= 2*time.Second {
		t.Fatalf("FAIL: Runaway script took %v to terminate (must be < 2 seconds)", elapsed)
	}

	t.Logf("PASS: Runaway 1.5 GB script cleanly terminated in %v (< 2s ceiling)", elapsed)
}

// TestChallengerM7_ProcessTreeReaping_OnQuotaBreach verifies that when a parent
// process spawns background children and subsequently breaches the memory quota,
// the entire descendant process tree is completely reaped by the Job Object.
func TestChallengerM7_ProcessTreeReaping_OnQuotaBreach(t *testing.T) {
	job, err := createTestSandboxedJob(256, 80)
	if err != nil {
		t.Fatalf("Failed to create Job Object: %v", err)
	}
	// We hold the handle; when the job is closed or parent dies, we verify children are reaped.
	defer windows.CloseHandle(job)

	// The parent launches a child powershell process that sleeps for 60 seconds and writes its PID to a file.
	// Then the parent immediately allocates 400 MB (> 256 MB limit) to trigger kernel quota termination.
	pidFile := fmt.Sprintf("%s/child_pid_%d.txt", t.TempDir(), time.Now().UnixNano())

	script := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		$childCode = "Set-Content -Path '%s' -Value ([int]$PID); Start-Sleep -Seconds 60"
		$p = Start-Process powershell -WindowStyle Hidden -ArgumentList "-NoProfile -NonInteractive -Command $childCode" -PassThru
		Start-Sleep -Milliseconds 600
		# Now breach 256 MB quota
		$arr = [byte[]]::new(400 * 1024 * 1024)
		Write-Output "PARENT_SURVIVED"
	`, strings.ReplaceAll(pidFile, `\`, `/`))

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start parent process: %v", err)
	}

	_ = assignProcessToJob(job, cmd.Process.Pid)

	waitErr := cmd.Wait()
	t.Logf("Parent terminated: %v", waitErr)

	// Close the job object to simulate supervisor/agent cleanup of the job
	windows.CloseHandle(job)

	// Give Windows kernel a brief moment (200ms) to reap job processes
	time.Sleep(200 * time.Millisecond)

	// Check if child PID was written
	// If the child was spawned into the job object, the close of the job object must have reaped it.
	// Let's verify whether the child PID is still alive in the OS.
	// If the child was reaped, OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION or TerminateProcess will fail or exit code is non-STILL_ACTIVE.
	// Let's check via powershell Get-Process.
	checkCmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", fmt.Sprintf(`
		if (Test-Path '%s') {
			$cpid = [int](Get-Content -Path '%s')
			$p = Get-Process -Id $cpid -ErrorAction SilentlyContinue
			if ($null -ne $p -and -not $p.HasExited) {
				Write-Output "CHILD_STILL_ALIVE:$cpid"
			} else {
				Write-Output "CHILD_REAPED"
			}
		} else {
			Write-Output "NO_CHILD_PID_FILE"
		}
	`, pidFile, pidFile))
	checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := checkCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Check command failed: %v", err)
	}
	outStr := strings.TrimSpace(string(out))
	t.Logf("Child status check: %s", outStr)

	if strings.Contains(outStr, "CHILD_STILL_ALIVE") {
		t.Fatalf("CRITICAL RESILIENCE FAILURE: Child process survived Job Object termination: %s", outStr)
	}
	t.Logf("PASS: Child process tree cleanly reaped on Job Object termination")
}

// TestChallengerM7_AdversarialSecretRedaction_EdgeCases stress tests
// secret redaction across subtle token variations, chunk boundary slicing, and negative controls.
func TestChallengerM7_AdversarialSecretRedaction_EdgeCases(t *testing.T) {
	// 1. Streaming Chunk Boundary Stress: 1-byte, 2-byte, 3-byte and random slicing
	t.Run("ArbitraryChunkSlicing", func(t *testing.T) {
		secretText := "Status: OK\n" +
			"Auth: Bearer eyJhbGciOiJIUzI1NiJ9.s3cr3tT0k3n.abc123xyz\n" +
			"DB: user=postgres password=MySuperSecurePassword123! host=db.local\n" +
			"API: api_key=sk_live_998877665544332211 token=ghp_PersonalAccessTokenABCDE secret=SuperSharedSecretKey999\n" +
			"-----BEGIN RSA PRIVATE KEY-----\n" +
			"MIIEowIBAAKCAQEA0Y1W9Z5luE9O5bK0Jk1M2N3P4Q5R6S7T\n" +
			"-----END RSA PRIVATE KEY-----\n" +
			"Diagnostics completed successfully\n"

		secrets := []string{
			"s3cr3tT0k3n",
			"MySuperSecurePassword123!",
			"sk_live_998877665544332211",
			"ghp_PersonalAccessTokenABCDE",
			"SuperSharedSecretKey999",
			"MIIEowIBAAKCAQEA0Y1W9Z5luE9O5bK0Jk1M2N3P4Q5R6S7T",
		}

		// Test chunk sizes: 1, 2, 3, 5, 7, 13, 29 bytes
		chunkSizes := []int{1, 2, 3, 5, 7, 13, 29}
		for _, size := range chunkSizes {
			t.Run(fmt.Sprintf("ChunkSize_%d", size), func(t *testing.T) {
				harness := NewStreamingRedactHarness()
				raw := []byte(secretText)
				for offset := 0; offset < len(raw); offset += size {
					end := offset + size
					if end > len(raw) {
						end = len(raw)
					}
					_, err := harness.Write(raw[offset:end])
					if err != nil {
						t.Fatalf("Write error: %v", err)
					}
				}
				harness.FlushRemainder()

				lines := harness.Lines()
				output := strings.Join(lines, "\n")

				for _, sec := range secrets {
					if strings.Contains(output, sec) {
						t.Fatalf("CRITICAL LEAK: Secret %q found in chunk size %d output:\n%s", sec, size, output)
					}
				}

				// Verify presence of required redactions
				if !strings.Contains(output, "Bearer [REDACTED]") {
					t.Errorf("Missing Bearer [REDACTED] in chunk size %d", size)
				}
				if !strings.Contains(output, "password=[REDACTED]") {
					t.Errorf("Missing password=[REDACTED] in chunk size %d", size)
				}
				if !strings.Contains(output, "api_key=[REDACTED]") {
					t.Errorf("Missing api_key=[REDACTED] in chunk size %d", size)
				}
				if !strings.Contains(output, "token=[REDACTED]") {
					t.Errorf("Missing token=[REDACTED] in chunk size %d", size)
				}
				if !strings.Contains(output, "secret=[REDACTED]") {
					t.Errorf("Missing secret=[REDACTED] in chunk size %d", size)
				}
				if !strings.Contains(output, "[REDACTED PRIVATE KEY]") {
					t.Errorf("Missing [REDACTED PRIVATE KEY] in chunk size %d", size)
				}
			})
		}
	})

	// 2. Negative Controls: Non-secret patterns must remain intact
	t.Run("NegativeControls", func(t *testing.T) {
		inputs := []string{
			"The bearer of bad news is rarely welcomed",
			"Bearer bond serial number BB-998877",
			"Public key: -----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----",
			"Certificate: -----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAL0=\n-----END CERTIFICATE-----",
			"Normal sentence with word password_reset_url=https://example.com/reset",
		}

		for _, inp := range inputs {
			out := agent.RedactSecrets(inp)
			if strings.Contains(inp, "bad news") && !strings.Contains(out, "bad news") {
				t.Errorf("False positive on English prose: %q -> %q", inp, out)
			}
			if strings.Contains(inp, "PUBLIC KEY") && !strings.Contains(out, "PUBLIC KEY") {
				t.Errorf("False positive on PUBLIC KEY: %q -> %q", inp, out)
			}
			if strings.Contains(inp, "CERTIFICATE") && !strings.Contains(out, "CERTIFICATE") {
				t.Errorf("False positive on CERTIFICATE: %q -> %q", inp, out)
			}
		}
	})
}
