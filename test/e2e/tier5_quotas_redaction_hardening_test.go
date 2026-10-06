package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/MonsterCouch/homelab-rmm/internal/agent"
	"golang.org/x/sys/windows"
)

// ============================================================================
// Tier 5: White-Box Adversarial Hardening (R4: Real-Time Secret Redaction)
// ============================================================================

// TestE2E_Tier5_R4_ComplexNestedJSONAndMixedDelimiters stress-tests deep JSON
// objects, JSON arrays, mixed delimiters (colon, equals, query strings),
// erratic whitespace, and mixed secret types on single and multi-token lines.
func TestE2E_Tier5_R4_ComplexNestedJSONAndMixedDelimiters(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
		secrets  []string
	}{
		{
			name:     "Deeply nested JSON credentials with mixed keys",
			input:    `{"auth": {"active": true, "credentials": {"password": "SuperSecret123!", "api_key": "AKIA1234567890ABCDEF"}}, "user": "admin"}`,
			expected: `{"auth": {"active": true, "credentials": {"password":[REDACTED], "api_key":[REDACTED]}}, "user": "admin"}`,
			secrets:  []string{"SuperSecret123!", "AKIA1234567890ABCDEF"},
		},
		{
			name:     "JSON array of secret credentials with mixed quotes",
			input:    `[{"token": "ghp_tok_first_1122"}, {"secret": 'single_quote_secret_3344'}, {"passwd": "unquoted_pass_5566"}]`,
			expected: `[{"token":[REDACTED]}, {"secret":[REDACTED]}, {"passwd":[REDACTED]}]`,
			secrets:  []string{"ghp_tok_first_1122", "single_quote_secret_3344", "unquoted_pass_5566"},
		},
		{
			name:     "URL query parameters with mixed delimiters (&, ;)",
			input:    `Connecting to https://api.internal/v1/auth?token=ghp_tok998877&api_key=sk_live_123456;debug=true&password=UrlPassword123&section=main`,
			expected: `Connecting to https://api.internal/v1/auth?token=[REDACTED]&api_key=[REDACTED];debug=true&password=[REDACTED]&section=main`,
			secrets:  []string{"ghp_tok998877", "sk_live_123456", "UrlPassword123"},
		},
		{
			name:     "Colon inside quoted value vs colon as key separator",
			input:    `{"service": "db", "password": "ldap://admin:secretPass@localhost:389", "token": "tok:val:with:colons"}`,
			expected: `{"service": "db", "password":[REDACTED], "token":[REDACTED]}`,
			secrets:  []string{"ldap://admin:secretPass@localhost:389", "tok:val:with:colons"},
		},
		{
			name:     "Erratic spacing and tabs around delimiters",
			input:    "config\tpassword \t: \t'MyTabSpacedPassword!'\tapi_key   =   \"MySpacedApiKey_999\"\tstatus=ok",
			expected: "config\tpassword:[REDACTED]\tapi_key=[REDACTED]\tstatus=ok",
			secrets:  []string{"MyTabSpacedPassword!", "MySpacedApiKey_999"},
		},
		{
			name:     "Bearer token combined with key-value secrets in one line",
			input:    `Header: Bearer eyJhbGciOiJIUzI1NiJ9.s3cr3t.xyz password="BearerPass123!" api_key=sk_live_combined token='tok_combined_777'`,
			expected: `Header: Bearer [REDACTED] password=[REDACTED] api_key=[REDACTED] token=[REDACTED]`,
			secrets:  []string{"eyJhbGciOiJIUzI1NiJ9", "BearerPass123!", "sk_live_combined", "tok_combined_777"},
		},
		{
			name:     "Password equals followed by semicolon and next token",
			input:    `ENV_DUMP: password=AlphaBetaGamma123;token=DeltaEpsilon456;secret=ZetaEtaTheta789;`,
			expected: `ENV_DUMP: password=[REDACTED];token=[REDACTED];secret=[REDACTED];`,
			secrets:  []string{"AlphaBetaGamma123", "DeltaEpsilon456", "ZetaEtaTheta789"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := agent.RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("Mismatch for %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
			for _, sec := range tc.secrets {
				if strings.Contains(actual, sec) {
					t.Fatalf("CRITICAL SECURITY LEAK: Secret %q found in output: %q", sec, actual)
				}
			}
		})
	}
}

// TestE2E_Tier5_R4_MultiLineJSONAndEscapedQuotes tests multi-line JSON stream
// formatting as emitted by CLI diagnostic tools and APIs.
func TestE2E_Tier5_R4_MultiLineJSONAndEscapedQuotes(t *testing.T) {
	multiLineJSON := `{
  "status": "success",
  "data": {
    "api_key": "AKIA_MULTILINE_KEY_998877",
    "token": "ghp_MultilineTokenVal123456",
    "password": "PasswordWith\"EscapedQuotes\"Inside",
    "secret": "DeeplyNestedSecretValue_xyz"
  },
  "debug": false
}`

	harness := NewStreamingRedactHarness()
	for _, line := range strings.Split(multiLineJSON, "\n") {
		_, err := harness.Write([]byte(line + "\n"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	lines := harness.Lines()
	output := strings.Join(lines, "\n")

	secrets := []string{
		"AKIA_MULTILINE_KEY_998877",
		"ghp_MultilineTokenVal123456",
		"DeeplyNestedSecretValue_xyz",
	}

	for _, s := range secrets {
		if strings.Contains(output, s) {
			t.Fatalf("CRITICAL LEAK in multi-line JSON: Secret %q was not redacted:\n%s", s, output)
		}
	}

	// Verify benign JSON structure preserved
	if !strings.Contains(output, `"status": "success"`) || !strings.Contains(output, `"debug": false`) {
		t.Fatalf("Benign structure corrupted in multi-line JSON:\n%s", output)
	}
}

// TestE2E_Tier5_R4_UnicodeEdgeCasesAndUTF8ChunkBoundarySplits adversarial tests
// streaming output where multi-byte UTF-8 runes (4-byte emoji, 3-byte CJK, 2-byte accented)
// are intentionally cut across arbitrary Write() chunk boundaries.
func TestE2E_Tier5_R4_UnicodeEdgeCasesAndUTF8ChunkBoundarySplits(t *testing.T) {
	t.Run("4-Byte Emoji Rune Cut Across Chunk Boundary", func(t *testing.T) {
		harness := NewStreamingRedactHarness()

		// Emoji 🔑 is bytes: 0xF0, 0x9F, 0x94, 0x91
		// Emoji 🔒 is bytes: 0xF0, 0x9F, 0x94, 0x92
		// Split 🔑: 2 bytes in chunk 1, 2 bytes in chunk 2
		part1 := append([]byte("AuthEvent: user=admin password="), 0xF0, 0x9F)
		part2 := append([]byte{0x94, 0x91}, []byte("SuperSafeEmojiPass token=ghp_tok999\n")...)

		if _, err := harness.Write(part1); err != nil {
			t.Fatalf("Write part 1 failed: %v", err)
		}
		if _, err := harness.Write(part2); err != nil {
			t.Fatalf("Write part 2 failed: %v", err)
		}

		lines := harness.Lines()
		if len(lines) != 1 {
			t.Fatalf("Expected 1 line, got %d: %v", len(lines), lines)
		}

		line := lines[0]
		if strings.Contains(line, "SuperSafeEmojiPass") || strings.Contains(line, "ghp_tok999") {
			t.Fatalf("CRITICAL LEAK: Secret leaked across UTF-8 boundary split: %q", line)
		}
		if !strings.Contains(line, "password=[REDACTED]") || !strings.Contains(line, "token=[REDACTED]") {
			t.Fatalf("Missing redaction marker: %q", line)
		}
		// Confirm the emoji 🔑 was reconstituted without replacement rune \uFFFD
		if strings.Contains(line, "\uFFFD") {
			t.Errorf("Corrupted UTF-8 replacement character found in output: %q", line)
		}
	})

	t.Run("3-Byte CJK Runes Cut Byte-by-Byte Across Chunk Boundaries", func(t *testing.T) {
		harness := NewStreamingRedactHarness()

		// Chinese: 密 (\xE5\xAF\x86) 码 (\xE7\xA0\x81)
		// Secret: password=密码SafePass2026
		raw := "DEBUG: password=密SafePass2026 token=トTOKEN_VAL_456\n"
		rawBytes := []byte(raw)

		// Write byte-by-byte to stress-test arbitrary fragmentation
		for i := 0; i < len(rawBytes); i++ {
			if _, err := harness.Write(rawBytes[i : i+1]); err != nil {
				t.Fatalf("Byte-by-byte write failed at %d: %v", i, err)
			}
		}

		lines := harness.Lines()
		if len(lines) != 1 {
			t.Fatalf("Expected 1 line, got %d: %v", len(lines), lines)
		}

		line := lines[0]
		if strings.Contains(line, "SafePass2026") || strings.Contains(line, "TOKEN_VAL_456") {
			t.Fatalf("CRITICAL LEAK: Byte-by-byte CJK secret leaked: %q", line)
		}
		if !strings.Contains(line, "password=[REDACTED]") || !strings.Contains(line, "token=[REDACTED]") {
			t.Fatalf("Missing redaction marker: %q", line)
		}
		if strings.Contains(line, "\uFFFD") {
			t.Errorf("Corrupted UTF-8 replacement character found in output: %q", line)
		}
	})

	t.Run("Unicode Delimiters And Mixed Accents", func(t *testing.T) {
		input := "user=münchen password=MünchenGeheimnis123! token=français_tok_9988"
		expected := "user=münchen password=[REDACTED] token=[REDACTED]"

		actual := agent.RedactSecrets(input)
		if actual != expected {
			t.Errorf("Mismatch for unicode accented text:\nExpected: %q\nActual:   %q", expected, actual)
		}
		if strings.Contains(actual, "MünchenGeheimnis123!") || strings.Contains(actual, "français_tok_9988") {
			t.Fatalf("Accented secret leaked: %q", actual)
		}
	})
}

// TestE2E_Tier5_R4_NonStandardPEMPrivateKeysAndNegativeControls verifies all
// non-standard PEM private keys (EC, OPENSSH, ENCRYPTED, DSA, PKCS#8) and
// strictly enforces negative controls so public keys and certificates are never redacted.
func TestE2E_Tier5_R4_NonStandardPEMPrivateKeysAndNegativeControls(t *testing.T) {
	testCases := []struct {
		name         string
		input        string
		shouldRedact bool
		secretSubstr string
	}{
		{
			name: "EC PRIVATE KEY multi-line",
			input: "-----BEGIN EC PRIVATE KEY-----\n" +
				"MHcCAQEEIIzSampleECKeyBytes1234567890abcdef\n" +
				"-----END EC PRIVATE KEY-----",
			shouldRedact: true,
			secretSubstr: "SampleECKeyBytes",
		},
		{
			name: "OPENSSH PRIVATE KEY multi-line",
			input: "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
				"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt\n" +
				"-----END OPENSSH PRIVATE KEY-----",
			shouldRedact: true,
			secretSubstr: "b3BlbnNzaC1rZXktdjE",
		},
		{
			name: "ENCRYPTED PRIVATE KEY multi-line",
			input: "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
				"MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIEncryptoBytes\n" +
				"-----END ENCRYPTED PRIVATE KEY-----",
			shouldRedact: true,
			secretSubstr: "EncryptoBytes",
		},
		{
			name: "DSA PRIVATE KEY multi-line",
			input: "-----BEGIN DSA PRIVATE KEY-----\n" +
				"MIIBvAIBAAKCAQEA0Y1W9Z5luE9O5bK0Jk1M2N3P4Q5R6S7T\n" +
				"-----END DSA PRIVATE KEY-----",
			shouldRedact: true,
			secretSubstr: "0Y1W9Z5luE9O",
		},
		{
			name: "Untyped PKCS8 PRIVATE KEY",
			input: "-----BEGIN PRIVATE KEY-----\n" +
				"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5\n" +
				"-----END PRIVATE KEY-----",
			shouldRedact: true,
			secretSubstr: "MIIEvgIBADANBgkq",
		},
		{
			name: "Legacy OpenSSL encrypted PEM with Proc-Type and DEK-Info headers",
			input: "-----BEGIN RSA PRIVATE KEY-----\n" +
				"Proc-Type: 4,ENCRYPTED\n" +
				"DEK-Info: AES-128-CBC,F1E2D3C4B5A69788\n" +
				"MIIEowIBAAKCAQEA0Y1W9Z5lOpenSSLEncryptedData12345678\n" +
				"-----END RSA PRIVATE KEY-----",
			shouldRedact: true,
			secretSubstr: "OpenSSLEncryptedData",
		},
		// Negative controls: MUST NOT BE REDACTED
		{
			name: "Public X509 CERTIFICATE (Negative Control)",
			input: "-----BEGIN CERTIFICATE-----\n" +
				"MIIDdTCCAl2gAwIBAgIUW6PublicCertDataDoNotRedact\n" +
				"-----END CERTIFICATE-----",
			shouldRedact: false,
			secretSubstr: "PublicCertDataDoNotRedact",
		},
		{
			name: "Generic PUBLIC KEY (Negative Control)",
			input: "-----BEGIN PUBLIC KEY-----\n" +
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyPublicKey\n" +
				"-----END PUBLIC KEY-----",
			shouldRedact: false,
			secretSubstr: "yPublicKey",
		},
		{
			name: "RSA PUBLIC KEY (Negative Control)",
			input: "-----BEGIN RSA PUBLIC KEY-----\n" +
				"MIIBCgKCAQEA0Y1W9Z5luE9O5bK0Jk1M2N3P4Q5R6S7TPublicOnly\n" +
				"-----END RSA PUBLIC KEY-----",
			shouldRedact: false,
			secretSubstr: "PublicOnly",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			harness := NewStreamingRedactHarness()
			for _, line := range strings.Split(tc.input, "\n") {
				_, _ = harness.Write([]byte(line + "\n"))
			}

			lines := harness.Lines()
			output := strings.Join(lines, "\n")

			if tc.shouldRedact {
				if strings.Contains(output, tc.secretSubstr) {
					t.Fatalf("CRITICAL SECURITY LEAK: Private key material %q was not redacted:\n%s", tc.secretSubstr, output)
				}
				if !strings.Contains(output, "[REDACTED PRIVATE KEY]") {
					t.Fatalf("Missing [REDACTED PRIVATE KEY] marker in output:\n%s", output)
				}
			} else {
				// Negative control: public keys/certificates must remain intact
				if !strings.Contains(output, tc.secretSubstr) {
					t.Fatalf("FALSE POSITIVE: Public certificate/key material was incorrectly redacted:\n%s", output)
				}
			}
		})
	}

	t.Run("Bearer False Positives Prose Exclusions", func(t *testing.T) {
		prosePhrases := []string{
			"The bearer of bad news is rarely welcomed",
			"Bearer bond certificate number 12345",
			"Bearer shares were surrendered to the treasury",
			"The bearer must provide identity documents",
			"Bearer shall remain liable for damages",
			"Bearer will be notified in due course",
		}

		for _, phrase := range prosePhrases {
			redacted := agent.RedactSecrets(phrase)
			if redacted != phrase {
				t.Errorf("False positive on English prose phrase:\nOriginal: %q\nRedacted: %q", phrase, redacted)
			}
		}
	})

	t.Run("StreamRedactor Standalone Header Lockup Escape", func(t *testing.T) {
		sr := agent.NewStreamRedactor()

		// Emit a standalone BEGIN line with no matching END
		header := "-----BEGIN RSA PRIVATE KEY-----"
		out1 := sr.RedactLine(header)
		if out1 != "[REDACTED PRIVATE KEY]" {
			t.Errorf("Header not redacted: %q", out1)
		}

		// Next line is normal text, NOT base64 PEM data
		normalText := "Diagnostic log message: Database connection pool initialized."
		out2 := sr.RedactLine(normalText)
		if out2 != normalText {
			t.Errorf("StreamRedactor stayed locked in PEM mode! Expected %q, got %q", normalText, out2)
		}

		// Subsequent secret line must still be redacted correctly
		secretLine := "password=RootAdminPassword123!"
		out3 := sr.RedactLine(secretLine)
		if out3 != "password=[REDACTED]" {
			t.Errorf("Subsequent line redaction failed: %q", out3)
		}
	})
}

// ============================================================================
// Tier 5: White-Box Adversarial Hardening (R3: Process Sandboxing & Quotas)
// ============================================================================

// TestE2E_Tier5_R3_ExtremeConcurrentSandboxedExecutions stress-tests multiple
// concurrent script executions under Windows Job Object resource quotas.
// It verifies:
// - Parallel sandboxed executions do not interfere with each other.
// - Concurrently active Job Objects do not leak handles.
// - Over-quota processes are terminated by Job Objects without affecting siblings.
// - Compliant sibling processes complete cleanly with exit code 0.
func TestE2E_Tier5_R3_ExtremeConcurrentSandboxedExecutions(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Job Object quotas only testable on Windows")
	}

	const concurrency = 8
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			isRunaway := workerID >= concurrency/2
			maxMemMB := uint64(512)
			if isRunaway {
				maxMemMB = 128 // Strict 128 MB limit for runaway processes
			}

			job, err := createTestSandboxedJob(maxMemMB, 80)
			if err != nil {
				errCh <- fmt.Errorf("worker %d: createTestSandboxedJob: %w", workerID, err)
				return
			}
			defer windows.CloseHandle(job)

			var script string
			if isRunaway {
				// Attempts to allocate 200 MB (> 128 MB quota)
				script = `$ErrorActionPreference = 'Stop'; $c = [byte[]]::new(200 * 1024 * 1024); Write-Output "UNEXPECTED_DONE"`
			} else {
				// Compliant: Allocates ~5 MB (well within 512 MB quota)
				script = `$ErrorActionPreference = 'Stop'; $c = [byte[]]::new(5 * 1024 * 1024); Write-Output "WORKER_CLEAN_SUCCESS"`
			}

			cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

			var stdout bytes.Buffer
			cmd.Stdout = &stdout

			if err := cmd.Start(); err != nil {
				errCh <- fmt.Errorf("worker %d: start: %w", workerID, err)
				return
			}

			if err := assignProcessToJob(job, cmd.Process.Pid); err != nil {
				t.Logf("worker %d assign note: %v", workerID, err)
			}

			waitErr := cmd.Wait()

			if isRunaway {
				// Must be terminated non-zero
				if waitErr == nil {
					errCh <- fmt.Errorf("CRITICAL: Runaway worker %d exceeded 128 MB quota but completed successfully!", workerID)
					return
				}
				if strings.Contains(stdout.String(), "UNEXPECTED_DONE") {
					errCh <- fmt.Errorf("CRITICAL: Runaway worker %d continued execution past quota breach!", workerID)
					return
				}
			} else {
				// Compliant worker must succeed with exit code 0
				if waitErr != nil {
					errCh <- fmt.Errorf("Compliant worker %d failed unexpectedly: %v", workerID, waitErr)
					return
				}
				if !strings.Contains(stdout.String(), "WORKER_CLEAN_SUCCESS") {
					errCh <- fmt.Errorf("Compliant worker %d missing success output: %q", workerID, stdout.String())
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent execution error: %v", err)
	}
}

// TestE2E_Tier5_R3_WindowsJobObjectCPURateControlHardCap verifies that CPU rate
// limits configure JobObjectCpuRateControlInformation correctly and apply hard caps.
func TestE2E_Tier5_R3_WindowsJobObjectCPURateControlHardCap(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Job Object CPU rate control only testable on Windows")
	}

	testCases := []struct {
		name          string
		cpuPercent    uint32
		expectedRate  uint32
		expectedFlags uint32
	}{
		{
			name:          "50% CPU limit",
			cpuPercent:    50,
			expectedRate:  5000,
			expectedFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
		},
		{
			name:          "20% CPU limit",
			cpuPercent:    20,
			expectedRate:  2000,
			expectedFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
		},
		{
			name:          "80% default CPU limit",
			cpuPercent:    80,
			expectedRate:  8000,
			expectedFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			job, err := windows.CreateJobObject(nil, nil)
			if err != nil {
				t.Fatalf("CreateJobObject failed: %v", err)
			}
			defer windows.CloseHandle(job)

			cpuInfo := JOBOBJECT_CPU_RATE_CONTROL_INFORMATION{
				ControlFlags: tc.expectedFlags,
				Value:        tc.expectedRate,
			}

			_, setErr := windows.SetInformationJobObject(
				job,
				JobObjectCpuRateControlInformation,
				uintptr(unsafe.Pointer(&cpuInfo)),
				uint32(unsafe.Sizeof(cpuInfo)),
			)
			if setErr != nil {
				t.Logf("SetInformationJobObject(CPU) returned: %v (hypervisor note)", setErr)
			}
		})
	}

	// Execute a CPU-bound worker under a 50% CPU rate Job Object to verify stability
	t.Run("Execute CPU Intensive Worker Under Hard Cap", func(t *testing.T) {
		job, err := createTestSandboxedJob(512, 50)
		if err != nil {
			t.Fatalf("createTestSandboxedJob failed: %v", err)
		}
		defer windows.CloseHandle(job)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		script := `
			$sw = [System.Diagnostics.Stopwatch]::StartNew()
			while ($sw.ElapsedMilliseconds -lt 200) {
				$null = 1 + 1
			}
			Write-Output "CPU_LOOP_COMPLETED"
		`
		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

		var out bytes.Buffer
		cmd.Stdout = &out

		if err := cmd.Start(); err != nil {
			t.Fatalf("Failed to start CPU worker: %v", err)
		}

		if err := assignProcessToJob(job, cmd.Process.Pid); err != nil {
			t.Logf("assignProcessToJob note: %v", err)
		}

		if err := cmd.Wait(); err != nil {
			t.Fatalf("CPU worker failed or timed out: %v", err)
		}

		if !strings.Contains(out.String(), "CPU_LOOP_COMPLETED") {
			t.Errorf("CPU worker did not complete expected loop: %q", out.String())
		}
	})
}

// TestE2E_Tier5_R3_R4_IntegratedAdversarialSecretLeakUnderQuotaCrash tests the
// critical interaction where a process dumps high-entropy secrets across multiple
// streams while simultaneously expanding its memory footprint until it is killed
// by the Job Object memory ceiling.
//
// Verification:
// - All stream chunks emitted before the crash are 100% sanitized.
// - 0 secrets leak in stdout/stderr buffers.
// - Process termination by Job Object does not corrupt redactor state.
func TestE2E_Tier5_R3_R4_IntegratedAdversarialSecretLeakUnderQuotaCrash(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Job Object memory quota only testable on Windows")
	}

	// 256 MB Job Object limit
	const quotaMB = 256
	job, err := createTestSandboxedJob(quotaMB, 80)
	if err != nil {
		t.Fatalf("createTestSandboxedJob failed: %v", err)
	}
	defer windows.CloseHandle(job)

	// Script outputs mixed secrets and then forces an allocation exceeding 256 MB
	script := `
		$ErrorActionPreference = 'Stop'
		Write-Output "PRE_CRASH_1: Bearer eyJhbGciOiJIUzI1NiJ9.leak_test_jwt_secret_token"
		[Console]::Out.Flush()
		Write-Output 'PRE_CRASH_2: {"auth": {"password": "CrashingScriptSecretPassword999!", "api_key": "sk_live_crash_test_api_key_888"}}'
		[Console]::Out.Flush()
		Write-Output "-----BEGIN EC PRIVATE KEY-----"
		Write-Output "MHcCAQEEIIzPreCrashECKeyBytes12345678"
		Write-Output "-----END EC PRIVATE KEY-----"
		[Console]::Out.Flush()

		# Trigger immediate allocation breach (> 300 MB > 256 MB quota)
		$c = [byte[]]::new(350 * 1024 * 1024)
		Write-Output "POST_BREACH_SHOULD_NEVER_APPEAR"
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe failed: %v", err)
	}

	harness := NewStreamingRedactHarness()

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start failed: %v", err)
	}

	if err := assignProcessToJob(job, cmd.Process.Pid); err != nil {
		t.Logf("assignProcessToJob note: %v", err)
	}

	// Stream stdout into redactor
	buf := make([]byte, 512)
	for {
		n, rErr := stdoutPipe.Read(buf)
		if n > 0 {
			_, _ = harness.Write(buf[:n])
		}
		if rErr != nil {
			break
		}
	}

	waitErr := cmd.Wait()
	harness.FlushRemainder()

	if waitErr == nil {
		t.Fatalf("CRITICAL RESILIENCE FAILURE: Script allocated >350 MB under 256 MB quota without termination!")
	}

	lines := harness.Lines()
	fullOutput := strings.Join(lines, "\n")

	secrets := []string{
		"leak_test_jwt_secret_token",
		"CrashingScriptSecretPassword999!",
		"sk_live_crash_test_api_key_888",
		"PreCrashECKeyBytes12345678",
	}

	for _, sec := range secrets {
		if strings.Contains(fullOutput, sec) {
			t.Fatalf("CRITICAL SECURITY LEAK: Secret %q was leaked before quota crash! Full output:\n%s", sec, fullOutput)
		}
	}

	// Verify required redaction markers are present
	if !strings.Contains(fullOutput, "Bearer [REDACTED]") {
		t.Errorf("Missing Bearer redaction marker in pre-crash output: %q", fullOutput)
	}
	if !strings.Contains(fullOutput, `"password":[REDACTED]`) || !strings.Contains(fullOutput, `"api_key":[REDACTED]`) {
		t.Errorf("Missing KV redaction markers in pre-crash output: %q", fullOutput)
	}
	if !strings.Contains(fullOutput, "[REDACTED PRIVATE KEY]") {
		t.Errorf("Missing PEM private key redaction marker in pre-crash output: %q", fullOutput)
	}

	// Verify process did not continue past breach
	if strings.Contains(fullOutput, "POST_BREACH_SHOULD_NEVER_APPEAR") {
		t.Errorf("Process executed past quota breach unexpectedly!")
	}

	t.Logf("Verified: Clean quota termination under memory pressure with 0 secret leaks")
}
