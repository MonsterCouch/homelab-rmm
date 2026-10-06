package e2e_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/agent"
)

// ============================================================================
// Tier 1: Feature Coverage (R4 Real-Time Secret Redaction)
// ============================================================================

func TestE2E_Tier1_R4_BearerTokenRedaction(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Standard JWT Bearer token",
			input:    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcbeZrQzzz",
			expected: "Authorization: Bearer [REDACTED]",
		},
		{
			name:     "Opaque Bearer token with punctuation",
			input:    "Connecting with Bearer ya29.a0AfH6SMB_xyz-123~+/== to cloud API",
			expected: "Connecting with Bearer [REDACTED] to cloud API",
		},
		{
			name:     "Multiple Bearer tokens in one line",
			input:    "Token 1: Bearer token_one_12345; Token 2: Bearer token_two_67890",
			expected: "Token 1: Bearer [REDACTED]; Token 2: Bearer [REDACTED]",
		},
		{
			name:     "Bearer token with multiple spaces",
			input:    "Headers: Bearer   sk_test_abc123xyz456",
			expected: "Headers: Bearer [REDACTED]",
		},
		{
			name:     "Bearer prefix preservation check",
			input:    "Bearer secretTokenVal",
			expected: "Bearer [REDACTED]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := agent.RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("Mismatch for %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
			if strings.Contains(actual, "eyJhbGciOi") || strings.Contains(actual, "ya29") || strings.Contains(actual, "token_one_12345") {
				t.Fatalf("CRITICAL LEAK: Unredacted bearer token found in output: %q", actual)
			}
		})
	}
}

func TestE2E_Tier1_R4_KeyValuePasswordRedaction(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Standard password equals",
			input:    "Connecting to DB with user=admin password=SuperSecretPassword123! host=db.internal",
			expected: "Connecting to DB with user=admin password=[REDACTED] host=db.internal",
		},
		{
			name:     "Password colon syntax",
			input:    "Config parsed: password: P@ssw0rd!#$ for root",
			expected: "Config parsed: password:[REDACTED] for root",
		},
		{
			name:     "Passwd shorthand equals",
			input:    "Login attempt passwd=TempPass456;",
			expected: "Login attempt passwd=[REDACTED];",
		},
		{
			name:     "Case insensitive uppercase PASSWORD",
			input:    "SET PASSWORD=AllCapsSecretPassword",
			expected: "SET PASSWORD=[REDACTED]",
		},
		{
			name:     "Mixed casing PassWd with spaces around colon",
			input:    "Account PassWd  :  MySecret_Pass",
			expected: "Account PassWd:[REDACTED]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := agent.RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("Mismatch for %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
			if strings.Contains(actual, "SuperSecretPassword123") || strings.Contains(actual, "P@ssw0rd!#$") {
				t.Fatalf("CRITICAL LEAK: Unredacted password found in output: %q", actual)
			}
		})
	}
}

func TestE2E_Tier1_R4_KeyValueAPIKeyAndTokenRedaction(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "api_key parameter in command line",
			input:    "curl -H 'x-api-key: xyz' api_key=sk_live_998877665544332211",
			expected: "curl -H 'x-api-key: xyz' api_key=[REDACTED]",
		},
		{
			name:     "Uppercase API_KEY colon",
			input:    "Exported API_KEY: AKIAIOSFODNN7EXAMPLE",
			expected: "Exported API_KEY:[REDACTED]",
		},
		{
			name:     "Token key-value pair",
			input:    "Github token=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
			expected: "Github token=[REDACTED]",
		},
		{
			name:     "Secret key parameter",
			input:    "OAuth credentials: client_id=123 secret=topSecretClientSecretValue!",
			expected: "OAuth credentials: client_id=123 secret=[REDACTED]",
		},
		{
			name:     "TOKEN uppercase with equal sign",
			input:    "Session TOKEN=eyJhbGciOiJIUzI1NiJ9",
			expected: "Session TOKEN=[REDACTED]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := agent.RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("Mismatch for %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
			if strings.Contains(actual, "sk_live_9988776655") || strings.Contains(actual, "AKIAIOSFODNN7") {
				t.Fatalf("CRITICAL LEAK: Unredacted key/token found in output: %q", actual)
			}
		})
	}
}

func TestE2E_Tier1_R4_PEMPrivateKeyHeaderAndBlock(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "Full multi-line RSA private key block",
			input: "Certificate loaded:\n" +
				"-----BEGIN RSA PRIVATE KEY-----\n" +
				"MIIEowIBAAKCAQEA0Y1W9Z5l\n" +
				"uE9O5bK0Jk1M2N3P4Q5R6S7T\n" +
				"-----END RSA PRIVATE KEY-----\n" +
				"Status: Key loaded successfully",
			expected: "Certificate loaded:\n[REDACTED PRIVATE KEY]\nStatus: Key loaded successfully",
		},
		{
			name: "Full EC private key block",
			input: "-----BEGIN EC PRIVATE KEY-----\n" +
				"MHcCAQEEIIz...sampleECKeyBytes\n" +
				"-----END EC PRIVATE KEY-----",
			expected: "[REDACTED PRIVATE KEY]",
		},
		{
			name: "Full OPENSSH private key block",
			input: "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
				"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt\n" +
				"-----END OPENSSH PRIVATE KEY-----",
			expected: "[REDACTED PRIVATE KEY]",
		},
		{
			name:     "Single line PEM header without closing block",
			input:    "Log warning: Key dump started: -----BEGIN PRIVATE KEY-----",
			expected: "Log warning: Key dump started: [REDACTED PRIVATE KEY]",
		},
		{
			name:     "BEGIN ENCRYPTED PRIVATE KEY header",
			input:    "-----BEGIN ENCRYPTED PRIVATE KEY-----\nsecret_bytes\n-----END ENCRYPTED PRIVATE KEY-----",
			expected: "[REDACTED PRIVATE KEY]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := agent.RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("Mismatch for %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
			if strings.Contains(actual, "MIIEowIBAAKCAQEA0Y1W9Z5l") || strings.Contains(actual, "b3BlbnNzaC") {
				t.Fatalf("CRITICAL LEAK: Private key material leaked: %q", actual)
			}
		})
	}
}

func TestE2E_Tier1_R4_ChunkBoundarySplitHandling(t *testing.T) {
	harness := NewStreamingRedactHarness()

	// Simulate streaming output where secret is split across arbitrary Write() chunk boundaries:
	// Chunk 1: "User authenticated with pass"
	// Chunk 2: "word=SuperSecretPass999; and Bear"
	// Chunk 3: "er my_jwt_token_123456\n"
	// Chunk 4: "Next line is clean\n"

	chunks := []string{
		"User authenticated with pass",
		"word=SuperSecretPass999; and Bear",
		"er my_jwt_token_123456\n",
		"Next line is clean\n",
	}

	for _, chunk := range chunks {
		n, err := harness.Write([]byte(chunk))
		if err != nil {
			t.Fatalf("Unexpected write error: %v", err)
		}
		if n != len(chunk) {
			t.Fatalf("Short write: %d != %d", n, len(chunk))
		}
	}

	lines := harness.Lines()
	if len(lines) != 2 {
		t.Fatalf("Expected 2 lines, got %d: %v", len(lines), lines)
	}

	firstLine := lines[0]
	if strings.Contains(firstLine, "SuperSecretPass999") || strings.Contains(firstLine, "my_jwt_token_123456") {
		t.Fatalf("CRITICAL LEAK: Chunk split resulted in leaked secret! Line: %q", firstLine)
	}

	expectedFirstLine := "User authenticated with password=[REDACTED]; and Bearer [REDACTED]"
	if firstLine != expectedFirstLine {
		t.Errorf("Reconstituted line mismatch:\nExpected: %q\nActual:   %q", expectedFirstLine, firstLine)
	}

	if lines[1] != "Next line is clean" {
		t.Errorf("Clean line corrupted: %q", lines[1])
	}
}

func TestE2E_Tier1_R4_StreamRedactorDirect(t *testing.T) {
	sr := agent.NewStreamRedactor()
	lines := []string{
		"Status: Key generator starting",
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIEowIBAAKCAQEA0Y1W9Z5l",
		"uE9O5bK0Jk1M2N3P4Q5R6S7T",
		"-----END RSA PRIVATE KEY-----",
		"Status: Finished password=SecretRoot123 Bearer token_e2e_direct_12345",
	}
	expected := []string{
		"Status: Key generator starting",
		"[REDACTED PRIVATE KEY]",
		"[REDACTED PRIVATE KEY]",
		"[REDACTED PRIVATE KEY]",
		"[REDACTED PRIVATE KEY]",
		"Status: Finished password=[REDACTED] Bearer [REDACTED]",
	}
	for idx, line := range lines {
		actual := sr.RedactLine(line)
		if actual != expected[idx] {
			t.Errorf("Line %d mismatch:\nExpected: %q\nActual:   %q", idx, expected[idx], actual)
		}
	}
}

func TestE2E_Tier1_R4_MixedSecretsInSingleLine(t *testing.T) {
	input := "Deploy: token=ghp_SecretToken123 secret=TopSecretKey password=MyRootPassword Bearer eyJhbGciOi"
	expected := "Deploy: token=[REDACTED] secret=[REDACTED] password=[REDACTED] Bearer [REDACTED]"

	actual := agent.RedactSecrets(input)
	if actual != expected {
		t.Errorf("Mixed secret redaction mismatch:\nExpected: %q\nActual:   %q", expected, actual)
	}
}

// ============================================================================
// Tier 2: Boundary & Corner Cases (R4)
// ============================================================================

func TestE2E_Tier2_R4_EmptyAndWhitespaceInputs(t *testing.T) {
	if agent.RedactSecrets("") != "" {
		t.Errorf("Expected empty string for empty input")
	}
	if agent.RedactSecrets("   \t  \n  ") != "   \t  \n  " {
		t.Errorf("Whitespace was altered unnecessarily")
	}
}

func TestE2E_Tier2_R4_ExtremeLengthStreamLine(t *testing.T) {
	// Construct a 64 KB line with secrets embedded at start, middle, and end
	prefix := "DEBUG_START: password=FirstSecretPass "
	padding := strings.Repeat("A", 32000)
	middle := " MIDDLE: Bearer MiddleBearerTokenXYZ "
	padding2 := strings.Repeat("B", 32000)
	suffix := " END: token=FinalTokenVal"

	giantLine := prefix + padding + middle + padding2 + suffix
	redacted := agent.RedactSecrets(giantLine)

	if strings.Contains(redacted, "FirstSecretPass") || strings.Contains(redacted, "MiddleBearerTokenXYZ") || strings.Contains(redacted, "FinalTokenVal") {
		t.Fatalf("Secret leaked in 64KB giant line!")
	}
	if !strings.Contains(redacted, "password=[REDACTED]") || !strings.Contains(redacted, "Bearer [REDACTED]") || !strings.Contains(redacted, "token=[REDACTED]") {
		t.Fatalf("Redaction marker missing in giant line!")
	}
}

func TestE2E_Tier2_R4_SpecialCharactersAndUnicode(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    "password=P@$$w0rd-with-symbols!#%*()_+{}[]\\|;:'\",.<>/?",
			expected: "password=[REDACTED];:'\",.<>/?", // Semicolon stops secret token
		},
		{
			input:    "secret=密码123456 token=トTOKEN_VAL_日本語",
			expected: "secret=[REDACTED] token=[REDACTED]",
		},
		{
			input:    "password=🔥SuperSafeEmojiPass🔥 other=val",
			expected: "password=[REDACTED] other=val",
		},
	}

	for _, tc := range testCases {
		actual := agent.RedactSecrets(tc.input)
		if actual != tc.expected {
			t.Errorf("Special character mismatch:\nExpected: %q\nActual:   %q", tc.expected, actual)
		}
		if strings.Contains(actual, "密码123456") || strings.Contains(actual, "SuperSafeEmojiPass") {
			t.Fatalf("Unicode/Emoji secret leaked: %q", actual)
		}
	}
}

// ============================================================================
// Tier 3: Cross-Feature Interactions (R4)
// ============================================================================

func TestE2E_Tier3_R4_ConcurrentStreamingRedaction(t *testing.T) {
	// Verify thread-safety and zero data corruption under concurrent stream chunks
	harness := NewStreamingRedactHarness()
	var wg sync.WaitGroup
	numWorkers := 10
	linesPerWorker := 50

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < linesPerWorker; j++ {
				chunk := fmt.Sprintf("Worker %d Line %d: password=Secret_%d_%d token=Tok_%d_%d\n", workerID, j, workerID, j, workerID, j)
				_, _ = harness.Write([]byte(chunk))
			}
		}(i)
	}

	wg.Wait()
	lines := harness.Lines()
	if len(lines) != numWorkers*linesPerWorker {
		t.Fatalf("Expected %d lines, got %d", numWorkers*linesPerWorker, len(lines))
	}

	for idx, line := range lines {
		if strings.Contains(line, "Secret_") || strings.Contains(line, "Tok_") {
			t.Fatalf("Leak in line %d: %q", idx, line)
		}
		if !strings.Contains(line, "password=[REDACTED]") || !strings.Contains(line, "token=[REDACTED]") {
			t.Fatalf("Missing redaction marker in line %d: %q", idx, line)
		}
	}
}

// ============================================================================
// Tier 4: Real-World Scenarios (R4)
// ============================================================================

func TestE2E_Tier4_R4_TechnicianDiagnosticOutputSanitization(t *testing.T) {
	// Scenario: Technician executes a diagnostic command that dumps environment
	// variables and connection strings containing critical cloud secrets.
	diagnosticDump := `
[2026-09-30 20:00:00] Starting host diagnostic survey...
OS: Microsoft Windows 11 Pro 10.0.26100
Host: homelab-srv-01
Environment variables:
  API_KEY: AKIAIOSFODNN7EXAMPLE
  SECRET: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  DATABASE_URL=postgres://app_user:password=ComplexSecret_9988@db.homelab.internal:5432/production
  GITHUB_TOKEN: token=ghp_990088112233aabbccddeeffgghhiijjkkll
  SERVICE_API_KEY: api_key=sk_live_abcdef1234567890abcdef1234567890
Checking TLS certificates:
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz7rL5q2M1...base64privatekeydata...
-----END RSA PRIVATE KEY-----
Diagnostic completed with exit code 0.
`

	harness := NewStreamingRedactHarness()
	for _, line := range strings.Split(diagnosticDump, "\n") {
		_, _ = harness.Write([]byte(line + "\n"))
	}

	sanitizedLines := harness.Lines()
	fullOutput := strings.Join(sanitizedLines, "\n")

	// Ensure no secrets leaked
	criticalSecrets := []string{
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"ComplexSecret_9988",
		"ghp_990088112233aabbccddeeffgghhiijjkkll",
		"sk_live_abcdef1234567890abcdef1234567890",
		"base64privatekeydata",
	}

	for _, secret := range criticalSecrets {
		if strings.Contains(fullOutput, secret) {
			t.Fatalf("CRITICAL SECURITY LEAK: %q was present in sanitized output!", secret)
		}
	}

	// Verify benign diagnostic context was preserved
	if !strings.Contains(fullOutput, "Microsoft Windows 11 Pro") || !strings.Contains(fullOutput, "homelab-srv-01") {
		t.Fatalf("Benign diagnostic data was corrupted!")
	}
	if !strings.Contains(fullOutput, "Diagnostic completed with exit code 0") {
		t.Fatalf("Status completion message was lost!")
	}
}
