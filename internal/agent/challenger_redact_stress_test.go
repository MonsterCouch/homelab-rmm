package agent

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Category 1: Whitespace, Casing, and Character Boundaries (Robustness)
// ============================================================================

func TestChallengerRedact_WhitespaceAndCasing_Robustness(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		mustContain []string
		mustOmit    []string
	}{
		{
			name:        "Bearer with single tab",
			input:       "Authorization: Bearer\tTabBearerTokenValue123",
			mustContain: []string{"Authorization: Bearer [REDACTED]"},
			mustOmit:    []string{"TabBearerTokenValue123"},
		},
		{
			name:        "Bearer with multiple tabs and spaces",
			input:       "Auth: Bearer \t \t MultiTabToken456",
			mustContain: []string{"Auth: Bearer [REDACTED]"},
			mustOmit:    []string{"MultiTabToken456"},
		},
		{
			name:        "Mixed casing: pAsSwOrD with colon and tabs",
			input:       "Login pAsSwOrD\t:\tCrazyCaseSecretPass",
			mustContain: []string{"Login pAsSwOrD:[REDACTED]"},
			mustOmit:    []string{"CrazyCaseSecretPass"},
		},
		{
			name:        "Mixed casing: tOkEn with equals",
			input:       "Session tOkEn=MixedCaseTokenVal789",
			mustContain: []string{"Session tOkEn=[REDACTED]"},
			mustOmit:    []string{"MixedCaseTokenVal789"},
		},
		{
			name:        "Mixed casing: sEcReT with colon and spaces",
			input:       "Client sEcReT  :   MixedCaseSecret999",
			mustContain: []string{"Client sEcReT:[REDACTED]"},
			mustOmit:    []string{"MixedCaseSecret999"},
		},
		{
			name:        "Mixed casing: aPi_KeY with equals",
			input:       "Header aPi_KeY=MixedCaseApiKeyVal111",
			mustContain: []string{"Header aPi_KeY=[REDACTED]"},
			mustOmit:    []string{"MixedCaseApiKeyVal111"},
		},
		{
			name:        "Mixed casing: pAsSwD with colon",
			input:       "Config pAsSwD:MixedCasePasswdVal222",
			mustContain: []string{"Config pAsSwD:[REDACTED]"},
			mustOmit:    []string{"MixedCasePasswdVal222"},
		},
		{
			name:        "Mixed casing: bEaReR token",
			input:       "Authorization: bEaReR myStrangeCaseBearer333",
			mustContain: []string{"Authorization: Bearer [REDACTED]"},
			mustOmit:    []string{"myStrangeCaseBearer333"},
		},
		{
			name:        "Delimiters with internal carriage returns or newlines avoided",
			input:       "password=secretVal\r\nnext_line=normal",
			mustContain: []string{"password=[REDACTED]", "next_line=normal"},
			mustOmit:    []string{"secretVal"},
		},
		{
			name:        "Zero-width space in password value is redacted",
			input:       "password:secret\u200Bvalue",
			mustContain: []string{"password:[REDACTED]"},
			mustOmit:    []string{"secret\u200Bvalue"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			for _, exp := range tc.mustContain {
				if !strings.Contains(actual, exp) {
					t.Errorf("Expected output to contain %q, but got %q", exp, actual)
				}
			}
			for _, leak := range tc.mustOmit {
				if strings.Contains(actual, leak) {
					t.Fatalf("CRITICAL LEAK: secret %q leaked in %q", leak, actual)
				}
			}
		})
	}
}

// ============================================================================
// Category 2: Huge 100KB Tokens and ReDoS Immunity (Performance)
// ============================================================================

func TestChallengerRedact_Huge100KBTokens_Performance(t *testing.T) {
	// 100 KB Bearer token
	token100KB := strings.Repeat("A1b2C3d4-._~+/", 7000) // ~98 KB
	bearerInput := "Header Authorization: Bearer " + token100KB + " trailing"
	start := time.Now()
	redactedBearer := RedactSecrets(bearerInput)
	durationBearer := time.Since(start)

	if durationBearer > 1*time.Second {
		t.Fatalf("Performance degradation: 100KB Bearer took %v (possible ReDoS)", durationBearer)
	}
	t.Logf("100KB Bearer redaction completed in %v", durationBearer)
	if strings.Contains(redactedBearer, token100KB) {
		t.Fatalf("CRITICAL LEAK: 100KB Bearer token leaked!")
	}
	if !strings.Contains(redactedBearer, "Bearer [REDACTED] trailing") {
		t.Fatalf("Expected 'Bearer [REDACTED] trailing', got %q", redactedBearer[:min(len(redactedBearer), 200)])
	}

	// 100 KB Password
	pass100KB := strings.Repeat("Secr3tP@ss!", 10000) // 110 KB
	passInput := "Database password=" + pass100KB + " connected"
	start = time.Now()
	redactedPass := RedactSecrets(passInput)
	durationPass := time.Since(start)

	if durationPass > 1*time.Second {
		t.Fatalf("Performance degradation: 100KB password took %v (possible ReDoS)", durationPass)
	}
	t.Logf("100KB Password redaction completed in %v", durationPass)
	if strings.Contains(redactedPass, pass100KB) {
		t.Fatalf("CRITICAL LEAK: 100KB password leaked!")
	}
	if !strings.Contains(redactedPass, "Database password=[REDACTED] connected") {
		t.Fatalf("Expected 'Database password=[REDACTED] connected', got %q", redactedPass[:min(len(redactedPass), 200)])
	}

	// 100 KB Multi-line PEM block
	pemBody := strings.Repeat("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n", 2000)
	pemInput := "-----BEGIN RSA PRIVATE KEY-----\n" + pemBody + "-----END RSA PRIVATE KEY-----"
	start = time.Now()
	redactedPEM := RedactSecrets(pemInput)
	durationPEM := time.Since(start)

	if durationPEM > 1*time.Second {
		t.Fatalf("Performance degradation: 100KB PEM took %v", durationPEM)
	}
	t.Logf("100KB PEM block redaction completed in %v", durationPEM)
	if strings.Contains(redactedPEM, "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7") {
		t.Fatalf("CRITICAL LEAK: 100KB PEM private key body leaked!")
	}
	if redactedPEM != "[REDACTED PRIVATE KEY]" {
		t.Fatalf("Expected '[REDACTED PRIVATE KEY]', got %q", redactedPEM[:min(len(redactedPEM), 200)])
	}
}

// ============================================================================
// Category 3: False Positive Resilience (Non-Secret Preservation)
// ============================================================================

func TestChallengerRedact_NonSecretPreservation_FalsePositives(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Public key header and block must NOT be redacted",
			input:    "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----",
			expected: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----",
		},
		{
			name:     "RSA Public key header must NOT be redacted",
			input:    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA0Y1W9Z5l\n-----END RSA PUBLIC KEY-----",
			expected: "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA0Y1W9Z5l\n-----END RSA PUBLIC KEY-----",
		},
		{
			name:     "Certificate block must NOT be redacted",
			input:    "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAL0p\n-----END CERTIFICATE-----",
			expected: "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAL0p\n-----END CERTIFICATE-----",
		},
		{
			name:     "BearerNotAToken must NOT be redacted",
			input:    "Class BearerNotAToken extends TokenHandler {",
			expected: "Class BearerNotAToken extends TokenHandler {",
		},
		{
			name:     "Bearer with non-token characters must NOT be redacted",
			input:    "Bearer ??? error in parsing",
			expected: "Bearer ??? error in parsing",
		},
		{
			name:     "password_strength=strong must NOT be redacted",
			input:    "Validation check: password_strength=strong score=95",
			expected: "Validation check: password_strength=strong score=95",
		},
		{
			name:     "password_policy=enforced must NOT be redacted",
			input:    "Security setting: password_policy=enforced for domain",
			expected: "Security setting: password_policy=enforced for domain",
		},
		{
			name:     "password_length: 16 must NOT be redacted",
			input:    "Config setting: password_length: 16 characters required",
			expected: "Config setting: password_length: 16 characters required",
		},
		{
			name:     "password_hash must NOT be redacted (it is non-reversible hash verification)",
			input:    "Stored record: password_hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expected: "Stored record: password_hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "token_count: 512 must NOT be redacted",
			input:    "Metrics token_count: 512 consumed in session",
			expected: "Metrics token_count: 512 consumed in session",
		},
		{
			name:     "tokenizer_model: gpt-4 must NOT be redacted",
			input:    "Engine setting tokenizer_model: gpt-4 initialized",
			expected: "Engine setting tokenizer_model: gpt-4 initialized",
		},
		{
			name:     "secret_handshake: valid must NOT be redacted",
			input:    "Peer handshake: secret_handshake: valid across nodes",
			expected: "Peer handshake: secret_handshake: valid across nodes",
		},
		{
			name:     "secrecy: high must NOT be redacted",
			input:    "Project classification: secrecy: high priority",
			expected: "Project classification: secrecy: high priority",
		},
		{
			name:     "api_gateway_url must NOT be redacted",
			input:    "Route info api_gateway_url=https://api.internal/v1",
			expected: "Route info api_gateway_url=https://api.internal/v1",
		},
		{
			name:     "passphrase_prompt must NOT be redacted",
			input:    "Status: passphrase_prompt=active waiting for user",
			expected: "Status: passphrase_prompt=active waiting for user",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("FALSE POSITIVE in %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
		})
	}
}

// ============================================================================
// Category 4: Secrets Embedded in YAML, XML, and Environment Variables
// ============================================================================

func TestChallengerRedact_EmbeddedFormats_YAML_XML_Env(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		mustContain []string
		mustOmit    []string
	}{
		{
			name: "YAML configuration block",
			input: "database:\n  host: db.homelab.lan\n  port: 5432\n  user: rmm\n  password: YamlSecretPassword999\n  token: YamlToken888\n",
			mustContain: []string{
				"host: db.homelab.lan",
				"password:[REDACTED]",
				"token:[REDACTED]",
			},
			mustOmit: []string{"YamlSecretPassword999", "YamlToken888"},
		},
		{
			name: "XML tag attributes containing secrets",
			input: `<connection user="admin" password="XmlSecretPassword111" api_key="XmlApiKey222" />`,
			mustContain: []string{
				`<connection user="admin"`,
				`password=[REDACTED]`,
				`api_key=[REDACTED]`,
			},
			mustOmit: []string{"XmlSecretPassword111", "XmlApiKey222"},
		},
		{
			name: "Environment variables export",
			input: "export DB_PASSWORD=SecretEnvPass333\nexport API_KEY=SecretEnvKey444\nexport GITHUB_TOKEN=SecretEnvTok555\n",
			mustContain: []string{
				"PASSWORD=[REDACTED]",
				"API_KEY=[REDACTED]",
				"TOKEN=[REDACTED]",
			},
			mustOmit: []string{"SecretEnvPass333", "SecretEnvKey444", "SecretEnvTok555"},
		},
		{
			name: "PowerShell environment assignments",
			input: `$env:PASSWORD = "SecretPsPassword666"; $env:TOKEN = "SecretPsToken777"`,
			mustContain: []string{
				`PASSWORD=[REDACTED]`,
				`TOKEN=[REDACTED]`,
			},
			mustOmit: []string{"SecretPsPassword666", "SecretPsToken777"},
		},
		{
			name: "Clustered secrets with space separation",
			input: "Bearer tokAlpha password=passBeta Bearer tokGamma secret:secDelta token=tokEpsilon",
			mustContain: []string{"Bearer [REDACTED]", "password=[REDACTED]", "secret:[REDACTED]", "token=[REDACTED]"},
			mustOmit:    []string{"tokAlpha", "passBeta", "tokGamma", "secDelta", "tokEpsilon"},
		},
		{
			name: "Clustered secrets with commas",
			input: "password=p1,token=t2,secret=s3,api_key=k4,passwd=pw5",
			mustContain: []string{"password=[REDACTED]", "token=[REDACTED]", "secret=[REDACTED]", "api_key=[REDACTED]", "passwd=[REDACTED]"},
			mustOmit:    []string{"p1", "t2", "s3", "k4", "pw5"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			for _, exp := range tc.mustContain {
				if !strings.Contains(actual, exp) {
					t.Errorf("Expected output to contain %q, but got %q", exp, actual)
				}
			}
			for _, leak := range tc.mustOmit {
				if strings.Contains(actual, leak) {
					t.Fatalf("CRITICAL LEAK: secret %q leaked in %q", leak, actual)
				}
			}
		})
	}
}

// ============================================================================
// Category 5: StreamRedactor and ScriptStream Stress
// ============================================================================

func TestChallengerRedact_StreamRedactor_Stress(t *testing.T) {
	t.Run("Multi-line PEM with interspersed normal logs and multiple keys", func(t *testing.T) {
		sr := NewStreamRedactor()

		streamLines := []struct {
			input    string
			expected string
		}{
			{"Log 1: Starting agent", "Log 1: Starting agent"},
			{"-----BEGIN RSA PRIVATE KEY-----", "[REDACTED PRIVATE KEY]"},
			{"MIIEowIBAAKCAQEA0Y1W9Z5l", "[REDACTED PRIVATE KEY]"},
			{"uE9O5bK0Jk1M2N3P4Q5R6S7T", "[REDACTED PRIVATE KEY]"},
			{"-----END RSA PRIVATE KEY-----", "[REDACTED PRIVATE KEY]"},
			{"Log 2: Middle status normal", "Log 2: Middle status normal"},
			{"Log 3: Bearer myInterspersedToken123", "Log 3: Bearer [REDACTED]"},
			{"-----BEGIN EC PRIVATE KEY-----", "[REDACTED PRIVATE KEY]"},
			{"MHcCAQEEIIz...sampleECKeyBytes", "[REDACTED PRIVATE KEY]"},
			{"-----END EC PRIVATE KEY-----", "[REDACTED PRIVATE KEY]"},
			{"Log 4: Finished key processing", "Log 4: Finished key processing"},
		}

		for i, sl := range streamLines {
			res := sr.RedactLine(sl.input)
			if res != sl.expected {
				t.Fatalf("Stream line %d (%q): expected %q, got %q", i, sl.input, sl.expected, res)
			}
		}
	})

	t.Run("Streaming Public Key must NOT be redacted line-by-line", func(t *testing.T) {
		sr := NewStreamRedactor()

		pubKeyLines := []string{
			"-----BEGIN PUBLIC KEY-----",
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y1W9Z5l",
			"-----END PUBLIC KEY-----",
		}

		for _, line := range pubKeyLines {
			res := sr.RedactLine(line)
			if res != line {
				t.Fatalf("Public key line was falsely redacted! Input: %q, Output: %q", line, res)
			}
		}
	})

	t.Run("Concurrent StreamRedactors under high contention", func(t *testing.T) {
		sr := NewStreamRedactor()
		var wg sync.WaitGroup
		concurrency := 20
		iterations := 100

		for c := 0; c < concurrency; c++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				for it := 0; it < iterations; it++ {
					line := fmt.Sprintf("Worker %d: password=SecretPass%d_%d Bearer tok%d_%d", workerID, workerID, it, workerID, it)
					res := sr.RedactLine(line)
					if strings.Contains(res, fmt.Sprintf("SecretPass%d_%d", workerID, it)) {
						t.Errorf("Worker %d leaked password!", workerID)
					}
					if strings.Contains(res, fmt.Sprintf("tok%d_%d", workerID, it)) {
						t.Errorf("Worker %d leaked bearer token!", workerID)
					}
				}
			}(c)
		}
		wg.Wait()
	})

	t.Run("ScriptStream byte-by-byte chunking boundary stress", func(t *testing.T) {
		var outputBuf bytes.Buffer
		var outMu sync.Mutex

		stream := newScriptStream(func(s string) {
			outMu.Lock()
			outputBuf.WriteString(s)
			outMu.Unlock()
		})

		secretText := "Deploying application with password=SuperFragmentedSecretPassword123 and token=SplitToken999\n"
		r := rand.New(rand.NewSource(42))

		idx := 0
		for idx < len(secretText) {
			chunkSize := r.Intn(4) + 1
			if idx+chunkSize > len(secretText) {
				chunkSize = len(secretText) - idx
			}
			chunk := []byte(secretText[idx : idx+chunkSize])
			_, err := stream.Write(chunk)
			if err != nil {
				t.Fatalf("Write error: %v", err)
			}
			idx += chunkSize
		}
		stream.flush()

		final := outputBuf.String()
		if strings.Contains(final, "SuperFragmentedSecretPassword123") {
			t.Fatalf("CRITICAL LEAK: Fragmented password leaked across chunk boundaries! Got: %q", final)
		}
		if strings.Contains(final, "SplitToken999") {
			t.Fatalf("CRITICAL LEAK: Fragmented token leaked across chunk boundaries! Got: %q", final)
		}
		if !strings.Contains(final, "password=[REDACTED]") || !strings.Contains(final, "token=[REDACTED]") {
			t.Fatalf("Redaction marker missing in fragmented stream! Got: %q", final)
		}
	})
}

// ============================================================================
// Category 6: Empirical Demonstration of Discovered Vulnerabilities & Gaps
// ============================================================================

// Defect 1 Remediated: Secrets in Standard JSON are properly redacted even when keys are quoted.
func TestChallengerRedact_Defect1_JSONKeyEvadesRedaction(t *testing.T) {
	jsonInputs := []struct {
		name   string
		json   string
		secret string
	}{
		{
			name:   "JSON password object",
			json:   `{"password": "SecretJsonPassword123!"}`,
			secret: "SecretJsonPassword123!",
		},
		{
			name:   "JSON token object",
			json:   `{"token": "ghp_JsonTokenVal456"}`,
			secret: "ghp_JsonTokenVal456",
		},
		{
			name:   "JSON api_key multi-line",
			json:   "{\n  \"api_key\": \"sk-live-jsonApiKey789\"\n}",
			secret: "sk-live-jsonApiKey789",
		},
		{
			name:   "JSON secret property",
			json:   `{"secret": "JsonSecretVal000"}`,
			secret: "JsonSecretVal000",
		},
	}

	for _, tc := range jsonInputs {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.json)
			if strings.Contains(actual, tc.secret) {
				t.Fatalf("CRITICAL LEAK: Secret %q leaked in JSON format!\nInput:  %s\nOutput: %s",
					tc.secret, tc.json, actual)
			}
			if !strings.Contains(actual, "[REDACTED]") {
				t.Fatalf("Expected redaction marker [REDACTED] in output, got: %s", actual)
			}
		})
	}
}

// Defect 2 Remediated: Quoted values containing spaces are completely redacted.
func TestChallengerRedact_Defect2_QuotedValuesWithSpacesLeak(t *testing.T) {
	input := `Config: password="Super Secret Complex Password" token="Token With Spaces"`
	actual := RedactSecrets(input)

	leakedPasswordSuffix := "Secret Complex Password"
	leakedTokenSuffix := "With Spaces"

	if strings.Contains(actual, leakedPasswordSuffix) || strings.Contains(actual, leakedTokenSuffix) {
		t.Fatalf("CRITICAL LEAK: Multi-word quoted secret leaked following words!\nInput:  %s\nOutput: %s",
			input, actual)
	}
	if !strings.Contains(actual, "password=[REDACTED]") || !strings.Contains(actual, "token=[REDACTED]") {
		t.Fatalf("Missing redaction markers in multi-word quoted secret output: %q", actual)
	}
}

// Defect 3 Remediated: English sentences using 'bearer' are preserved and not falsely redacted.
func TestChallengerRedact_Defect3_BearerFalsePositiveOnProse(t *testing.T) {
	proseCases := []struct {
		name     string
		sentence string
	}{
		{
			name:     "bearer of bad news",
			sentence: "He was the bearer of bad news regarding the outage",
		},
		{
			name:     "bearer must present ID",
			sentence: "The bearer must present identification at check-in",
		},
	}

	for _, tc := range proseCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.sentence)
			if strings.Contains(actual, "[REDACTED]") {
				t.Fatalf("FALSE POSITIVE: English prose was falsely redacted!\nInput:  %s\nOutput: %s",
					tc.sentence, actual)
			}
			if actual != tc.sentence {
				t.Fatalf("Prose altered unexpectedly:\nExpected: %q\nActual:   %q", tc.sentence, actual)
			}
		})
	}
}

// Defect 4 Remediated: URL query parameters without whitespace/semicolons are not greedily swallowed.
func TestChallengerRedact_Defect4_QueryStringParameterAbsorption(t *testing.T) {
	url := "https://api.internal/auth?token=myTokenVal123&user=admin&role=superadmin"
	actual := RedactSecrets(url)

	if strings.Contains(actual, "myTokenVal123") {
		t.Fatalf("CRITICAL LEAK: URL token secret leaked: %q", actual)
	}
	if !strings.Contains(actual, "token=[REDACTED]") {
		t.Fatalf("Missing token=[REDACTED] in URL output: %q", actual)
	}
	if !strings.Contains(actual, "user=admin") || !strings.Contains(actual, "role=superadmin") {
		t.Fatalf("OVER-REDACTION: Query parameters were swallowed by redactor: %q", actual)
	}
}
