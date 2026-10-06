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
// 1. Empirical Byte-by-Byte Streaming Deep Stress Tests
// ============================================================================

func TestEmpirical_ByteByByte_DeepStress(t *testing.T) {
	testCases := []struct {
		name         string
		input        string
		mustContain  []string
		secretsOmit  []string
		withNewline  bool
	}{
		{
			name: "Complex JSON credentials fed 1 byte at a time",
			input: "{\"auth\": {\"password\": \"BytePass123!\", \"token\": \"ghp_ByteTok456\", \"api_key\": \"sk_live_ByteKey789\"}}\n",
			mustContain: []string{
				"\"password\":[REDACTED]",
				"\"token\":[REDACTED]",
				"\"api_key\":[REDACTED]",
			},
			secretsOmit: []string{"BytePass123!", "ghp_ByteTok456", "sk_live_ByteKey789"},
			withNewline: true,
		},
		{
			name: "URL query parameters with & and @ delimiters fed 1 byte at a time",
			input: "GET /api/v1?token=secret_query_tok&password=secret_query_pass&user=admin@example.com HTTP/1.1\n",
			mustContain: []string{
				"token=[REDACTED]",
				"password=[REDACTED]",
				"user=admin@example.com",
			},
			secretsOmit: []string{"secret_query_tok", "secret_query_pass"},
			withNewline: true,
		},
		{
			name: "Bearer token containing @, =, +, and - characters fed 1 byte at a time",
			input: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.user@corp.local+sub-key=val/123==\n",
			mustContain: []string{
				"Authorization: Bearer [REDACTED]\n",
			},
			secretsOmit: []string{"user@corp.local", "sub-key=val"},
			withNewline: true,
		},
		{
			name: "English prose containing bearer must NOT be redacted when fed 1 byte at a time",
			input: "The bearer of these bearer bonds must present identification before any transaction.\n",
			mustContain: []string{
				"The bearer of these bearer bonds must present identification before any transaction.\n",
			},
			secretsOmit: nil,
			withNewline: true,
		},
		{
			name: "Unterminated secret line (flush required) fed 1 byte at a time",
			input: "diagnostic_log user=root secret:TopSecretUnterminatedToken_445566",
			mustContain: []string{
				"diagnostic_log user=root secret:[REDACTED]\n",
			},
			secretsOmit: []string{"TopSecretUnterminatedToken_445566"},
			withNewline: false,
		},
		{
			name: "Full 4-line PEM EC private key block fed 1 byte at a time",
			input: "-----BEGIN EC PRIVATE KEY-----\n" +
				"MHcCAQEEIIn2J+59sSampleEcKeyBytes8899aabbccddeeff\n" +
				"AoGCCqGSM49AwEHoUQDQgAE\n" +
				"-----END EC PRIVATE KEY-----\n",
			mustContain: []string{
				"[REDACTED PRIVATE KEY]\n",
			},
			secretsOmit: []string{
				"MHcCAQEEIIn2J+59sSampleEcKeyBytes8899aabbccddeeff",
				"AoGCCqGSM49AwEHoUQDQgAE",
			},
			withNewline: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var received []string
			stream := newScriptStream(func(line string) {
				mu.Lock()
				received = append(received, line)
				mu.Unlock()
			})

			for i := 0; i < len(tc.input); i++ {
				n, err := stream.Write([]byte{tc.input[i]})
				if err != nil || n != 1 {
					t.Fatalf("Write byte %d failed: n=%d, err=%v", i, n, err)
				}
			}

			if !tc.withNewline {
				stream.flush()
			}

			mu.Lock()
			emitted := strings.Join(received, "")
			mu.Unlock()
			captured := stream.String()

			for _, sec := range tc.secretsOmit {
				if strings.Contains(emitted, sec) {
					t.Fatalf("CRITICAL LEAK: Secret %q found in emitted stream: %q", sec, emitted)
				}
				if strings.Contains(captured, sec) {
					t.Fatalf("CRITICAL LEAK: Secret %q found in captured buffer: %q", sec, captured)
				}
			}

			for _, exp := range tc.mustContain {
				if !strings.Contains(emitted, exp) {
					t.Errorf("Expected emitted to contain %q, got: %q", exp, emitted)
				}
				if !strings.Contains(captured, exp) {
					t.Errorf("Expected captured to contain %q, got: %q", exp, captured)
				}
			}
		})
	}
}

// ============================================================================
// 2. Empirical Boundary Splits across '=', '@', quotes, and PEM Headers
// ============================================================================

func TestEmpirical_BoundarySplits_Tokens(t *testing.T) {
	testCases := []struct {
		name        string
		chunks      []string
		mustContain string
		secretOmit  string
		flushEnd    bool
	}{
		{
			name: "Split directly across '=': 'pass' | 'word' | '=' | 'secret123'",
			chunks: []string{
				"Connecting ",
				"pass",
				"word",
				"=",
				"SecretVal_BoundaryEquals_999",
				" host=db.internal\n",
			},
			mustContain: "Connecting password=[REDACTED] host=db.internal\n",
			secretOmit:  "SecretVal_BoundaryEquals_999",
			flushEnd:    false,
		},
		{
			name: "Split across '@' in Bearer token: 'Bearer prefix' | '@' | 'domain.com=secret'",
			chunks: []string{
				"Authorization: Bearer eyJhbGciOi",
				"user",
				"@",
				"domain.corp.internal=secretpayload123\n",
			},
			mustContain: "Authorization: Bearer [REDACTED]\n",
			secretOmit:  "domain.corp.internal=secretpayload123",
			flushEnd:    false,
		},
		{
			name: "Split across JSON quotes and colon: '\"password\"' | ' : ' | '\"secret\"'",
			chunks: []string{
				"{\"config\": {",
				"\"pass",
				"word\"",
				" : ",
				"\"My Super Secret ",
				"Password With Spaces\"",
				"}}\n",
			},
			mustContain: "{\"config\": {\"password\":[REDACTED]}}\n",
			secretOmit:  "My Super Secret Password With Spaces",
			flushEnd:    false,
		},
		{
			name: "Split across PEM header delimiters: '-----' | 'BEGIN RSA ' | 'PRIVATE KEY-----'",
			chunks: []string{
				"-----",
				"BEGIN RSA ",
				"PRIVATE KEY-----",
				"\nMIIEowIBAAKCAQEA0Y1W9Z5l\n-----END RSA PRIVATE KEY-----\n",
			},
			mustContain: "[REDACTED PRIVATE KEY]\n",
			secretOmit:  "MIIEowIBAAKCAQEA0Y1W9Z5l",
			flushEnd:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var received []string
			stream := newScriptStream(func(line string) {
				mu.Lock()
				received = append(received, line)
				mu.Unlock()
			})

			for _, chunk := range tc.chunks {
				n, err := stream.Write([]byte(chunk))
				if err != nil || n != len(chunk) {
					t.Fatalf("Write chunk failed: %v", err)
				}
			}

			if tc.flushEnd {
				stream.flush()
			}

			mu.Lock()
			emitted := strings.Join(received, "")
			mu.Unlock()
			captured := stream.String()

			if strings.Contains(emitted, tc.secretOmit) {
				t.Fatalf("CRITICAL LEAK: secret %q leaked in emitted: %q", tc.secretOmit, emitted)
			}
			if strings.Contains(captured, tc.secretOmit) {
				t.Fatalf("CRITICAL LEAK: secret %q leaked in captured: %q", tc.secretOmit, captured)
			}
			if !strings.Contains(emitted, tc.mustContain) {
				t.Errorf("Emitted missing %q:\nGot: %q", tc.mustContain, emitted)
			}
		})
	}
}

// ============================================================================
// 3. Empirical PEM State Machine Stress & Lockup Escape
// ============================================================================

func TestEmpirical_PEMStateMachine_DeepLockupEscape(t *testing.T) {
	t.Run("Standalone PEM header followed by logs with spaces immediately escapes", func(t *testing.T) {
		sr := NewStreamRedactor()

		// Line 1: Standalone PEM header (no subsequent PEM body)
		l1 := sr.RedactLine("-----BEGIN RSA PRIVATE KEY-----")
		if l1 != "[REDACTED PRIVATE KEY]" {
			t.Fatalf("Line 1 expected [REDACTED PRIVATE KEY], got %q", l1)
		}

		// Line 2: Normal application log with spaces - must escape immediately and NOT be redacted as PEM
		l2 := sr.RedactLine("2026-10-01 12:00:00 INFO Service started on port 8080")
		if l2 != "2026-10-01 12:00:00 INFO Service started on port 8080" {
			t.Fatalf("Line 2 failed to escape PEM lockup! Got %q", l2)
		}

		// Line 3: Another normal line with a password secret - must be normally redacted as password
		l3 := sr.RedactLine("DB connection string user=postgres password=MyPostgresSecretPassword123 host=localhost")
		if strings.Contains(l3, "MyPostgresSecretPassword123") {
			t.Fatalf("Line 3 secret leaked: %q", l3)
		}
		if !strings.Contains(l3, "password=[REDACTED]") {
			t.Fatalf("Line 3 expected password=[REDACTED], got %q", l3)
		}
	})

	t.Run("Standalone PEM header followed by spaceless alphanumeric lines escapes at maxPEMLines cap", func(t *testing.T) {
		sr := NewStreamRedactor()

		// Line 0: Header
		sr.RedactLine("-----BEGIN PRIVATE KEY-----")

		// Emit 150 spaceless Base64-like lines (e.g. valid Base64 lines)
		for i := 1; i <= 150; i++ {
			line := fmt.Sprintf("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC%04d", i)
			res := sr.RedactLine(line)
			if res != "[REDACTED PRIVATE KEY]" {
				t.Fatalf("PEM body line %d expected [REDACTED PRIVATE KEY], got %q", i, res)
			}
		}

		// Line 151: Exceeds maxPEMLines = 150! Must break out of PEM lockup!
		line151 := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0151"
		res151 := sr.RedactLine(line151)
		// Should NOT be [REDACTED PRIVATE KEY] because cap was exceeded and line has no secret
		if res151 == "[REDACTED PRIVATE KEY]" {
			t.Fatalf("Line 151 failed to escape PEM lockup after maxPEMLines! Got %q", res151)
		}

		// Subsequent secret line must be processed normally
		secLine := sr.RedactLine("NormalLogAfterEscaping password=EscapedSecretValue456")
		if strings.Contains(secLine, "EscapedSecretValue456") {
			t.Fatalf("Secret leaked after escaping: %q", secLine)
		}
		if !strings.Contains(secLine, "password=[REDACTED]") {
			t.Fatalf("Expected password=[REDACTED], got %q", secLine)
		}
	})

	t.Run("PEM header with trailing text does NOT enter PEM block", func(t *testing.T) {
		sr := NewStreamRedactor()

		// Not ending with "PRIVATE KEY-----", so should NOT enter multi-line state
		l1 := sr.RedactLine("Notice: -----BEGIN PRIVATE KEY----- is the standard header")
		if !strings.Contains(l1, "[REDACTED PRIVATE KEY]") {
			t.Fatalf("Header expected [REDACTED PRIVATE KEY], got %q", l1)
		}

		// Next line is a single spaceless word. If it had entered PEM block, this would be redacted.
		// Since it did NOT enter PEM block, this should remain untouched!
		l2 := sr.RedactLine("DiagnosticsOutputStatus")
		if l2 != "DiagnosticsOutputStatus" {
			t.Fatalf("Line 2 was incorrectly redacted as PEM body! Got %q", l2)
		}
	})

	t.Run("Public key block must NOT enter PEM private key state or be redacted", func(t *testing.T) {
		sr := NewStreamRedactor()

		pubLines := []string{
			"-----BEGIN PUBLIC KEY-----",
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y1W9Z5luE9O5bK0Jk1M",
			"2N3P4Q5R6S7TuV8W9X0Y1Z2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u",
			"-----END PUBLIC KEY-----",
		}

		for _, l := range pubLines {
			res := sr.RedactLine(l)
			if res != l {
				t.Fatalf("Public key line %q was incorrectly modified to %q", l, res)
			}
		}
	})

	t.Run("Consecutive PEM blocks without intervening lines", func(t *testing.T) {
		sr := NewStreamRedactor()

		lines := []string{
			"-----BEGIN RSA PRIVATE KEY-----",
			"MIIEowIBAAKCAQEA0Y1W9Z5l",
			"-----END RSA PRIVATE KEY-----",
			"-----BEGIN EC PRIVATE KEY-----",
			"MHcCAQEEIIzSampleECKeyBytes1234",
			"-----END EC PRIVATE KEY-----",
			"Post-PEM normal line",
		}

		for i, l := range lines {
			res := sr.RedactLine(l)
			if i < 6 {
				if res != "[REDACTED PRIVATE KEY]" {
					t.Fatalf("PEM line %d %q expected [REDACTED PRIVATE KEY], got %q", i, l, res)
				}
			} else {
				if res != "Post-PEM normal line" {
					t.Fatalf("Post-PEM line expected untouched, got %q", res)
				}
			}
		}
	})
}

// ============================================================================
// 4. Extreme Line Lengths (64 KB and 1 MB) Stress Tests
// ============================================================================

func TestEmpirical_ExtremeLine_64KB_and_1MB(t *testing.T) {
	t.Run("64KB line with multiple secret types and complex delimiters", func(t *testing.T) {
		sec1 := "Sec64_Pass_111"
		sec2 := "Sec64_Tok_222"
		sec3 := "Sec64_Bearer_333"
		sec4 := "Sec64_ApiKey_444"

		pad := strings.Repeat("A", 25*1024)
		line := fmt.Sprintf("START password=%s %s token=\"%s\" %s Bearer %s %s api_key:%s END\n",
			sec1, pad, sec2, pad, sec3, pad, sec4)

		if len(line) < 64*1024 {
			t.Fatalf("Line length %d < 64KB", len(line))
		}

		var mu sync.Mutex
		var received []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			received = append(received, l)
			mu.Unlock()
		})

		start := time.Now()
		_, err := stream.Write([]byte(line))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		stream.flush()
		dur := time.Since(start)

		mu.Lock()
		emitted := strings.Join(received, "")
		mu.Unlock()
		captured := stream.String()

		for _, sec := range []string{sec1, sec2, sec3, sec4} {
			if strings.Contains(emitted, sec) {
				t.Fatalf("CRITICAL LEAK: %q in 64KB emitted!", sec)
			}
			if strings.Contains(captured, sec) {
				t.Fatalf("CRITICAL LEAK: %q in 64KB captured!", sec)
			}
		}

		t.Logf("Empirical 64KB line (%d bytes) verified in %v", len(line), dur)
	})

	t.Run("1MB line with trailing newline", func(t *testing.T) {
		sec1 := "MegaEmpiricalPass_111"
		sec2 := "MegaEmpiricalTok_222"
		sec3 := "MegaEmpiricalBearer_333"

		pad := strings.Repeat("M", 550*1024)
		line := fmt.Sprintf("START password=%s %s token=%s %s Bearer %s END\n", sec1, pad, sec2, pad, sec3)

		if len(line) < 1024*1024 {
			t.Fatalf("Line length %d < 1MB", len(line))
		}

		var mu sync.Mutex
		var received []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			received = append(received, l)
			mu.Unlock()
		})

		start := time.Now()
		_, err := stream.Write([]byte(line))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		stream.flush()
		dur := time.Since(start)

		mu.Lock()
		emitted := strings.Join(received, "")
		mu.Unlock()
		captured := stream.String()

		for _, sec := range []string{sec1, sec2, sec3} {
			if strings.Contains(emitted, sec) {
				t.Fatalf("CRITICAL LEAK: %q in 1MB emitted!", sec)
			}
			if strings.Contains(captured, sec) {
				t.Fatalf("CRITICAL LEAK: %q in 1MB captured!", sec)
			}
		}

		if !strings.HasSuffix(captured, scriptTruncated) {
			t.Fatalf("Expected 1MB captured buffer to be marked with scriptTruncated")
		}

		t.Logf("Empirical 1MB line with newline (%d bytes) verified in %v", len(line), dur)
	})

	t.Run("1MB line without newline triggers maxScriptLine cleanly", func(t *testing.T) {
		sec1 := "MegaNoNL_Pass_444"
		sec2 := "MegaNoNL_Bearer_555"

		pad := strings.Repeat("N", 600*1024)
		// Total > 1,048,576 bytes without newline
		line := fmt.Sprintf("START password=%s %s Bearer %s %s END", sec1, pad, sec2, pad)

		var mu sync.Mutex
		var received []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			received = append(received, l)
			mu.Unlock()
		})

		_, err := stream.Write([]byte(line))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		stream.flush()

		mu.Lock()
		emitted := strings.Join(received, "")
		mu.Unlock()
		captured := stream.String()

		for _, sec := range []string{sec1, sec2} {
			if strings.Contains(emitted, sec) {
				t.Fatalf("CRITICAL LEAK: %q in endless line emitted!", sec)
			}
			if strings.Contains(captured, sec) {
				t.Fatalf("CRITICAL LEAK: %q in endless line captured!", sec)
			}
		}
	})
}

// ============================================================================
// 5. High Concurrency & Data Race Verification
// ============================================================================

func TestEmpirical_Concurrency_Stress(t *testing.T) {
	t.Run("50 concurrent goroutines writing to single scriptStream", func(t *testing.T) {
		var mu sync.Mutex
		var receivedLines []string
		stream := newScriptStream(func(line string) {
			mu.Lock()
			receivedLines = append(receivedLines, line)
			mu.Unlock()
		})

		const numWorkers = 50
		const linesPerWorker = 30
		var wg sync.WaitGroup

		start := make(chan struct{})

		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				<-start

				for l := 0; l < linesPerWorker; l++ {
					line := fmt.Sprintf("W%02d L%03d: password=Pass_%d_%d token=Tok_%d_%d Bearer Jwt_%d_%d api_key:Key_%d_%d\n",
						id, l, id, l, id, l, id, l, id, l)
					_, err := stream.Write([]byte(line))
					if err != nil {
						t.Errorf("Worker %d write error: %v", id, err)
					}
				}
			}(w)
		}

		close(start)
		wg.Wait()
		stream.flush()

		mu.Lock()
		allEmitted := strings.Join(receivedLines, "")
		total := len(receivedLines)
		mu.Unlock()

		if total != numWorkers*linesPerWorker {
			t.Fatalf("Expected %d lines, got %d", numWorkers*linesPerWorker, total)
		}

		// Verify no leaks under concurrency
		leakKeywords := []string{"Pass_", "Tok_", "Jwt_", "Key_"}
		for _, kw := range leakKeywords {
			if strings.Contains(allEmitted, kw) {
				t.Fatalf("CRITICAL LEAK: Unredacted keyword %q under concurrency!", kw)
			}
		}
	})

	t.Run("50 concurrent goroutines invoking StreamRedactor methods", func(t *testing.T) {
		sr := NewStreamRedactor()
		const numWorkers = 50
		const iters = 50
		var wg sync.WaitGroup

		start := make(chan struct{})

		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				<-start

				for i := 0; i < iters; i++ {
					line := fmt.Sprintf("Goroutine %d iter %d: password=P_%d_%d Bearer B_%d_%d",
						id, i, id, i, id, i)
					clean := sr.RedactLine(line)

					if strings.Contains(clean, fmt.Sprintf("P_%d_%d", id, i)) ||
						strings.Contains(clean, fmt.Sprintf("B_%d_%d", id, i)) {
						t.Errorf("CRITICAL LEAK in concurrent StreamRedactor: %q", clean)
					}

					if i%10 == 0 {
						sr.Reset()
					}
				}
			}(w)
		}

		close(start)
		wg.Wait()
	})
}

// ============================================================================
// 6. Randomized Fuzz Chunking over Mixed Payloads
// ============================================================================

func TestEmpirical_RandomFuzzChunking(t *testing.T) {
	// Construct a realistic, large mixed script output payload
	var buf bytes.Buffer
	var secrets []string

	for i := 0; i < 30; i++ {
		secP := fmt.Sprintf("FuzzSecretPassword_%d_%d", i, rand.Intn(10000))
		secB := fmt.Sprintf("FuzzBearerToken_%d_%d", i, rand.Intn(10000))
		secK := fmt.Sprintf("FuzzApiKey_%d_%d", i, rand.Intn(10000))
		secrets = append(secrets, secP, secB, secK)

		buf.WriteString(fmt.Sprintf("log_entry %d: connecting with password=%s and token=Bearer %s\n", i, secP, secB))
		buf.WriteString(fmt.Sprintf("{\"env\": {\"API_KEY\": \"%s\", \"PASSWD\": \"%s\"}}\n", secK, secP))
	}

	payload := buf.Bytes()

	// Try multiple random chunking seeds
	seeds := []int64{42, 1337, 2026, 99999}
	for _, seed := range seeds {
		r := rand.New(rand.NewSource(seed))

		var mu sync.Mutex
		var received []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			received = append(received, l)
			mu.Unlock()
		})

		pos := 0
		for pos < len(payload) {
			// Chunk size between 1 and 13 bytes
			chunkSize := r.Intn(13) + 1
			if pos+chunkSize > len(payload) {
				chunkSize = len(payload) - pos
			}
			chunk := payload[pos : pos+chunkSize]
			_, err := stream.Write(chunk)
			if err != nil {
				t.Fatalf("Write chunk failed at pos %d: %v", pos, err)
			}
			pos += chunkSize
		}
		stream.flush()

		mu.Lock()
		emitted := strings.Join(received, "")
		mu.Unlock()
		captured := stream.String()

		for _, sec := range secrets {
			if strings.Contains(emitted, sec) {
				t.Fatalf("CRITICAL LEAK with seed %d: secret %q found in emitted!", seed, sec)
			}
			if strings.Contains(captured, sec) {
				t.Fatalf("CRITICAL LEAK with seed %d: secret %q found in captured!", seed, sec)
			}
		}
	}
}
