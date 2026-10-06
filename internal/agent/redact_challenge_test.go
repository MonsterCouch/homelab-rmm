package agent

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ============================================================================
// Scenario 1: 1-Byte Writes Feeding PEM Private Key & Bearer Tokens Byte-by-Byte
// ============================================================================

func TestChallenger_ChunkBoundary_ByteByByte(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
		secrets  []string
		withNL   bool
	}{
		{
			name:     "JWT Bearer token 1 byte per write with newline",
			input:    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.s3cr3t_p@yload.xyz123\n",
			expected: "Authorization: Bearer [REDACTED]\n",
			secrets:  []string{"eyJhbGciOiJIUzI1NiJ9", "s3cr3t_p@yload"},
			withNL:   true,
		},
		{
			name:     "Opaque Bearer token with base64 padding 1 byte per write with newline",
			input:    "Header: Bearer ya29.a0AfH6SMB_xyz-123~+/==\n",
			expected: "Header: Bearer [REDACTED]\n",
			secrets:  []string{"ya29.a0AfH6SMB_xyz-123~+/=="},
			withNL:   true,
		},
		{
			name:     "Bearer token 1 byte per write without newline (flush test)",
			input:    "Authorization: Bearer my_flushed_bearer_token_999888",
			expected: "Authorization: Bearer [REDACTED]\n",
			secrets:  []string{"my_flushed_bearer_token_999888"},
			withNL:   false,
		},
		{
			name:     "Password equals 1 byte per write with newline",
			input:    "Connecting user=admin password=UltraSecretByteByBytePass123! host=db\n",
			expected: "Connecting user=admin password=[REDACTED] host=db\n",
			secrets:  []string{"UltraSecretByteByBytePass123!"},
			withNL:   true,
		},
		{
			name:     "API key colon 1 byte per write without newline (flush test)",
			input:    "Service dump api_key: sk_live_byte_by_byte_key_456789",
			expected: "Service dump api_key:[REDACTED]\n",
			secrets:  []string{"sk_live_byte_by_byte_key_456789"},
			withNL:   false,
		},
		{
			name: "PEM RSA private key block 1 byte per write",
			input: "-----BEGIN RSA PRIVATE KEY-----\n" +
				"MIIEowIBAAKCAQEA0Y1W9Z5l\n" +
				"uE9O5bK0Jk1M2N3P4Q5R6S7T\n" +
				"-----END RSA PRIVATE KEY-----\n",
			expected: "[REDACTED PRIVATE KEY]\n" +
				"[REDACTED PRIVATE KEY]\n" +
				"[REDACTED PRIVATE KEY]\n" +
				"[REDACTED PRIVATE KEY]\n",
			secrets: []string{"MIIEowIBAAKCAQEA0Y1W9Z5l", "uE9O5bK0Jk1M2N3P4Q5R6S7T"},
			withNL:  true,
		},
		{
			name: "PEM EC private key block 1 byte per write without newline (flush test)",
			input: "-----BEGIN EC PRIVATE KEY-----\n" +
				"MHcCAQEEIIzSampleECKeyBytes1234\n" +
				"-----END EC PRIVATE KEY-----",
			expected: "[REDACTED PRIVATE KEY]\n" +
				"[REDACTED PRIVATE KEY]\n" +
				"[REDACTED PRIVATE KEY]\n",
			secrets: []string{"MHcCAQEEIIzSampleECKeyBytes1234"},
			withNL:  false,
		},
		{
			name:     "Mixed secrets 1 byte per write",
			input:    "token=ghp_ByteTok1 secret:SecByte2 Bearer MyBearerTok3\n",
			expected: "token=[REDACTED] secret:[REDACTED] Bearer [REDACTED]\n",
			secrets:  []string{"ghp_ByteTok1", "SecByte2", "MyBearerTok3"},
			withNL:   true,
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

			// Write 1 byte at a time
			for i := 0; i < len(tc.input); i++ {
				b := []byte{tc.input[i]}
				n, err := stream.Write(b)
				if err != nil || n != 1 {
					t.Fatalf("Write byte %d failed: n=%d, err=%v", i, n, err)
				}
			}

			// If no trailing newline, flush must deliver the sanitized line
			if !tc.withNL {
				stream.flush()
			}

			mu.Lock()
			fullEmitted := strings.Join(received, "")
			mu.Unlock()

			// Check that no secrets leaked in streamed chunks
			for _, sec := range tc.secrets {
				if strings.Contains(fullEmitted, sec) {
					t.Fatalf("CRITICAL LEAK in byte-by-byte emitted stream: secret %q found in %q", sec, fullEmitted)
				}
			}

			// Check captured buffer
			captured := stream.String()
			for _, sec := range tc.secrets {
				if strings.Contains(captured, sec) {
					t.Fatalf("CRITICAL LEAK in byte-by-byte captured buffer: secret %q found in %q", sec, captured)
				}
			}

			if fullEmitted != tc.expected {
				t.Errorf("Emitted mismatch:\nExpected: %q\nActual:   %q", tc.expected, fullEmitted)
			}
		})
	}
}

// ============================================================================
// Scenario 2: Chunk Boundaries Falling Directly in Middle of Delimiters (=, :)
// ============================================================================

func TestChallenger_ChunkBoundary_MiddleOfEquals(t *testing.T) {
	testCases := []struct {
		name     string
		chunks   []string
		secret   string
		wantSub  string
		flushEnd bool
	}{
		{
			name:     "password in chunk 1, = in chunk 2, secret in chunk 3 with newline",
			chunks:   []string{"user=admin password", "=", "SecretVal456\n"},
			secret:   "SecretVal456",
			wantSub:  "user=admin password=[REDACTED]\n",
			flushEnd: false,
		},
		{
			name:     "password in chunk 1, = in chunk 2, secret in chunk 3 WITHOUT newline (flush)",
			chunks:   []string{"user=admin password", "=", "SecretValFlushed789"},
			secret:   "SecretValFlushed789",
			wantSub:  "user=admin password=[REDACTED]\n",
			flushEnd: true,
		},
		{
			name:     "passwd with spaces around equals split across 3 chunks",
			chunks:   []string{"config passwd   ", "   =   ", "MySpacedPasswd999;\n"},
			secret:   "MySpacedPasswd999",
			wantSub:  "config passwd=[REDACTED];\n",
			flushEnd: false,
		},
		{
			name:     "api_key in chunk 1, : in chunk 2, secret in chunk 3",
			chunks:   []string{"Header api_key", ":", "sk_live_MiddleOfColon123\n"},
			secret:   "sk_live_MiddleOfColon123",
			wantSub:  "Header api_key:[REDACTED]\n",
			flushEnd: false,
		},
		{
			name:     "secret with spaces around colon split across 3 chunks",
			chunks:   []string{"Client secret  ", "  :  ", "TopSecretValBytes888\n"},
			secret:   "TopSecretValBytes888",
			wantSub:  "Client secret:[REDACTED]\n",
			flushEnd: false,
		},
		{
			name:     "token in chunk 1, = in chunk 2, secret with comma in chunk 3",
			chunks:   []string{"Deploy token", "=", "ghp_MiddleEqualsTok,arg=next\n"},
			secret:   "ghp_MiddleEqualsTok",
			wantSub:  "Deploy token=[REDACTED],arg=next\n",
			flushEnd: false,
		},
		{
			name:     "Multiple delimiter splits across 7 chunks on single line",
			chunks:   []string{"password", "=", "pass1 Bear", "er ", "my_jwt_tok token", "=", "tok1\n"},
			secret:   "pass1",
			wantSub:  "password=[REDACTED] Bearer [REDACTED] token=[REDACTED]\n",
			flushEnd: false,
		},
		{
			name:     "Split in middle of PEM header across 3 chunks",
			chunks:   []string{"Key dump: -----BEGIN ", "RSA PRIVATE ", "KEY-----\n"},
			secret:   "RSA PRIVATE KEY",
			wantSub:  "Key dump: [REDACTED PRIVATE KEY]\n",
			flushEnd: false,
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

			for _, ch := range tc.chunks {
				n, err := stream.Write([]byte(ch))
				if err != nil || n != len(ch) {
					t.Fatalf("Write failed: n=%d, err=%v", n, err)
				}
			}

			if tc.flushEnd {
				stream.flush()
			}

			mu.Lock()
			emitted := strings.Join(received, "")
			mu.Unlock()
			captured := stream.String()

			if strings.Contains(emitted, tc.secret) {
				t.Fatalf("CRITICAL LEAK in emitted stream: %q found in %q", tc.secret, emitted)
			}
			if strings.Contains(captured, tc.secret) {
				t.Fatalf("CRITICAL LEAK in captured buffer: %q found in %q", tc.secret, captured)
			}
			if !strings.Contains(captured, tc.wantSub) {
				t.Errorf("Missing expected sanitized output %q in captured: %q", tc.wantSub, captured)
			}
		})
	}
}

// ============================================================================
// Scenario 3: Rapid Concurrent Writes to Stream & StreamRedactor
// ============================================================================

func TestChallenger_RapidConcurrentWrites_ScriptStream(t *testing.T) {
	var mu sync.Mutex
	var receivedLines []string
	stream := newScriptStream(func(line string) {
		mu.Lock()
		receivedLines = append(receivedLines, line)
		mu.Unlock()
	})

	const numWorkers = 20
	const linesPerWorker = 50
	var wg sync.WaitGroup

	startBarrier := make(chan struct{})

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startBarrier

			for l := 0; l < linesPerWorker; l++ {
				line := fmt.Sprintf("W%02d L%03d: password=SecretPass_%d_%d token=ghp_Tok_%d_%d Bearer JwtTok_%d_%d api_key:Key_%d_%d\n",
					workerID, l, workerID, l, workerID, l, workerID, l, workerID, l)
				_, err := stream.Write([]byte(line))
				if err != nil {
					t.Errorf("Worker %d write error: %v", workerID, err)
				}
			}
		}(w)
	}

	close(startBarrier)
	wg.Wait()
	stream.flush()

	mu.Lock()
	totalReceived := len(receivedLines)
	allEmitted := strings.Join(receivedLines, "")
	mu.Unlock()

	expectedLines := numWorkers * linesPerWorker
	if totalReceived != expectedLines {
		t.Fatalf("Line count mismatch: expected %d lines, received %d", expectedLines, totalReceived)
	}

	// Verify not a single secret leaked across any worker stream
	leakKeywords := []string{"SecretPass_", "ghp_Tok_", "JwtTok_", "Key_"}
	for _, kw := range leakKeywords {
		if strings.Contains(allEmitted, kw) {
			t.Fatalf("CRITICAL LEAK: Unredacted keyword %q detected in emitted output under concurrency!", kw)
		}
	}

	captured := stream.String()
	for _, kw := range leakKeywords {
		if strings.Contains(captured, kw) {
			t.Fatalf("CRITICAL LEAK: Unredacted keyword %q detected in captured buffer under concurrency!", kw)
		}
	}

	t.Logf("CONFIRMED: %d goroutines streamed %d total lines (%d bytes) with 0 leaks and 0 race conditions",
		numWorkers, expectedLines, len(captured))
}

func TestChallenger_RapidConcurrentWrites_StreamRedactor(t *testing.T) {
	redactor := NewStreamRedactor()
	const numGoroutines = 20
	const opsPerGoroutine = 100
	var wg sync.WaitGroup

	startBarrier := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			<-startBarrier

			for j := 0; j < opsPerGoroutine; j++ {
				// Mix of key-values, Bearer tokens, and PEM blocks
				raw := fmt.Sprintf("goroutine=%d iter=%d password=ConcurrentPass_%d_%d Bearer ConcurrentBearer_%d_%d",
					gid, j, gid, j, gid, j)
				clean := redactor.RedactLine(raw)

				if strings.Contains(clean, fmt.Sprintf("ConcurrentPass_%d_%d", gid, j)) ||
					strings.Contains(clean, fmt.Sprintf("ConcurrentBearer_%d_%d", gid, j)) {
					t.Errorf("CRITICAL LEAK in concurrent StreamRedactor: %q", clean)
				}
				if !strings.Contains(clean, "password=[REDACTED]") || !strings.Contains(clean, "Bearer [REDACTED]") {
					t.Errorf("Missing redaction markers in concurrent StreamRedactor: %q", clean)
				}

				if j%20 == 0 {
					redactor.Reset()
				}
			}
		}(i)
	}

	close(startBarrier)
	wg.Wait()

	t.Logf("CONFIRMED: %d goroutines completed %d concurrent StreamRedactor operations with 0 data races",
		numGoroutines, numGoroutines*opsPerGoroutine)
}

func TestChallenger_HighConcurrency_LiveScriptRuns(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Live concurrent script runs apply to Windows")
	}

	runner := newScriptRunner()
	const numRuns = 10
	var wg sync.WaitGroup

	errCh := make(chan error, numRuns)
	startBarrier := make(chan struct{})

	for i := 0; i < numRuns; i++ {
		wg.Add(1)
		go func(runIdx int) {
			defer wg.Done()
			<-startBarrier

			secretVal := fmt.Sprintf("ConcRunSecret_%d_%d", runIdx, time.Now().UnixNano())
			bearerVal := fmt.Sprintf("ConcRunBearer_%d", runIdx)

			cmdBody := fmt.Sprintf("@echo off\r\necho run=%d password=%s Bearer %s\r\n", runIdx, secretVal, bearerVal)

			var streamed strings.Builder
			var streamMu sync.Mutex

			req := protocol.ScriptRun{
				RunID:    fmt.Sprintf("concurrent-run-%d", runIdx),
				Language: "cmd",
				Body:     cmdBody,
				Timeout:  30,
			}

			res := runner.run(context.Background(), req, func(c protocol.ScriptChunk) {
				streamMu.Lock()
				streamed.WriteString(c.Data)
				streamMu.Unlock()
			})

			if res.ExitCode != 0 {
				errCh <- fmt.Errorf("run %d exited with %d: %s", runIdx, res.ExitCode, res.Error)
				return
			}

			streamMu.Lock()
			emitted := streamed.String()
			streamMu.Unlock()

			if strings.Contains(emitted, secretVal) || strings.Contains(res.Stdout, secretVal) {
				errCh <- fmt.Errorf("run %d leaked password secret %q", runIdx, secretVal)
				return
			}
			if strings.Contains(emitted, bearerVal) || strings.Contains(res.Stdout, bearerVal) {
				errCh <- fmt.Errorf("run %d leaked bearer secret %q", runIdx, bearerVal)
				return
			}
			if !strings.Contains(res.Stdout, "password=[REDACTED]") || !strings.Contains(res.Stdout, "Bearer [REDACTED]") {
				errCh <- fmt.Errorf("run %d missing redaction markers in stdout: %q", runIdx, res.Stdout)
				return
			}
		}(i)
	}

	close(startBarrier)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("Concurrent script runner failure: %v", err)
		}
	}

	t.Logf("CONFIRMED: %d concurrent live script runs completed with 100%% secret redaction", numRuns)
}

// ============================================================================
// Scenario 4: Streaming Output That Terminates Abruptly Without Trailing Newline
// ============================================================================

func TestChallenger_StreamAbruptTermination_NoTrailingNewline(t *testing.T) {
	t.Run("Abrupt termination in middle of active PEM block", func(t *testing.T) {
		chunks := []string{
			"Starting key dump...\n",
			"-----BEGIN RSA PRIVATE KEY-----\n",
			"MIIEowIBAAKCAQEA0Y1W9Z5l\n",
			"AbruptlyTerminatedKeyMaterialWithoutEndOrNewline",
		}

		var mu sync.Mutex
		var lines []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			lines = append(lines, l)
			mu.Unlock()
		})

		for _, ch := range chunks {
			_, err := stream.Write([]byte(ch))
			if err != nil {
				t.Fatalf("Write failed: %v", err)
			}
		}

		// Process dies abruptly, runtime calls flush()
		stream.flush()

		mu.Lock()
		emitted := strings.Join(lines, "")
		mu.Unlock()
		captured := stream.String()

		leak := "AbruptlyTerminatedKeyMaterialWithoutEndOrNewline"
		if strings.Contains(emitted, leak) {
			t.Fatalf("CRITICAL LEAK in abruptly terminated PEM emitted stream: %q found in %q", leak, emitted)
		}
		if strings.Contains(captured, leak) {
			t.Fatalf("CRITICAL LEAK in abruptly terminated PEM captured buffer: %q found in %q", leak, captured)
		}

		// Verify line was redacted
		if !strings.HasSuffix(captured, "[REDACTED PRIVATE KEY]\n") {
			t.Fatalf("Expected final flushed line to be [REDACTED PRIVATE KEY], got: %q", captured)
		}
	})

	t.Run("Abrupt termination with Bearer token", func(t *testing.T) {
		var mu sync.Mutex
		var lines []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			lines = append(lines, l)
			mu.Unlock()
		})

		secretBearer := "BearerTokenAbruptEOF_12345"
		stream.Write([]byte("Authorization: Bearer " + secretBearer))
		stream.flush()

		mu.Lock()
		emitted := strings.Join(lines, "")
		mu.Unlock()
		captured := stream.String()

		if strings.Contains(emitted, secretBearer) || strings.Contains(captured, secretBearer) {
			t.Fatalf("CRITICAL LEAK: %q leaked on abrupt EOF!", secretBearer)
		}
		expected := "Authorization: Bearer [REDACTED]\n"
		if emitted != expected || captured != expected {
			t.Errorf("Mismatch on abrupt Bearer EOF:\nExpected: %q\nActual:   %q", expected, emitted)
		}
	})

	t.Run("Abrupt termination with Key-Value secret", func(t *testing.T) {
		var mu sync.Mutex
		var lines []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			lines = append(lines, l)
			mu.Unlock()
		})

		secretPass := "AbruptPassSecret999!"
		stream.Write([]byte("password=" + secretPass))
		stream.flush()

		mu.Lock()
		emitted := strings.Join(lines, "")
		mu.Unlock()
		captured := stream.String()

		if strings.Contains(emitted, secretPass) || strings.Contains(captured, secretPass) {
			t.Fatalf("CRITICAL LEAK: %q leaked on abrupt EOF!", secretPass)
		}
		expected := "password=[REDACTED]\n"
		if emitted != expected || captured != expected {
			t.Errorf("Mismatch on abrupt password EOF:\nExpected: %q\nActual:   %q", expected, emitted)
		}
	})

	t.Run("Abrupt termination with bare keyword and equals (no value)", func(t *testing.T) {
		var mu sync.Mutex
		var lines []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			lines = append(lines, l)
			mu.Unlock()
		})

		stream.Write([]byte("Connecting with password="))
		stream.flush()

		mu.Lock()
		emitted := strings.Join(lines, "")
		mu.Unlock()
		captured := stream.String()

		expected := "Connecting with password=\n"
		if emitted != expected || captured != expected {
			t.Errorf("Mismatch on bare password= EOF:\nExpected: %q\nActual:   %q", expected, emitted)
		}
	})

	t.Run("Abrupt termination with lone PEM header", func(t *testing.T) {
		var mu sync.Mutex
		var lines []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			lines = append(lines, l)
			mu.Unlock()
		})

		stream.Write([]byte("-----BEGIN RSA PRIVATE KEY-----"))
		stream.flush()

		mu.Lock()
		emitted := strings.Join(lines, "")
		mu.Unlock()
		captured := stream.String()

		expected := "[REDACTED PRIVATE KEY]\n"
		if emitted != expected || captured != expected {
			t.Errorf("Mismatch on lone PEM header EOF:\nExpected: %q\nActual:   %q", expected, emitted)
		}
	})

	t.Run("Flush on completely empty stream does not crash", func(t *testing.T) {
		var lines []string
		stream := newScriptStream(func(l string) {
			lines = append(lines, l)
		})
		stream.flush()
		if len(lines) != 0 || stream.String() != "" {
			t.Fatalf("Expected empty output from empty flush, got lines=%v, capture=%q", lines, stream.String())
		}
	})
}

// ============================================================================
// Scenario 5: Multiple Consecutive PEM Blocks in a Single Stream
// ============================================================================

func TestChallenger_MultipleConsecutivePEMBlocks(t *testing.T) {
	t.Run("Five distinct PEM private key types separated by logs", func(t *testing.T) {
		streamChunks := []string{
			"Status: Initializing key manager...\n",
			// 1. RSA
			"-----BEGIN RSA PRIVATE KEY-----\n",
			"MIIEowIBAAKCAQEA0Y1W9Z5lRSABlockData\n",
			"-----END RSA PRIVATE KEY-----\n",
			"Status: Key 1 (RSA) loaded successfully\n",
			// 2. EC
			"-----BEGIN EC PRIVATE KEY-----\n",
			"MHcCAQEEIIzSampleECKeyData5678\n",
			"-----END EC PRIVATE KEY-----\n",
			"Status: Key 2 (EC) loaded successfully\n",
			// 3. OPENSSH
			"-----BEGIN OPENSSH PRIVATE KEY-----\n",
			"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n",
			"-----END OPENSSH PRIVATE KEY-----\n",
			"Status: Key 3 (OPENSSH) loaded successfully\n",
			// 4. ENCRYPTED
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
			"MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIEncryptedData\n",
			"-----END ENCRYPTED PRIVATE KEY-----\n",
			"Status: Key 4 (ENCRYPTED) loaded successfully\n",
			// 5. Generic PKCS#8
			"-----BEGIN PRIVATE KEY-----\n",
			"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7GenericData\n",
			"-----END PRIVATE KEY-----\n",
			"Status: All 5 keys loaded and verified.\n",
		}

		var mu sync.Mutex
		var lines []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			lines = append(lines, l)
			mu.Unlock()
		})

		for _, chunk := range streamChunks {
			_, err := stream.Write([]byte(chunk))
			if err != nil {
				t.Fatalf("Write failed: %v", err)
			}
		}
		stream.flush()

		mu.Lock()
		emitted := strings.Join(lines, "")
		mu.Unlock()
		captured := stream.String()

		privateKeyLeaks := []string{
			"MIIEowIBAAKCAQEA0Y1W9Z5lRSABlockData",
			"MHcCAQEEIIzSampleECKeyData5678",
			"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ",
			"MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIEncryptedData",
			"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7GenericData",
		}

		for _, leak := range privateKeyLeaks {
			if strings.Contains(emitted, leak) {
				t.Fatalf("CRITICAL LEAK in 5-PEM emitted stream: %q found in %q", leak, emitted)
			}
			if strings.Contains(captured, leak) {
				t.Fatalf("CRITICAL LEAK in 5-PEM captured buffer: %q found in %q", leak, captured)
			}
		}

		// Ensure all 5 benign status lines were preserved verbatim
		expectedStatuses := []string{
			"Status: Initializing key manager...\n",
			"Status: Key 1 (RSA) loaded successfully\n",
			"Status: Key 2 (EC) loaded successfully\n",
			"Status: Key 3 (OPENSSH) loaded successfully\n",
			"Status: Key 4 (ENCRYPTED) loaded successfully\n",
			"Status: All 5 keys loaded and verified.\n",
		}

		for _, st := range expectedStatuses {
			if !strings.Contains(captured, st) {
				t.Errorf("Benign status line was corrupted or missing: %q", st)
			}
		}

		// Verify count of redaction markers
		markerCount := strings.Count(captured, "[REDACTED PRIVATE KEY]\n")
		// Each PEM has 3 lines: header, body, footer. 5 blocks * 3 lines = 15 markers
		if markerCount != 15 {
			t.Errorf("Expected 15 [REDACTED PRIVATE KEY] markers, got %d", markerCount)
		}
	})

	t.Run("Consecutive PEM blocks directly adjacent with zero intervening lines", func(t *testing.T) {
		streamChunks := []string{
			"-----BEGIN RSA PRIVATE KEY-----\n",
			"RSABlockDataLine1\n",
			"-----END RSA PRIVATE KEY-----\n",
			"-----BEGIN EC PRIVATE KEY-----\n",
			"ECBlockDataLine1\n",
			"-----END EC PRIVATE KEY-----\n",
			"Clean trailing line\n",
		}

		var mu sync.Mutex
		var lines []string
		stream := newScriptStream(func(l string) {
			mu.Lock()
			lines = append(lines, l)
			mu.Unlock()
		})

		for _, chunk := range streamChunks {
			stream.Write([]byte(chunk))
		}
		stream.flush()

		mu.Lock()
		emitted := strings.Join(lines, "")
		mu.Unlock()
		captured := stream.String()

		if strings.Contains(emitted, "RSABlockDataLine1") || strings.Contains(emitted, "ECBlockDataLine1") {
			t.Fatalf("CRITICAL LEAK in back-to-back adjacent PEM blocks: %q", emitted)
		}
		if !strings.Contains(captured, "Clean trailing line\n") {
			t.Errorf("Clean trailing line missing from capture: %q", captured)
		}
		if count := strings.Count(captured, "[REDACTED PRIVATE KEY]\n"); count != 6 {
			t.Errorf("Expected 6 markers, got %d: %q", count, captured)
		}
	})
}

// ============================================================================
// Scenario 6: Extreme Line Lengths (64 KB and 1 MB) Stress Tests
// ============================================================================

func TestChallenger_ExtremeLine_64KB(t *testing.T) {
	secStart := "SecStart_Password_111"
	secQuarter := "SecQuarter_Token_222"
	secMid := "SecMid_Bearer_333"
	secThreeQuarter := "SecThreeQuarter_ApiKey_444"
	secEnd := "SecEnd_Secret_555"

	const targetSize64 = 64 * 1024 // 65,536 bytes
	padSize := (targetSize64 / 4) + 200
	pad1 := strings.Repeat("A", padSize)
	pad2 := strings.Repeat("B", padSize)
	pad3 := strings.Repeat("C", padSize)
	pad4 := strings.Repeat("D", padSize)

	line := fmt.Sprintf("START password=%s %s token=%s %s Bearer %s %s api_key:%s %s secret=%s END\n",
		secStart, pad1, secQuarter, pad2, secMid, pad3, secThreeQuarter, pad4, secEnd)

	if len(line) < 64*1024 {
		t.Fatalf("Line length %d < 64 KB", len(line))
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
	elapsed := time.Since(start)

	t.Logf("64 KB line (%d bytes) processed in %v", len(line), elapsed)

	mu.Lock()
	emitted := strings.Join(received, "")
	mu.Unlock()
	captured := stream.String()

	secrets := []string{secStart, secQuarter, secMid, secThreeQuarter, secEnd}
	for _, sec := range secrets {
		if strings.Contains(emitted, sec) {
			t.Fatalf("CRITICAL LEAK: %q leaked in 64 KB emitted stream!", sec)
		}
		if strings.Contains(captured, sec) {
			t.Fatalf("CRITICAL LEAK: %q leaked in 64 KB captured buffer!", sec)
		}
	}

	expectedMarkers := []string{
		"password=[REDACTED]",
		"token=[REDACTED]",
		"Bearer [REDACTED]",
		"api_key:[REDACTED]",
		"secret=[REDACTED]",
	}
	for _, marker := range expectedMarkers {
		if !strings.Contains(captured, marker) {
			t.Fatalf("Expected marker %q missing from 64 KB line capture!", marker)
		}
	}
}

func TestChallenger_ExtremeLine_1MB(t *testing.T) {
	t.Run("1MB line with trailing newline", func(t *testing.T) {
		sec1 := "MegaPass1_SecretVal123"
		sec2 := "MegaToken2_GhpSecretVal456"
		sec3 := "MegaBearer3_JwtSecretVal789"
		sec4 := "MegaKey4_ApiKeySecretVal000"

		const targetSize1MB = 1024 * 1024 // 1,048,576 bytes
		padSize := (targetSize1MB / 3) + 2000
		pad := strings.Repeat("x", padSize)

		line := fmt.Sprintf("password=%s %s token=%s %s Bearer %s %s api_key=%s END_OF_1MB\n",
			sec1, pad, sec2, pad, sec3, pad, sec4)

		if len(line) < 1024*1024 {
			t.Fatalf("Line length %d < 1 MB", len(line))
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
		elapsed := time.Since(start)

		t.Logf("1 MB line with newline processed in %v (%d bytes)", elapsed, len(line))

		mu.Lock()
		emitted := strings.Join(received, "")
		mu.Unlock()
		captured := stream.String()

		for _, sec := range []string{sec1, sec2, sec3, sec4} {
			if strings.Contains(emitted, sec) {
				t.Fatalf("CRITICAL LEAK: %q found in 1 MB emitted output!", sec)
			}
			if strings.Contains(captured, sec) {
				t.Fatalf("CRITICAL LEAK: %q found in 1 MB captured buffer!", sec)
			}
		}

		if !strings.Contains(emitted, "password=[REDACTED]") ||
			!strings.Contains(emitted, "token=[REDACTED]") ||
			!strings.Contains(emitted, "Bearer [REDACTED]") ||
			!strings.Contains(emitted, "api_key=[REDACTED]") {
			t.Fatalf("Missing redaction markers in 1 MB emitted line!")
		}
		if !strings.HasSuffix(captured, scriptTruncated) {
			t.Fatalf("Expected 1MB line capture to be marked with scriptTruncated")
		}
	})

	t.Run("1MB line without trailing newline triggering maxScriptLine chunking", func(t *testing.T) {
		sec1 := "NoNL_Pass_SecretVal999"
		sec2 := "NoNL_Bearer_SecretVal888"

		pad := strings.Repeat("z", 550000)
		// Total > 1048576 (maxScriptLine) without any newline
		line := fmt.Sprintf("BEGIN password=%s %s Bearer %s %s END", sec1, pad, sec2, pad)

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
				t.Fatalf("CRITICAL LEAK: %q found in endless line emitted output!", sec)
			}
			if strings.Contains(captured, sec) {
				t.Fatalf("CRITICAL LEAK: %q found in endless line captured buffer!", sec)
			}
		}
	})
}

// ============================================================================
// Scenario 7: UTF-8 Multi-Byte Rune Split Across Chunk Boundaries
// ============================================================================

func TestChallenger_ChunkBoundary_UTF8RuneSplit(t *testing.T) {
	// "密碼" in UTF-8 is \xE5\xAF\x86 \xE7\xA2\xBC (3 bytes each)
	// We split chunk 1 in the middle of the 3-byte sequence of '密'
	prefix := []byte("User secret=\xE5\xAF") // first 2 bytes of '密'
	suffix := []byte("\x86\xE7\xA2\xBC_Pass123!\n")

	var mu sync.Mutex
	var received []string
	stream := newScriptStream(func(l string) {
		mu.Lock()
		received = append(received, l)
		mu.Unlock()
	})

	stream.Write(prefix)
	stream.Write(suffix)
	stream.flush()

	mu.Lock()
	emitted := strings.Join(received, "")
	mu.Unlock()
	captured := stream.String()

	if strings.Contains(emitted, "密碼_Pass123!") || strings.Contains(captured, "密碼_Pass123!") {
		t.Fatalf("CRITICAL LEAK: UTF-8 secret leaked across rune split boundary!")
	}
	expected := "User secret=[REDACTED]\n"
	if emitted != expected || captured != expected {
		t.Errorf("Mismatch on UTF-8 rune split:\nExpected: %q\nActual:   %q", expected, emitted)
	}
}

// ============================================================================
// Scenario 8: Live scriptRunner Execution with PowerShell & CMD
// ============================================================================

func TestChallenger_LiveRunner_PowerShell_SanitizesStdoutStderrAndErrors(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell live test applies to Windows")
	}
	if _, err := powershellScriptExe(); err != nil {
		t.Skip("PowerShell not available:", err)
	}

	runner := newScriptRunner()

	secretPSPass := "P@ssw0rdFromPowerShellLive999!"
	secretPSBearer := "eyJhbGciOiJIUzI1NiJ9.PowerShellLiveJWT.XYZ"
	secretPSAPIKey := "sk_live_powershell_api_key_888777"
	secretPSToken := "ghp_powershell_token_666555"
	secretPSPrivKey := "MIIEowIBAAKCAQEA0Y1W9Z5lPSLivePrivKey"
	secretStderrPass := "StderrSecretPasswordFromPS111"
	secretStderrBearer := "StderrBearerTokenFromPS222"

	scriptBody := fmt.Sprintf(`
		Write-Output "User: admin password=%s host=db.internal"
		Write-Output "Authorization: Bearer %s"
		Write-Output "Header: api_key=%s"
		Write-Output "Github: token=%s"
		Write-Output "-----BEGIN RSA PRIVATE KEY-----"
		Write-Output "%s"
		Write-Output "-----END RSA PRIVATE KEY-----"
		[Console]::Error.WriteLine("Error diagnostic: password=%s")
		[Console]::Error.WriteLine("Error auth: Bearer %s")
		Write-Output "FINAL_CLEAN_STATUS_OK"
	`, secretPSPass, secretPSBearer, secretPSAPIKey, secretPSToken, secretPSPrivKey, secretStderrPass, secretStderrBearer)

	var (
		mu           sync.Mutex
		stdoutChunks []string
		stderrChunks []string
	)

	req := protocol.ScriptRun{
		RunID:    "ps-live-redact-stress",
		Language: "powershell",
		Body:     scriptBody,
		Timeout:  30,
	}

	res := runner.run(context.Background(), req, func(c protocol.ScriptChunk) {
		mu.Lock()
		defer mu.Unlock()
		if c.Stream == "stdout" {
			stdoutChunks = append(stdoutChunks, c.Data)
		} else if c.Stream == "stderr" {
			stderrChunks = append(stderrChunks, c.Data)
		}
	})

	if res.ExitCode != 0 {
		t.Fatalf("Script failed with exit code %d: err=%q stderr=%q", res.ExitCode, res.Error, res.Stderr)
	}

	mu.Lock()
	allStdoutStreamed := strings.Join(stdoutChunks, "")
	allStderrStreamed := strings.Join(stderrChunks, "")
	mu.Unlock()

	allSecrets := []string{
		secretPSPass,
		secretPSBearer,
		secretPSAPIKey,
		secretPSToken,
		secretPSPrivKey,
		secretStderrPass,
		secretStderrBearer,
	}

	for _, s := range allSecrets {
		if strings.Contains(allStdoutStreamed, s) {
			t.Fatalf("CRITICAL SECURITY LEAK: Secret %q leaked in live streamed stdout!", s)
		}
		if strings.Contains(allStderrStreamed, s) {
			t.Fatalf("CRITICAL SECURITY LEAK: Secret %q leaked in live streamed stderr!", s)
		}
		if strings.Contains(res.Stdout, s) {
			t.Fatalf("CRITICAL SECURITY LEAK: Secret %q leaked in res.Stdout!", s)
		}
		if strings.Contains(res.Stderr, s) {
			t.Fatalf("CRITICAL SECURITY LEAK: Secret %q leaked in res.Stderr!", s)
		}
		if strings.Contains(res.Error, s) {
			t.Fatalf("CRITICAL SECURITY LEAK: Secret %q leaked in res.Error!", s)
		}
	}

	if !strings.Contains(res.Stdout, "password=[REDACTED]") ||
		!strings.Contains(res.Stdout, "Bearer [REDACTED]") ||
		!strings.Contains(res.Stdout, "api_key=[REDACTED]") ||
		!strings.Contains(res.Stdout, "token=[REDACTED]") ||
		!strings.Contains(res.Stdout, "[REDACTED PRIVATE KEY]") {
		t.Fatalf("Redaction markers missing from res.Stdout: %q", res.Stdout)
	}

	if !strings.Contains(res.Stderr, "password=[REDACTED]") ||
		!strings.Contains(res.Stderr, "Bearer [REDACTED]") {
		t.Fatalf("Redaction markers missing from res.Stderr: %q", res.Stderr)
	}

	if !strings.Contains(res.Stdout, "FINAL_CLEAN_STATUS_OK") {
		t.Fatalf("Benign output was lost or corrupted: %q", res.Stdout)
	}
}

func TestChallenger_LiveRunner_CMD_SanitizesStdoutStderr(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("CMD live test applies to Windows")
	}

	runner := newScriptRunner()

	secretCmdPass := "CmdSecretPassword_ABC123!"
	secretCmdBearer := "CmdBearerToken_XYZ789"
	secretCmdAPIKey := "cmd_api_key_val_456"
	secretCmdStderrPass := "CmdStderrSecretPass_999"

	body := "@echo off\r\n" +
		fmt.Sprintf("echo User connecting password=%s host=localhost\r\n", secretCmdPass) +
		fmt.Sprintf("echo Authorization: Bearer %s\r\n", secretCmdBearer) +
		fmt.Sprintf("echo Config api_key=%s\r\n", secretCmdAPIKey) +
		fmt.Sprintf("echo Diagnostic failure: password=%s 1>&2\r\n", secretCmdStderrPass) +
		"echo CMD_CLEAN_FINISH_MARKER\r\n"

	var (
		mu           sync.Mutex
		stdoutChunks []string
		stderrChunks []string
	)

	req := protocol.ScriptRun{
		RunID:    "cmd-live-redact-stress",
		Language: "cmd",
		Body:     body,
		Timeout:  30,
	}

	res := runner.run(context.Background(), req, func(c protocol.ScriptChunk) {
		mu.Lock()
		defer mu.Unlock()
		if c.Stream == "stdout" {
			stdoutChunks = append(stdoutChunks, c.Data)
		} else {
			stderrChunks = append(stderrChunks, c.Data)
		}
	})

	if res.ExitCode != 0 {
		t.Fatalf("CMD script failed: exit=%d, err=%q", res.ExitCode, res.Error)
	}

	mu.Lock()
	streamedOut := strings.Join(stdoutChunks, "")
	streamedErr := strings.Join(stderrChunks, "")
	mu.Unlock()

	secrets := []string{secretCmdPass, secretCmdBearer, secretCmdAPIKey, secretCmdStderrPass}
	for _, sec := range secrets {
		if strings.Contains(streamedOut, sec) || strings.Contains(res.Stdout, sec) {
			t.Fatalf("CRITICAL LEAK: %q found in CMD stdout!", sec)
		}
		if strings.Contains(streamedErr, sec) || strings.Contains(res.Stderr, sec) {
			t.Fatalf("CRITICAL LEAK: %q found in CMD stderr!", sec)
		}
	}

	if !strings.Contains(res.Stdout, "password=[REDACTED]") ||
		!strings.Contains(res.Stdout, "Bearer [REDACTED]") ||
		!strings.Contains(res.Stdout, "api_key=[REDACTED]") {
		t.Fatalf("Missing redaction markers in CMD stdout: %q", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "password=[REDACTED]") {
		t.Fatalf("Missing redaction markers in CMD stderr: %q", res.Stderr)
	}
	if !strings.Contains(res.Stdout, "CMD_CLEAN_FINISH_MARKER") {
		t.Fatalf("Benign CMD finish marker missing: %q", res.Stdout)
	}
}

func TestChallenger_LiveRunner_PowerShell_FailureErrorSanitization(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell live test applies to Windows")
	}
	if _, err := powershellScriptExe(); err != nil {
		t.Skip("PowerShell not available:", err)
	}

	runner := newScriptRunner()
	secretInError := "SecretPasswordInException_9999"

	script := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		throw "Critical failure with password=%s"
	`, secretInError)

	req := protocol.ScriptRun{
		RunID:    "ps-error-sanitization",
		Language: "powershell",
		Body:     script,
		Timeout:  15,
	}

	res := runner.run(context.Background(), req, func(protocol.ScriptChunk) {})

	if res.ExitCode == 0 {
		t.Fatalf("Expected non-zero exit code on throw, got %d", res.ExitCode)
	}

	if strings.Contains(res.Error, secretInError) {
		t.Fatalf("CRITICAL LEAK: Secret leaked in res.Error: %q", res.Error)
	}
	if strings.Contains(res.Stderr, secretInError) {
		t.Fatalf("CRITICAL LEAK: Secret leaked in res.Stderr: %q", res.Stderr)
	}
	if strings.Contains(res.Stdout, secretInError) {
		t.Fatalf("CRITICAL LEAK: Secret leaked in res.Stdout: %q", res.Stdout)
	}

	t.Logf("CONFIRMED: Script error sanitized: res.Error=%q, res.Stderr=%q", res.Error, res.Stderr)
}
