package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// TestScriptFileBytesGivesPowerShellItsBOM: a BOM-less .ps1 is decoded by
// Windows PowerShell 5.1 with the ANSI code page, so a body with a "✓" in it
// is mojibake - usually a parse error - before it ever runs.
func TestScriptFileBytesGivesPowerShellItsBOM(t *testing.T) {
	body := "$s = \"héllo ✓\"\n\"LEN=\" + $s.Length\n"
	ps := scriptFileBytes("powershell", body)
	if string(ps[:3]) != "\xEF\xBB\xBF" {
		t.Fatalf("a .ps1 needs the UTF-8 BOM, got % x", ps[:3])
	}
	if string(ps[3:]) != body {
		t.Fatal("the BOM must not change the body itself")
	}
	// cmd.exe would echo a BOM as part of the first line, and the shells and
	// python read UTF-8 already.
	for _, lang := range []string{"cmd", "python", "bash", "sh"} {
		if got := string(scriptFileBytes(lang, body)); got != body {
			t.Fatalf("%s body was rewritten: %q", lang, got)
		}
	}
}

// collectStream drives a scriptStream and returns what it emitted.
func collectStream(t *testing.T, writes ...string) (*scriptStream, []string) {
	t.Helper()
	var (
		mu    sync.Mutex
		lines []string
	)
	s := newScriptStream(func(l string) {
		mu.Lock()
		lines = append(lines, l)
		mu.Unlock()
	})
	for _, w := range writes {
		n, err := s.Write([]byte(w))
		if err != nil || n != len(w) {
			t.Fatalf("Write(%d bytes) = %d, %v - a stream that refuses bytes blocks the interpreter", len(w), n, err)
		}
	}
	s.flush()
	mu.Lock()
	defer mu.Unlock()
	return s, append([]string(nil), lines...)
}

func TestScriptStreamSplitsLines(t *testing.T) {
	s, lines := collectStream(t, "one\r\ntw", "o\nthree")
	want := []string{"one\n", "two\n", "three\n"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("lines = %q, want %q", lines, want)
	}
	if s.String() != "one\ntwo\nthree\n" {
		t.Fatalf("capture = %q", s.String())
	}
}

// TestScriptStreamSurvivesAnEndlessLine: a bufio.Scanner used to sit here and
// it stopped with ErrTooLong on the first line over 1 MiB, which left the
// pipe undrained, the interpreter blocked on write and the run wedged until
// its timeout killed it - losing everything printed after the long line.
func TestScriptStreamSurvivesAnEndlessLine(t *testing.T) {
	long := strings.Repeat("z", 3*maxScriptLine+7)
	_, lines := collectStream(t, "BEFORE\n", long+"\n", "AFTER\n")
	if lines[0] != "BEFORE\n" || lines[len(lines)-1] != "AFTER\n" {
		t.Fatalf("output around the long line was lost: %q ... %q", lines[0], lines[len(lines)-1])
	}
	var body strings.Builder
	for _, l := range lines[1 : len(lines)-1] {
		body.WriteString(strings.TrimSuffix(l, "\n"))
	}
	if body.String() != long {
		t.Fatalf("the long line came back as %d bytes, want %d", body.Len(), len(long))
	}
}

// TestScriptStreamMarksTruncation: output past the cap is dropped, and a
// capture that ends mid-report must say so rather than look complete.
func TestScriptStreamMarksTruncation(t *testing.T) {
	line := strings.Repeat("y", 200) + "\n"
	writes := make([]string, 0, maxCapture/len(line)+20)
	for i := 0; i < cap(writes); i++ {
		writes = append(writes, line)
	}
	s, lines := collectStream(t, writes...)
	if len(lines) != len(writes) {
		t.Fatalf("every line must still be streamed: got %d of %d", len(lines), len(writes))
	}
	got := s.String()
	if !strings.HasSuffix(got, scriptTruncated) {
		t.Fatalf("a truncated capture must be marked, ends with %q", got[max(0, len(got)-40):])
	}
	if len(got) > maxCapture+len(scriptTruncated) {
		t.Fatalf("capture kept %d bytes, cap is %d", len(got), maxCapture)
	}
}

// TestScriptStreamNeverSplitsARune: cutting the capture mid-character would
// put a U+FFFD in the JSON reply, which is the very thing the decode exists
// to avoid.
func TestScriptStreamNeverSplitsARune(t *testing.T) {
	s := newScriptStream(func(string) {})
	s.limit = 10
	s.Write([]byte("abcdefgh✓ijk\n"))
	s.flush()
	got := strings.TrimSuffix(s.String(), scriptTruncated)
	if got != "abcdefgh" {
		t.Fatalf("capture = %q, want the text cut at a rune boundary", got)
	}
}

// TestSignedExitCode: Windows hands back the raw DWORD, so `exit -1` used to
// be reported as 4294967295 while the same script on Linux reports 255.
func TestSignedExitCode(t *testing.T) {
	cases := []struct {
		code    int
		windows bool
		want    int
	}{
		{4294967295, true, -1},
		{3221225477, true, -1073741819}, // 0xC0000005, an access violation
		{300, true, 300},
		{0, true, 0},
		{255, false, 255},
		{-1, false, -1},
	}
	for _, c := range cases {
		if got := signedExitCode(c.code, c.windows); got != c.want {
			t.Errorf("signedExitCode(%d, windows=%v) = %d, want %d", c.code, c.windows, got, c.want)
		}
	}
}

// TestCmdArgumentsStayData: exec quotes with CommandLineToArgvW rules, which
// cmd.exe does not implement - a value with a quote in it used to close the
// quoted region and run the rest as a second command, as SYSTEM, under an
// audit entry that showed only the parameter.
func TestCmdArgumentsStayData(t *testing.T) {
	inject := `a" & echo WINVAL-INJECTED-MARKER & rem "b`
	if _, unsafe := cmdUnsafeArg(inject); !unsafe {
		t.Fatal("an argument containing a double quote must be refused")
	}
	for _, v := range []string{`%PATH%`, "!DELAYED!", "line\nbreak", "cr\rlf"} {
		if _, unsafe := cmdUnsafeArg(v); !unsafe {
			t.Errorf("%q must be refused: cmd.exe acts on it even inside quotes", v)
		}
	}
	for _, v := range []string{"plain", "a & b", "a&b", "C:\\Program Files (x86)\\x", "a|b", ""} {
		if bad, unsafe := cmdUnsafeArg(v); unsafe {
			t.Errorf("%q was refused over %q, but quoting handles it", v, string(bad))
		}
	}
	// Quoting only where it is needed, so a plain value still arrives as the
	// bare %1 it always did.
	if got := cmdQuote("plain"); got != "plain" {
		t.Errorf("cmdQuote(plain) = %q", got)
	}
	for _, v := range []string{"a&b", "a & b", "a|b", "a>b", "a^b", "a(b)"} {
		if got := cmdQuote(v); got != `"`+v+`"` {
			t.Errorf("cmdQuote(%q) = %q, want a quoted region", v, got)
		}
	}
	if got := cmdQuote(""); got != `""` {
		t.Errorf("an empty argument must still occupy its position, got %q", got)
	}
}

// TestCmdScriptLineKeepsQuotesWhole: when the string after /c opens with a
// quote, cmd.exe strips the first quote and the *last* one before parsing, so
// the whole thing needs one more pair around it.
func TestCmdScriptLineKeepsQuotesWhole(t *testing.T) {
	plain := cmdScriptLine(`C:\W\cmd.exe`, `C:\tmp\script.cmd`, []string{"one", "a & b"})
	if plain != `C:\W\cmd.exe /d /c C:\tmp\script.cmd one "a & b"` {
		t.Fatalf("command line = %q", plain)
	}
	spaced := cmdScriptLine(`C:\W\cmd.exe`, `C:\my temp\script.cmd`, []string{"a & b"})
	want := `C:\W\cmd.exe /d /c ""C:\my temp\script.cmd" "a & b""`
	if spaced != want {
		t.Fatalf("command line = %q, want %q", spaced, want)
	}
}

// TestPythonKeyNewer: a lexical compare picks 3.9 over 3.12, and the 32-bit
// key of a version must lose to the 64-bit one.
func TestPythonKeyNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"3.12", "3.9", true},
		{"3.9", "3.12", false},
		{"3.12", "3.12-32", true},
		{"3.12-32", "3.12", false},
		{"4.0", "3.13", true},
		{"3.12", "3.12", false},
	}
	for _, c := range cases {
		if got := pythonKeyNewer(c.a, c.b); got != c.want {
			t.Errorf("pythonKeyNewer(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestScriptRunnerSurvivesAnEndlessLine drives the whole runner - temp file,
// interpreter, pipes, result - over the case that used to wedge it. A line
// past the old scanner's token limit ended the pump, nothing drained the
// pipe, the interpreter blocked on write and the run was killed by its own
// timeout: a script that finishes in half a second was recorded as a timeout
// with everything after the long line missing.
func TestScriptRunnerSurvivesAnEndlessLine(t *testing.T) {
	if _, err := pythonScriptExe(); err != nil {
		t.Skip("no python on this device:", err)
	}
	r := newScriptRunner()
	body := "import sys\n" +
		"print('BEFORE-MARKER')\n" +
		"sys.stdout.write('z' * 1500000 + '\\n')\n" +
		"print('AFTER-MARKER')\n" +
		"sys.exit(0)\n"
	var (
		mu       sync.Mutex
		streamed strings.Builder
	)
	start := time.Now()
	res := r.run(context.Background(), protocol.ScriptRun{RunID: "long", Language: "python", Body: body, Timeout: 60}, func(c protocol.ScriptChunk) {
		mu.Lock()
		if c.Stream == "stdout" {
			streamed.WriteString(c.Data)
		}
		mu.Unlock()
	})
	if res.TimedOut || res.ExitCode != 0 || res.Error != "" {
		t.Fatalf("a script that prints one long line must still finish: exit=%d timed_out=%v err=%q", res.ExitCode, res.TimedOut, res.Error)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatalf("the long line stalled the run (%s)", time.Since(start))
	}
	mu.Lock()
	all := streamed.String()
	mu.Unlock()
	if !strings.HasPrefix(all, "BEFORE-MARKER\n") || !strings.HasSuffix(all, "AFTER-MARKER\n") {
		t.Fatalf("output around the long line was lost (%d bytes streamed)", len(all))
	}
	// The capture stops at the cap, but it says where it stopped instead of
	// looking like the whole report.
	if !strings.HasSuffix(res.Stdout, scriptTruncated) {
		t.Fatalf("a capture that hit the cap must be marked (%d bytes)", len(res.Stdout))
	}
}

// TestSweepScriptTemp: a run directory outlives an agent that was killed
// mid-run, and it still holds the script body. Nothing else ever looks at it.
func TestSweepScriptTemp(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, scriptTempPrefix+"111")
	fresh := filepath.Join(root, scriptTempPrefix+"222")
	other := filepath.Join(root, "not-ours")
	for _, d := range []string{old, fresh, other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "script.ps1"), []byte("Write-Output secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	aged := time.Now().Add(-2 * scriptTempMaxAge)
	if err := os.Chtimes(old, aged, aged); err != nil {
		t.Fatal(err)
	}
	sweepScriptTemp(root)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("an abandoned run directory must be swept (%v)", err)
	}
	for _, d := range []string{fresh, other} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("%s must be left alone: %v", filepath.Base(d), err)
		}
	}
	// A run in flight is younger than the cut-off whatever its name.
	if scriptTempStale(scriptTempPrefix+"333", true, time.Now(), time.Now()) {
		t.Fatal("a live run directory must never be swept")
	}
	if scriptTempStale("rmm-wua-1", true, aged, time.Now()) {
		t.Fatal("the sweep must only claim its own directories")
	}
}

// TestRemoveScriptDirReportsFailure is the other half of F060: the run's own
// cleanup must actually remove the body, and say so when it cannot.
func TestRemoveScriptDirReportsFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), scriptTempPrefix+"444")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "script.sh"), []byte("echo hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeScriptDir(dir)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the run directory is still there: %v", err)
	}
}

// ============================================================================
// Streaming Chunk Boundary & Redaction Integration Tests (Milestone 2 - R4)
// ============================================================================

func TestStreamingChunkBoundary(t *testing.T) {
	t.Run("Secret Keyword Split Across Write Calls", func(t *testing.T) {
		// Secret keyword "password" is split between "pass" and "word="
		// "Bearer" is split between "Bear" and "er "
		chunks := []string{
			"User authenticated with pass",
			"word=SuperSecretPass999; and Bear",
			"er my_jwt_token_123456\n",
			"Next line is clean\n",
		}

		s, lines := collectStream(t, chunks...)

		if len(lines) != 2 {
			t.Fatalf("Expected 2 lines, got %d: %v", len(lines), lines)
		}

		firstLine := lines[0]
		if strings.Contains(firstLine, "SuperSecretPass999") || strings.Contains(firstLine, "my_jwt_token_123456") {
			t.Fatalf("CRITICAL LEAK: Chunk split resulted in leaked secret! Line: %q", firstLine)
		}

		expectedFirstLine := "User authenticated with password=[REDACTED]; and Bearer [REDACTED]\n"
		if firstLine != expectedFirstLine {
			t.Errorf("Reconstituted line mismatch:\nExpected: %q\nActual:   %q", expectedFirstLine, firstLine)
		}

		if lines[1] != "Next line is clean\n" {
			t.Errorf("Clean line corrupted: %q", lines[1])
		}

		// Also verify captured buffer String()
		if strings.Contains(s.String(), "SuperSecretPass999") || strings.Contains(s.String(), "my_jwt_token_123456") {
			t.Fatalf("CRITICAL LEAK in captured buffer: %q", s.String())
		}
	})

	t.Run("Secret Value Split Across Write Calls", func(t *testing.T) {
		chunks := []string{
			"Connecting with token=ghp_",
			"1234567890abcdefghijklmnopqrstuvwxyz\n",
		}

		s, lines := collectStream(t, chunks...)
		if len(lines) != 1 {
			t.Fatalf("Expected 1 line, got %d", len(lines))
		}

		expected := "Connecting with token=[REDACTED]\n"
		if lines[0] != expected {
			t.Errorf("Mismatch:\nExpected: %q\nActual:   %q", expected, lines[0])
		}
		if strings.Contains(s.String(), "1234567890abcdef") {
			t.Fatalf("Secret leaked in stream capture: %q", s.String())
		}
	})

	t.Run("Secret Split Flushed Without Trailing Newline", func(t *testing.T) {
		// Output terminates without newline, flushed at process exit
		chunks := []string{
			"Diagnostic api_",
			"key=sk_live_998877",
		}

		s, lines := collectStream(t, chunks...)
		if len(lines) != 1 {
			t.Fatalf("Expected 1 line from flush, got %d", len(lines))
		}

		expected := "Diagnostic api_key=[REDACTED]\n"
		if lines[0] != expected {
			t.Errorf("Mismatch:\nExpected: %q\nActual:   %q", expected, lines[0])
		}
		if strings.Contains(s.String(), "sk_live_998877") {
			t.Fatalf("Secret leaked after flush: %q", s.String())
		}
	})

	t.Run("PEM Header Split Across Write Calls", func(t *testing.T) {
		chunks := []string{
			"Key dump: -----BEGIN RSA ",
			"PRIVATE KEY-----\n",
		}

		s, lines := collectStream(t, chunks...)
		if len(lines) != 1 {
			t.Fatalf("Expected 1 line, got %d", len(lines))
		}

		expected := "Key dump: [REDACTED PRIVATE KEY]\n"
		if lines[0] != expected {
			t.Errorf("Mismatch:\nExpected: %q\nActual:   %q", expected, lines[0])
		}
		if strings.Contains(s.String(), "RSA PRIVATE KEY") {
			t.Fatalf("PEM header leaked: %q", s.String())
		}
	})
}

func TestScriptStreamMultiLinePEMStreaming(t *testing.T) {
	// A multi-line private key streamed line-by-line across multiple Write calls
	chunks := []string{
		"Certificate loaded:\n",
		"-----BEGIN RSA PRIVATE KEY-----\n",
		"MIIEowIBAAKCAQEA0Y1W9Z5l\n",
		"uE9O5bK0Jk1M2N3P4Q5R6S7T\n",
		"-----END RSA PRIVATE KEY-----\n",
		"Status: Key loaded successfully\n",
	}

	s, lines := collectStream(t, chunks...)
	if len(lines) != 6 {
		t.Fatalf("Expected 6 lines, got %d: %v", len(lines), lines)
	}

	// Line 0: Certificate loaded:
	if lines[0] != "Certificate loaded:\n" {
		t.Errorf("Line 0 corrupted: %q", lines[0])
	}
	// Lines 1-4: all private key lines must be redacted
	for idx := 1; idx <= 4; idx++ {
		if lines[idx] != "[REDACTED PRIVATE KEY]\n" {
			t.Errorf("Line %d not redacted: %q", idx, lines[idx])
		}
	}
	// Line 5: Status: Key loaded successfully
	if lines[5] != "Status: Key loaded successfully\n" {
		t.Errorf("Line 5 corrupted: %q", lines[5])
	}

	captured := s.String()
	leaks := []string{
		"MIIEowIBAAKCAQEA0Y1W9Z5l",
		"uE9O5bK0Jk1M2N3P4Q5R6S7T",
	}
	for _, lk := range leaks {
		if strings.Contains(captured, lk) {
			t.Fatalf("CRITICAL LEAK: Private key material found in capture buffer: %q", captured)
		}
	}
}

func TestScriptStreamRedactsCapturedBuffer(t *testing.T) {
	s, _ := collectStream(t, "user=admin password=SecretAdminPass123! token=ghp_tok789\n")
	captured := s.String()
	expected := "user=admin password=[REDACTED] token=[REDACTED]\n"
	if captured != expected {
		t.Errorf("Captured buffer mismatch:\nExpected: %q\nActual:   %q", expected, captured)
	}
	if strings.Contains(captured, "SecretAdminPass123!") || strings.Contains(captured, "ghp_tok789") {
		t.Fatalf("Secret leaked in captured stream buffer: %q", captured)
	}
}

func TestScriptStreamConcurrentWrites(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	s := newScriptStream(func(l string) {
		mu.Lock()
		lines = append(lines, l)
		mu.Unlock()
	})

	var wg sync.WaitGroup
	numWorkers := 8
	linesPerWorker := 25

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < linesPerWorker; j++ {
				chunk := fmt.Sprintf("Worker %d Line %d: password=Secret_%d_%d token=Tok_%d_%d\n", workerID, j, workerID, j, workerID, j)
				_, _ = s.Write([]byte(chunk))
			}
		}(i)
	}

	wg.Wait()
	s.flush()

	mu.Lock()
	collected := append([]string(nil), lines...)
	mu.Unlock()

	if len(collected) != numWorkers*linesPerWorker {
		t.Fatalf("Expected %d lines, got %d", numWorkers*linesPerWorker, len(collected))
	}

	for idx, line := range collected {
		if strings.Contains(line, "Secret_") || strings.Contains(line, "Tok_") {
			t.Fatalf("Leak in line %d: %q", idx, line)
		}
		if !strings.Contains(line, "password=[REDACTED]") || !strings.Contains(line, "token=[REDACTED]") {
			t.Fatalf("Missing redaction marker in line %d: %q", idx, line)
		}
	}
}

func TestScriptRunnerRedactsSecretsInOutput(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd script runner test for windows")
	}
	r := newScriptRunner()
	body := "@echo off\r\n" +
		"echo user=admin password=SecretPassword123! host=db.internal\r\n" +
		"echo Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.tok\r\n"
	var (
		mu       sync.Mutex
		streamed []string
	)
	res := r.run(context.Background(), protocol.ScriptRun{RunID: "redact-run", Language: "cmd", Body: body, Timeout: 30}, func(c protocol.ScriptChunk) {
		mu.Lock()
		streamed = append(streamed, c.Data)
		mu.Unlock()
	})
	if res.ExitCode != 0 || res.Error != "" {
		t.Fatalf("run failed: exit=%d err=%q", res.ExitCode, res.Error)
	}
	if strings.Contains(res.Stdout, "SecretPassword123!") || strings.Contains(res.Stdout, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatalf("CRITICAL LEAK in res.Stdout: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "password=[REDACTED]") || !strings.Contains(res.Stdout, "Bearer [REDACTED]") {
		t.Fatalf("Redaction marker missing in res.Stdout: %q", res.Stdout)
	}
	mu.Lock()
	allStreamed := strings.Join(streamed, "")
	mu.Unlock()
	if strings.Contains(allStreamed, "SecretPassword123!") || strings.Contains(allStreamed, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatalf("CRITICAL LEAK in streamed chunks: %q", allStreamed)
	}
}
