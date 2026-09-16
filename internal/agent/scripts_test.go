package agent

import (
	"context"
	"os"
	"path/filepath"
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
