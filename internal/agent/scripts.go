package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// scriptRunner executes script bodies with streaming output and cancellation.
type scriptRunner struct {
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

func newScriptRunner() *scriptRunner {
	// An agent that was killed mid-run (or whose removal kept failing) leaves
	// its run directory behind with the script body still in it, and nothing
	// else ever looks at it again. The first runner in the process sweeps.
	scriptSweep.Do(func() { go sweepScriptTemp(os.TempDir()) })
	return &scriptRunner{cancels: map[string]context.CancelFunc{}}
}

var scriptSweep sync.Once

func (r *scriptRunner) cancel(runID string) {
	r.mu.Lock()
	c := r.cancels[runID]
	r.mu.Unlock()
	if c != nil {
		c()
	}
}

const (
	// maxCapture is how much of each stream the final result carries. What
	// goes past it is streamed but not stored, so the capture says so
	// (scriptTruncated) rather than ending mid-sentence.
	maxCapture = 1 << 20
	// maxScriptLine bounds how much of a line with no newline in it a stream
	// holds before delivering it as a chunk of its own. A bufio.Scanner used
	// to sit here and it failed with ErrTooLong on the first line over 1 MiB,
	// which left the pipe undrained, the interpreter blocked on write and the
	// run wedged until its timeout killed it.
	maxScriptLine = 1 << 20
	// scriptTruncated marks a capture that stopped short, the way
	// exec_windows.go and the server's own cap already mark theirs.
	scriptTruncated = "\n[output truncated]"
	// scriptTempPrefix names a run's private temp directory.
	scriptTempPrefix = "rmm-script-"
	// scriptTempMaxAge is how old an orphan must be before the startup sweep
	// removes it, so a run in flight - here or in another agent on the same
	// machine - is never pulled out from under.
	scriptTempMaxAge = time.Hour
	// scriptWaitDelay bounds how long Wait may block on a pipe a grandchild
	// inherited and kept open after the interpreter itself exited.
	scriptWaitDelay = 10 * time.Second
)

// run writes the body to a temp file with the right extension, launches the
// interpreter, streams stdout/stderr lines as they arrive and returns the
// final result. Timeout and cancel both kill the process tree.
func (r *scriptRunner) run(parent context.Context, req protocol.ScriptRun, emit func(protocol.ScriptChunk)) *protocol.ScriptResult {
	res := &protocol.ScriptResult{RunID: req.RunID, ExitCode: -1}
	start := time.Now()
	timeout := time.Duration(req.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	r.mu.Lock()
	r.cancels[req.RunID] = cancel
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.cancels, req.RunID)
		r.mu.Unlock()
		res.Duration = time.Since(start).Milliseconds()
	}()

	dir, err := os.MkdirTemp("", scriptTempPrefix)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer removeScriptDir(dir)
	file := filepath.Join(dir, "script"+scriptExt(req.Language))
	body := req.Body
	if req.Language != "cmd" {
		body = strings.ReplaceAll(body, "\r\n", "\n")
	}
	if err := os.WriteFile(file, scriptFileBytes(req.Language, body), 0o700); err != nil {
		res.Error = err.Error()
		return res
	}
	cmd, err := scriptCommand(ctx, req.Language, file, req.Args)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	cmd.Dir = dir
	cmd.Env = os.Environ()
	if req.Language == "python" {
		// A redirected python writes its stdout in the locale encoding, which
		// on Windows is the ANSI code page. Ask for UTF-8 instead, before
		// req.Env so an operator can still override it.
		cmd.Env = append(cmd.Env, "PYTHONIOENCODING=utf-8")
	}
	for k, v := range req.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Env = append(cmd.Env, "RMM_RUN_ID="+req.RunID)
	prepareCommand(cmd)

	outS := newScriptStream(func(data string) { emit(protocol.ScriptChunk{RunID: req.RunID, Stream: "stdout", Data: data}) })
	errS := newScriptStream(func(data string) { emit(protocol.ScriptChunk{RunID: req.RunID, Stream: "stderr", Data: data}) })
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = outS, errS
	// exec owns the pipes rather than the runner: a grandchild that inherited
	// them must not keep Wait blocked once the interpreter itself has gone
	// (exec_windows.go relies on the same delay). prepareCommand sets one on
	// the platforms that have an opinion.
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = scriptWaitDelay
	}
	if err := cmd.Start(); err != nil {
		res.Error = err.Error()
		return res
	}
	waitErr := cmd.Wait()
	outS.flush()
	errS.flush()
	res.Stdout, res.Stderr = outS.String(), errS.String()
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.Error = fmt.Sprintf("timed out after %s", timeout)
		return res
	}
	if ctx.Err() == context.Canceled && parent.Err() == nil {
		// The server reads this exact text back as the "cancelled" run status
		// (internal/server/runs.go), so an operator's own cancel is not
		// recorded, counted or alerted on as a script failure.
		res.Error = "cancelled"
		return res
	}
	var ee *exec.ExitError
	switch {
	case waitErr == nil:
		res.ExitCode = 0
	case errors.As(waitErr, &ee):
		res.ExitCode = scriptExitCode(ee.ExitCode())
	case errors.Is(waitErr, exec.ErrWaitDelay):
		// The interpreter exited cleanly; only an inherited pipe lingered.
		res.ExitCode = 0
	default:
		res.Error = waitErr.Error()
	}
	return res
}

// ---- output ----

// scriptStream is the io.Writer behind one of a run's two pipes. It splits
// the interpreter's bytes into lines as they arrive and hands each to onLine,
// decoding them first because a Windows interpreter answers in the console
// code page rather than UTF-8. It keeps at most maxCapture bytes for the
// final result and remembers that it dropped the rest, and it never refuses
// or delays a write: exec owns the pipe, so a writer that blocked would block
// the interpreter with it.
type scriptStream struct {
	onLine func(string)
	limit  int

	mu        sync.Mutex
	b         strings.Builder
	pending   []byte
	truncated bool
}

func newScriptStream(onLine func(string)) *scriptStream {
	return &scriptStream{onLine: onLine, limit: maxCapture}
}

func (s *scriptStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.pending = append(s.pending, p...)
	var lines []string
	for {
		i := bytes.IndexByte(s.pending, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, scriptDecodeOutput(bytes.TrimSuffix(s.pending[:i], []byte("\r")))+"\n")
		s.pending = s.pending[i+1:]
	}
	if len(s.pending) >= maxScriptLine {
		// A line with no end in sight: hand over what there is instead of
		// buffering it forever. No "\n" - the line has not ended.
		lines = append(lines, scriptDecodeOutput(s.pending))
		s.pending = nil
	}
	if len(s.pending) == 0 {
		s.pending = nil // release the backing array between lines
	}
	for _, l := range lines {
		s.capture(l)
	}
	s.mu.Unlock()
	for _, l := range lines {
		s.onLine(l)
	}
	return len(p), nil
}

// flush delivers a last line that had no newline of its own; call it once the
// interpreter has exited.
func (s *scriptStream) flush() {
	s.mu.Lock()
	var line string
	if len(s.pending) > 0 {
		line = scriptDecodeOutput(bytes.TrimSuffix(s.pending, []byte("\r"))) + "\n"
		s.pending = nil
		s.capture(line)
	}
	s.mu.Unlock()
	if line != "" {
		s.onLine(line)
	}
}

// capture appends to the stored copy until the cap, never splitting a rune.
func (s *scriptStream) capture(v string) {
	room := s.limit - s.b.Len()
	switch {
	case room <= 0:
		s.truncated = true
	case len(v) > room:
		for room > 0 && !utf8.RuneStart(v[room]) {
			room--
		}
		s.b.WriteString(v[:room])
		s.truncated = true
	default:
		s.b.WriteString(v)
	}
}

// String is the capture as the result carries it; call it after flush.
func (s *scriptStream) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.truncated {
		return s.b.String() + scriptTruncated
	}
	return s.b.String()
}

// ---- temp directory ----

// removeScriptDir deletes a run's temp directory. The interpreter had it as
// its working directory and a scanner may still hold the script file open for
// a moment after the process exits, so a first failure is retried rather than
// discarded: an unreported failure leaves the script body on disk for good.
func removeScriptDir(dir string) {
	delay := 50 * time.Millisecond
	for attempt := 0; ; attempt++ {
		err := os.RemoveAll(dir)
		if err == nil {
			return
		}
		if attempt == 3 {
			slog.Warn("script temp directory left behind", "dir", dir, "err", err)
			return
		}
		time.Sleep(delay)
		delay *= 2
	}
}

// sweepScriptTemp removes the run directories of an agent that never got to
// clean up after itself. Only directories old enough that no live run can own
// one are touched.
func sweepScriptTemp(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	swept := 0
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !scriptTempStale(e.Name(), e.IsDir(), info.ModTime(), time.Now()) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, e.Name())); err != nil {
			slog.Warn("stale script temp directory left behind", "dir", e.Name(), "err", err)
			continue
		}
		swept++
	}
	if swept > 0 {
		slog.Info("removed stale script temp directories", "count", swept)
	}
}

// scriptTempStale reports whether a temp entry is an abandoned run directory.
func scriptTempStale(name string, isDir bool, mod, now time.Time) bool {
	return isDir && strings.HasPrefix(name, scriptTempPrefix) && now.Sub(mod) >= scriptTempMaxAge
}

// ---- the script file ----

func scriptExt(lang string) string {
	switch lang {
	case "powershell":
		return ".ps1"
	case "cmd":
		return ".cmd"
	case "python":
		return ".py"
	default:
		return ".sh"
	}
}

// scriptFileBytes encodes the body for the interpreter that is about to read
// the file. Windows PowerShell 5.1 decodes a BOM-less .ps1 with the ANSI code
// page, so a body holding any non-ASCII character is mojibake - often a parse
// error - before it ever runs; the UTF-8 BOM is what tells it otherwise, and
// updates_windows.go's writeTempScript already does this for the Windows
// Update helper. pwsh 7 reads the BOM just as happily. Everything else gets
// the bytes as the operator wrote them: python and the shells read UTF-8, and
// cmd.exe would echo a BOM as part of the first line. A .cmd body is
// therefore limited to what the device's OEM code page can express (ASCII
// everywhere); docs/ARCHITECTURE.md says so.
func scriptFileBytes(lang, body string) []byte {
	if lang == "powershell" {
		return append([]byte{0xEF, 0xBB, 0xBF}, body...)
	}
	return []byte(body)
}

// ---- exit codes ----

// scriptExitCode normalises the platform's exit status for the result.
func scriptExitCode(code int) int { return signedExitCode(code, runtime.GOOS == "windows") }

// signedExitCode sign-extends a Windows exit status. Windows hands back the
// raw DWORD, so `exit -1` arrives as 4294967295 and an access violation as
// 3221225477; as int32 they read -1 and -1073741819, which is what the
// operator wrote and what PowerShell's own $LASTEXITCODE shows. -1 is also
// the "never produced an exit code" value the runner starts from, but the two
// are told apart by the run's status, which is timeout or cancelled whenever
// no code was produced.
func signedExitCode(code int, windows bool) int {
	if windows && code > math.MaxInt32 {
		return int(int32(uint32(code)))
	}
	return code
}

// ---- the interpreter ----

// scriptCommand builds the interpreter invocation. PowerShell prefers pwsh
// (7) when present and falls back to Windows PowerShell 5.1. On Windows every
// interpreter is resolved by absolute path rather than through PATH: the
// agent runs as SYSTEM, and exec_windows.go's systemExe spells out why a
// writable directory that made it onto the machine PATH must never get to
// choose which binary a script run executes.
func scriptCommand(ctx context.Context, lang, file string, args []string) (*exec.Cmd, error) {
	switch lang {
	case "powershell":
		exe, err := powershellScriptExe()
		if err != nil {
			return nil, err
		}
		return exec.CommandContext(ctx, exe, append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file}, args...)...), nil
	case "cmd":
		if runtime.GOOS != "windows" {
			return nil, errors.New("cmd scripts only run on Windows")
		}
		return cmdScriptCommand(ctx, file, args)
	case "python":
		exe, err := pythonScriptExe()
		if err != nil {
			return nil, err
		}
		return exec.CommandContext(ctx, exe, append([]string{file}, args...)...), nil
	case "bash":
		if p, err := exec.LookPath("bash"); err == nil {
			return exec.CommandContext(ctx, p, append([]string{file}, args...)...), nil
		}
		if runtime.GOOS == "windows" {
			return nil, errors.New("bash is not available on this Windows device")
		}
		return exec.CommandContext(ctx, "sh", append([]string{file}, args...)...), nil
	case "sh":
		if runtime.GOOS == "windows" {
			return nil, errors.New("sh scripts do not run on Windows")
		}
		return exec.CommandContext(ctx, "sh", append([]string{file}, args...)...), nil
	}
	return nil, errors.New("unsupported language " + lang)
}

// ---- cmd.exe quoting ----
//
// exec quotes arguments with syscall.EscapeArg, which follows the
// CommandLineToArgvW rules every normal program parses with. cmd.exe does not
// implement those rules - it counts quote characters and knows no escapes -
// so EscapeArg's \" for a literal quote ends the quoted region and the rest
// of the value is run as a further command, as SYSTEM, under an audit entry
// that shows only the parameter. Arguments are data (docs/SECURITY.md: "never
// a shell string"), so the command line for a .cmd run is built here instead.

// cmdQuotable are the characters cmd.exe acts on outside a quoted region and
// passes through as data inside one, so quoting is enough to tame them.
const cmdQuotable = " \t&|<>^()"

// cmdUnsafeArg reports the first character of v that cmd.exe would act on
// even inside a quoted region, and that therefore cannot reach a .cmd script
// as data: a double quote ends the region, % is expanded as a variable
// reference wherever it stands, ! is too on a device where delayed expansion
// is switched on by default, and a newline ends the command line.
func cmdUnsafeArg(v string) (rune, bool) {
	if i := strings.IndexAny(v, "\"%!\r\n\x00"); i >= 0 {
		return rune(v[i]), true
	}
	return 0, false
}

// cmdQuote wraps a value in the one form cmd.exe and a batch file's %1..%9
// agree on - a "..." region with nothing escaped inside it - and only when it
// is needed, so a plain value still arrives as the bare %1 it always did.
// cmdUnsafeArg has already rejected what this cannot express.
func cmdQuote(v string) string {
	if v == "" {
		return `""`
	}
	if strings.ContainsAny(v, cmdQuotable) {
		return `"` + v + `"`
	}
	return v
}

// cmdScriptLine is the command line for "cmd.exe /d /c <script> <args...>".
// Everything after /c is one string that cmd.exe parses itself, and when that
// string opens with a quote cmd strips the first quote and the *last* one
// before parsing (the rule under `cmd /?`), which would tear the last
// argument apart - so it is wrapped in one more pair, the documented way to
// keep it whole.
func cmdScriptLine(exe, file string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, cmdQuote(file))
	for _, a := range args {
		parts = append(parts, cmdQuote(a))
	}
	line := strings.Join(parts, " ")
	if strings.HasPrefix(line, `"`) {
		line = `"` + line + `"`
	}
	return cmdQuote(exe) + " /d /c " + line
}

// ---- python versions ----

// pythonKeyNewer compares two PythonCore registry key names ("3.12", "3.9",
// "3.12-32"). A lexical compare would prefer 3.9 over 3.12, and the 32-bit
// key of a version loses to the 64-bit one.
func pythonKeyNewer(a, b string) bool {
	amaj, amin, a32 := parsePythonKey(a)
	bmaj, bmin, b32 := parsePythonKey(b)
	switch {
	case amaj != bmaj:
		return amaj > bmaj
	case amin != bmin:
		return amin > bmin
	default:
		return b32 && !a32
	}
}

func parsePythonKey(k string) (major, minor int, win32 bool) {
	if base, suffix, ok := strings.Cut(k, "-"); ok {
		win32, k = suffix == "32", base
	}
	majS, minS, _ := strings.Cut(k, ".")
	major, _ = strconv.Atoi(majS)
	minor, _ = strconv.Atoi(minS)
	return major, minor, win32
}
