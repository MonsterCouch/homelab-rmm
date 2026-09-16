package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// scriptRunner executes script bodies with streaming output and cancellation.
type scriptRunner struct {
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

func newScriptRunner() *scriptRunner { return &scriptRunner{cancels: map[string]context.CancelFunc{}} }

func (r *scriptRunner) cancel(runID string) {
	r.mu.Lock()
	c := r.cancels[runID]
	r.mu.Unlock()
	if c != nil {
		c()
	}
}

const maxCapture = 1 << 20

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

	dir, err := os.MkdirTemp("", "rmm-script-")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "script"+scriptExt(req.Language))
	body := req.Body
	if req.Language != "cmd" {
		body = strings.ReplaceAll(body, "\r\n", "\n")
	}
	if err := os.WriteFile(file, []byte(body), 0o700); err != nil {
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
	for k, v := range req.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Env = append(cmd.Env, "RMM_RUN_ID="+req.RunID)
	prepareCommand(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if err := cmd.Start(); err != nil {
		res.Error = err.Error()
		return res
	}
	// On Windows this puts the interpreter and everything it spawns in a
	// kill-on-close job, so a timeout or a cancel reaches a descendant whose
	// parent already exited - the one that would otherwise hold the pipes
	// below open for ever. Elsewhere the process group already does that.
	defer superviseCommand(cmd)()
	var (
		wg         sync.WaitGroup
		outB, errB strings.Builder
		omu        sync.Mutex
	)
	pump := func(rd io.Reader, name string, b *strings.Builder) {
		defer wg.Done()
		sc := bufio.NewScanner(rd)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text() + "\n"
			omu.Lock()
			if b.Len() < maxCapture {
				b.WriteString(line)
			}
			omu.Unlock()
			emit(protocol.ScriptChunk{RunID: req.RunID, Stream: name, Data: line})
		}
	}
	wg.Add(2)
	go pump(stdout, "stdout", &outB)
	go pump(stderr, "stderr", &errB)
	wg.Wait()
	waitErr := cmd.Wait()
	res.Stdout, res.Stderr = outB.String(), errB.String()
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.Error = fmt.Sprintf("timed out after %s", timeout)
		return res
	}
	if ctx.Err() == context.Canceled && parent.Err() == nil {
		res.Error = "cancelled"
		return res
	}
	var ee *exec.ExitError
	switch {
	case waitErr == nil:
		res.ExitCode = 0
	case errors.As(waitErr, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		res.Error = waitErr.Error()
	}
	return res
}

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

// scriptCommand builds the interpreter invocation. PowerShell prefers pwsh
// (7) when present and falls back to Windows PowerShell 5.1.
func scriptCommand(ctx context.Context, lang, file string, args []string) (*exec.Cmd, error) {
	switch lang {
	case "powershell":
		if p, err := exec.LookPath("pwsh"); err == nil {
			return exec.CommandContext(ctx, p, append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file}, args...)...), nil
		}
		if runtime.GOOS == "windows" {
			return exec.CommandContext(ctx, "powershell.exe", append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file}, args...)...), nil
		}
		return nil, errors.New("pwsh is not installed on this device")
	case "cmd":
		if runtime.GOOS != "windows" {
			return nil, errors.New("cmd scripts only run on Windows")
		}
		return exec.CommandContext(ctx, "cmd.exe", append([]string{"/d", "/c", file}, args...)...), nil
	case "python":
		for _, p := range []string{"python3", "python", "py"} {
			if path, err := exec.LookPath(p); err == nil {
				return exec.CommandContext(ctx, path, append([]string{file}, args...)...), nil
			}
		}
		return nil, errors.New("python is not installed on this device")
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
