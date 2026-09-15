//go:build windows

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/sys/windows"
)

// winMaxOutput caps what a helper command may hand back. A 2000-event
// wevtutil page in RenderedXml is the largest legitimate output and fits
// comfortably; anything bigger is a runaway process and gets truncated.
const winMaxOutput = 32 << 20

// outputBuffer collects at most limit bytes and remembers that it dropped
// the rest. It never fails the write, so a chatty child is never killed by
// a broken pipe before it finishes its real work. Bytes are kept raw and
// decoded once at String time, because the code page is a property of the
// whole capture, not of one chunk.
type outputBuffer struct {
	mu        sync.Mutex
	b         bytes.Buffer
	limit     int
	truncated bool
}

func (o *outputBuffer) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	room := o.limit - o.b.Len()
	switch {
	case room <= 0:
		o.truncated = true
	case len(p) > room:
		o.b.Write(p[:room])
		o.truncated = true
	default:
		o.b.Write(p)
	}
	return len(p), nil
}

func (o *outputBuffer) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := winDecodeOutput(o.b.Bytes())
	if o.truncated {
		return s + "\n[output truncated]"
	}
	return s
}

// cpOEM is CP_OEMCP, "the system's current OEM code page": what console
// tools (wevtutil, query, shutdown, Windows PowerShell 5.1) write when their
// stdout is a pipe rather than a console.
const cpOEM = 1

// winDecodeOutput turns a tool's raw stdout into a Go string. Output that is
// already valid UTF-8 (pwsh 7, winget, anything ASCII) is used as is; the
// rest is decoded from the OEM code page so an accented character in an
// event-log message or an update title reaches the operator instead of
// turning into U+FFFD in the JSON reply.
func winDecodeOutput(b []byte) string {
	if len(b) == 0 || utf8.Valid(b) {
		return string(b)
	}
	n, err := windows.MultiByteToWideChar(cpOEM, 0, &b[0], int32(len(b)), nil, 0)
	if err != nil || n <= 0 {
		return string(b)
	}
	buf := make([]uint16, n)
	if _, err := windows.MultiByteToWideChar(cpOEM, 0, &b[0], int32(len(b)), &buf[0], n); err != nil {
		return string(b)
	}
	return string(utf16.Decode(buf))
}

// systemExe resolves a bare tool name against %SystemRoot%\System32 before
// PATH. The agent runs as SYSTEM, so a writable directory that somehow made
// it onto PATH must never be able to shadow shutdown.exe or wevtutil.exe.
func systemExe(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	base := name
	if !strings.HasSuffix(strings.ToLower(base), ".exe") {
		base += ".exe"
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	p := filepath.Join(root, "System32", base)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if lp, err := exec.LookPath(name); err == nil {
		return lp
	}
	return name
}

// runHidden executes name with args (never through a shell) without a
// console window, captures stdout and stderr separately and honours ctx by
// killing the whole process tree. err is non-nil when the command could not
// run, was killed by ctx, or exited non-zero; stdout and stderr are returned
// in every case so callers can read a tool's own error text.
func runHidden(ctx context.Context, name string, args ...string) (stdout, stderr string, err error) {
	return runHiddenLines(ctx, nil, name, args...)
}

// runHiddenLines is runHidden for a long-running child whose stdout is worth
// watching live: every complete line is handed to onLine as it arrives (a
// PowerShell install script's PROGRESS lines) while the whole capture is
// still returned at the end. The pipe stays exec's own so WaitDelay can
// close it should a grandchild inherit it and outlive the child; a raw
// os.Pipe would leave the reader blocked for as long as that grandchild
// lives.
func runHiddenLines(ctx context.Context, onLine func(string), name string, args ...string) (stdout, stderr string, err error) {
	cmd := exec.CommandContext(ctx, systemExe(name), args...)
	prepareCommand(cmd)
	cmd.Stdin = nil
	outB := &outputBuffer{limit: winMaxOutput}
	errB := &outputBuffer{limit: 1 << 20}
	var splitter *winLineSplitter
	if onLine != nil {
		splitter = &winLineSplitter{sink: outB, decode: winDecodeOutput, onLine: onLine}
		cmd.Stdout = splitter
	} else {
		cmd.Stdout = outB
	}
	cmd.Stderr = errB
	// A grandchild that inherited our pipes must not keep Wait blocked after
	// the child itself has gone.
	cmd.WaitDelay = 10 * time.Second
	runErr := cmd.Run()
	if splitter != nil {
		splitter.flush()
	}
	stdout, stderr = outB.String(), errB.String()
	switch {
	case ctx.Err() != nil:
		err = fmt.Errorf("%s: %w", name, ctx.Err())
	case runErr == nil:
	case errors.Is(runErr, exec.ErrWaitDelay):
		// The child itself exited cleanly; only an inherited pipe lingered.
	default:
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			err = fmt.Errorf("%s exited with %d: %s", name, ee.ExitCode(), winFirstLine(stderr, stdout))
		} else {
			err = fmt.Errorf("%s: %w", name, runErr)
		}
	}
	return stdout, stderr, err
}
