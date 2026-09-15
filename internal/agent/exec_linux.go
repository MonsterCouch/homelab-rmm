//go:build linux

package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// maxCmdOutput caps what a helper command may hand back. Package listings
// and journal dumps are the biggest legitimate outputs and they fit in a few
// MB; anything larger is a runaway process and gets truncated, not buffered.
const maxCmdOutput = 10 << 20

// stableEnv is appended to every helper command so parsers see English,
// untranslated, un-localised output whatever the service environment is.
var stableEnv = []string{"LC_ALL=C", "LANG=C", "LANGUAGE=C"}

// cappedBuffer collects at most cap bytes and remembers that it dropped the
// rest; it never fails the write so the child is not killed by a SIGPIPE.
type cappedBuffer struct {
	mu        sync.Mutex
	b         strings.Builder
	cap       int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.cap - c.b.Len()
	if room <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		c.b.Write(p[:room])
		c.truncated = true
		return len(p), nil
	}
	c.b.Write(p)
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.truncated {
		return c.b.String() + "\n[output truncated]"
	}
	return c.b.String()
}

// errNotFound tells callers a helper binary is simply absent, which for most
// features means "degrade", not "fail".
var errNotFound = errors.New("command not found")

// runCmd executes name with args (never through a shell), captures stdout
// and stderr separately (each capped at maxCmdOutput) and returns the exit
// code. err is non-nil when the command could not run at all, was killed by
// ctx, or exited non-zero; exitCode is -1 when no code is available.
// Callers that treat particular exit codes as data (dnf check-update = 100,
// pacman -Qu = 1) inspect exitCode and ignore err.
func runCmd(ctx context.Context, name string, args ...string) (stdout, stderr string, exitCode int, err error) {
	return runCmdEnv(ctx, nil, name, args...)
}

// runCmdEnv is runCmd with extra KEY=VALUE pairs appended to the environment
// (DEBIAN_FRONTEND=noninteractive and friends).
func runCmdEnv(ctx context.Context, extraEnv []string, name string, args ...string) (stdout, stderr string, exitCode int, err error) {
	path, lerr := exec.LookPath(name)
	if lerr != nil {
		return "", "", -1, fmt.Errorf("%s: %w", name, errNotFound)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(append(os.Environ(), stableEnv...), extraEnv...)
	cmd.Stdin = nil
	outB := &cappedBuffer{cap: maxCmdOutput}
	errB := &cappedBuffer{cap: maxCmdOutput}
	cmd.Stdout, cmd.Stderr = outB, errB
	prepareCommand(cmd)
	runErr := cmd.Run()
	stdout, stderr = outB.String(), errB.String()
	exitCode = -1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	if runErr != nil && ctx.Err() != nil {
		// Killed by the deadline (or the process was, and the context is the
		// reason). A command that exited cleanly a moment before its context
		// ended is a success, not a timeout.
		return stdout, stderr, exitCode, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return stdout, stderr, exitCode, fmt.Errorf("%s exited with %d: %s", name, exitCode, firstLine(stderr))
		}
		return stdout, stderr, exitCode, fmt.Errorf("%s: %w", name, runErr)
	}
	return stdout, stderr, exitCode, nil
}

// runCmdTimeout is runCmd for call sites that have no context of their own
// (service listing, journal queries, power actions).
func runCmdTimeout(d time.Duration, name string, args ...string) (stdout, stderr string, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return runCmd(ctx, name, args...)
}

// streamCmd runs a long command (package installs) and hands every line of
// stdout and stderr to progress as it appears, so the operator watches the
// install live instead of staring at a spinner. The combined log is also
// returned, capped like runCmd.
func streamCmd(ctx context.Context, extraEnv []string, progress func(string), name string, args ...string) (log string, exitCode int, err error) {
	path, lerr := exec.LookPath(name)
	if lerr != nil {
		return "", -1, fmt.Errorf("%s: %w", name, errNotFound)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(append(os.Environ(), stableEnv...), extraEnv...)
	cmd.Stdin = nil
	prepareCommand(cmd)
	stdout, perr := cmd.StdoutPipe()
	if perr != nil {
		return "", -1, fmt.Errorf("%s: %w", name, perr)
	}
	stderr, perr := cmd.StderrPipe()
	if perr != nil {
		return "", -1, fmt.Errorf("%s: %w", name, perr)
	}
	if err := cmd.Start(); err != nil {
		return "", -1, fmt.Errorf("%s: %w", name, err)
	}
	logB := &cappedBuffer{cap: maxCmdOutput}
	var (
		wg  sync.WaitGroup
		pmu sync.Mutex
	)
	pump := func(rd io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(rd)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			logB.Write([]byte(line + "\n"))
			if progress != nil && strings.TrimSpace(line) != "" {
				pmu.Lock()
				progress(line)
				pmu.Unlock()
			}
		}
		// Drain whatever the scanner refused (a line over 1 MB) so the child
		// is never blocked on a full pipe.
		io.Copy(io.Discard, rd)
	}
	wg.Add(2)
	go pump(stdout)
	go pump(stderr)
	wg.Wait()
	waitErr := cmd.Wait()
	exitCode = -1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	log = logB.String()
	if waitErr != nil && ctx.Err() != nil {
		return log, exitCode, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			return log, exitCode, fmt.Errorf("%s exited with %d", name, exitCode)
		}
		return log, exitCode, fmt.Errorf("%s: %w", name, waitErr)
	}
	return log, exitCode, nil
}

// hasCmd reports whether a helper binary is on PATH.
func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// firstLine trims a stderr blob to its first non-empty line for error text.
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// readSysFile reads a small file such as a /sys or /etc entry and returns
// its trimmed content, or "" on any error.
func readSysFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// fileExists is a stat helper for "is this signal present" checks.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
