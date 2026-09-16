package main

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// brokenStderr is os.Stderr in a process the Windows Service Control Manager
// started: GetStdHandle hands back 0 and every write fails.
type brokenStderr struct{ writes int }

func (b *brokenStderr) Write(p []byte) (int, error) {
	b.writes++
	return 0, errors.New("write /dev/stderr: The handle is invalid.")
}

// TestLoggingReachesTheFileOverABrokenStderr is the server half of the agent's
// test of the same name: the handler was io.MultiWriter(os.Stderr, f), which
// returns on the first writer's error and never reaches the file, and slog
// throws that error away. Under the SCM that left server.log at 0 bytes - and
// server.log is where docs/OPERATIONS.md sends the operator for the one-time
// first-run setup code, which is the only way into a fresh console.
func TestLoggingReachesTheFileOverABrokenStderr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stderr := &brokenStderr{}
	setupHandler(stderr, f)
	// The server never closes its log; this test must, or Windows will not
	// let the temporary directory go.
	t.Cleanup(func() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) })

	slog.Warn("FIRST RUN: no users yet. Open the console and create the administrator. The setup form asks for this one-time code", "setup_code", "3f9a1c07")
	slog.Info("listening", "addr", "[::]:8443", "tls", true)
	f.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"setup_code=3f9a1c07", "msg=listening"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("server.log is missing %q; it has:\n%s", want, b)
		}
	}
	if stderr.writes == 0 {
		t.Error("stderr was dropped from the handler even before it failed")
	}
}

// setupLogging hands over a nil file when the data directory cannot be
// written; the server still runs, and logging must not panic.
func TestLoggingStillWorksWithNoFileAtAll(t *testing.T) {
	setupHandler(io.Discard, nil)
	t.Cleanup(func() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) })
	slog.Info("still here")
}
