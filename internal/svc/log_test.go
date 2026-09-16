package svc

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deadSink is os.Stderr in a process the Windows Service Control Manager
// started: the handle is 0 and every write fails.
type deadSink struct{ writes int }

func (d *deadSink) Write(p []byte) (int, error) {
	d.writes++
	return 0, errors.New("write /dev/stderr: The handle is invalid.")
}

// TestLogWriterKeepsTheOtherSinksWhenOneFails pins the bug that left
// agent.log 0 bytes on every Windows service install: io.MultiWriter returns
// on the first writer's error, so the log file behind a dead stderr never saw
// a byte, and slog threw the error away.
func TestLogWriterKeepsTheOtherSinksWhenOneFails(t *testing.T) {
	dead := &deadSink{}
	var file bytes.Buffer
	n, err := LogWriter(dead, &file).Write([]byte("connected\n"))
	if err != nil {
		t.Fatalf("Write = %v, want a dead sink tolerated", err)
	}
	if n != len("connected\n") {
		t.Fatalf("Write = %d bytes, want %d", n, len("connected\n"))
	}
	if file.String() != "connected\n" {
		t.Fatalf("the log file got %q", file.String())
	}
	if dead.writes == 0 {
		t.Fatal("the failing sink was never offered the record")
	}
}

// The same thing one level up, where the bug actually lived: slog discards its
// handler's write error, so a handler that gives up on the first failing sink
// loses the record silently.
func TestLogWriterLetsSlogReachTheFileOverADeadStderr(t *testing.T) {
	var file bytes.Buffer
	log := slog.New(slog.NewTextHandler(LogWriter(&deadSink{}, &file), nil))
	log.Info("connected", "server", "https://rmm.lan:8443")
	if !strings.Contains(file.String(), "connected") {
		t.Fatalf("the log file got %q", file.String())
	}
}

func TestLogWriterDropsAFileItCannotWrite(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "closed.log"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close() // Stat now fails, exactly as it does for a handle the SCM never gave us
	var file bytes.Buffer
	if _, err := LogWriter(f, &file).Write([]byte("x")); err != nil {
		t.Fatalf("Write = %v", err)
	}
	if file.String() != "x" {
		t.Fatalf("the usable sink got %q", file.String())
	}
}

func TestLogWriterWithNothingUsableStillAcceptsWrites(t *testing.T) {
	// A process that can open no log at all still runs; it must not panic or
	// block on the first line it writes.
	w := LogWriter(nil)
	if w != io.Discard {
		t.Fatalf("LogWriter() = %T, want io.Discard", w)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatalf("Write = %v", err)
	}
}

func TestLogWriterReportsFailureOnlyWhenEverySinkRefused(t *testing.T) {
	if _, err := LogWriter(&deadSink{}, &deadSink{}).Write([]byte("x")); err == nil {
		t.Fatal("two dead sinks reported a successful write")
	}
}
