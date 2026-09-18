package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The log is the only durable copy of the setup code, so the parser is the
// whole feature. These pin the cases that actually occur in a real server.log.

func TestLatestSetupCodeTakesTheMostRecentOne(t *testing.T) {
	// A code is minted on every start that finds no users, so a log from a
	// server restarted three times holds three codes and only the last is
	// still live. Handing back an earlier one sends the operator in a circle.
	dir := t.TempDir()
	path := filepath.Join(dir, "server.log")
	var b strings.Builder
	for _, code := range []string{"aaaa1111", "bbbb2222", "cccc3333"} {
		b.WriteString(`time=2026-09-18T10:00:00.000Z level=INFO msg=listening addr=[::]:8443` + "\n")
		fmt.Fprintf(&b, `time=2026-09-18T10:00:00.001Z level=WARN msg="FIRST RUN: no users yet. Open the console and create the administrator. The setup form asks for this one-time code" setup_code=%s`+"\n", code)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := latestSetupCode(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "cccc3333" {
		t.Fatalf("latestSetupCode = %q, want the last code cccc3333", got)
	}
}

func TestLatestSetupCodeIgnoresAnOrdinaryLog(t *testing.T) {
	// A server that has users mints no code, and the command has to say so
	// rather than return something arbitrary from a nearby line.
	dir := t.TempDir()
	path := filepath.Join(dir, "server.log")
	os.WriteFile(path, []byte(
		"time=2026-09-18T10:00:00.000Z level=INFO msg=listening addr=[::]:8443 fingerprint=ab:cd\n"+
			"time=2026-09-18T10:00:01.000Z level=INFO msg=\"agent connected\" agent=box\n"), 0o600)
	got, err := latestSetupCode(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("latestSetupCode = %q, want empty for a log with no code", got)
	}
}

func TestLatestSetupCodeHandlesAQuotedValue(t *testing.T) {
	// slog's text handler quotes a value only when it has to. The code is hex
	// today so it never is, but a parser that only accepts the bare form would
	// break silently if that ever changed.
	dir := t.TempDir()
	path := filepath.Join(dir, "server.log")
	os.WriteFile(path, []byte(`time=2026-09-18T10:00:00Z level=WARN msg="FIRST RUN" setup_code="3f9a1c07"`+"\n"), 0o600)
	got, err := latestSetupCode(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "3f9a1c07" {
		t.Fatalf("latestSetupCode = %q, want 3f9a1c07 unquoted", got)
	}
}

func TestLatestSetupCodeStopsAtTheNextAttribute(t *testing.T) {
	// An attribute after the code must not be swallowed into it.
	dir := t.TempDir()
	path := filepath.Join(dir, "server.log")
	os.WriteFile(path, []byte(`time=2026-09-18T10:00:00Z level=WARN msg="FIRST RUN" setup_code=3f9a1c07 data=C:\ProgramData`+"\n"), 0o600)
	got, err := latestSetupCode(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "3f9a1c07" {
		t.Fatalf("latestSetupCode = %q, want the code alone", got)
	}
}

func TestLatestSetupCodeTreatsAMissingLogAsNoCode(t *testing.T) {
	// A server that has never started has no log. That is the "restart and
	// look again" case, not an error to report as a failure to read a file.
	got, err := latestSetupCode(filepath.Join(t.TempDir(), "absent.log"))
	if err != nil {
		t.Fatalf("a missing log must not be an error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}
