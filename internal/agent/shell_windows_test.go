//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The terminal's command line is the whole Windows shell contract: which
// binary runs as SYSTEM, and whether what it writes survives the trip to the
// browser. Both were wrong, so both are pinned here.

// A pseudo console starts on the machine OEM code page (437 on an English
// install), and cmd.exe and Windows PowerShell encode their output to it
// before ConPTY ever sees it - so every character outside that page was
// destroyed upstream of the agent. The shell has to be told to use UTF-8 as
// it starts.
func TestShellCommandLineStartsTheSessionInUTF8(t *testing.T) {
	ps, err := shellCommandLine("powershell")
	if err != nil {
		t.Fatalf("powershell: %v", err)
	}
	for _, want := range []string{"-NoExit", "-Command", "OutputEncoding", "InputEncoding", "UTF8Encoding"} {
		if !strings.Contains(ps, want) {
			t.Errorf("powershell command line does not set up UTF-8 (%q missing):\n%s", want, ps)
		}
	}
	if strings.Contains(ps, "$OutputEncoding") == false {
		t.Errorf("powershell 5.1 also needs $OutputEncoding for native pipes:\n%s", ps)
	}
	// "" and "pwsh" are the same shell.
	for _, name := range []string{"", "pwsh"} {
		if got, err := shellCommandLine(name); err != nil || got != ps {
			t.Errorf("shellCommandLine(%q) = %q, %v; want the same as powershell", name, got, err)
		}
	}

	cmd, err := shellCommandLine("cmd")
	if err != nil {
		t.Fatalf("cmd: %v", err)
	}
	if !strings.Contains(strings.ToLower(cmd), `\chcp.com`) || !strings.Contains(cmd, "65001") {
		t.Errorf("cmd command line does not switch the console to code page 65001:\n%s", cmd)
	}
	if !strings.Contains(cmd, ">nul") {
		t.Errorf("chcp's banner is not suppressed, so the session opens with noise:\n%s", cmd)
	}
	if !strings.Contains(cmd, " /k ") {
		t.Errorf("cmd must stay interactive after the prelude (/k):\n%s", cmd)
	}

	if _, err := shellCommandLine("bash"); err == nil {
		t.Error("bash is not a Windows shell and must be refused")
	}
}

// The agent runs as LocalSystem and this binary becomes a SYSTEM shell, so a
// writable directory that made it onto PATH must not be able to choose it -
// the rule systemExe applies to the helper tools, and docs/SECURITY.md
// states for the agent as a whole. The cmd branch was already hardened; the
// PowerShell branch was a bare exec.LookPath.
func TestShellCommandLineIgnoresPwshFromAnUntrustedPath(t *testing.T) {
	untrusted := t.TempDir()
	writeFakeExe(t, filepath.Join(untrusted, "pwsh.exe"))
	// A Program Files with no PowerShell in it, so only PATH could answer.
	t.Setenv("ProgramFiles", t.TempDir())
	t.Setenv("ProgramW6432", "")
	t.Setenv("ProgramFiles(x86)", "")
	t.Setenv("PATH", untrusted+string(os.PathListSeparator)+os.Getenv("PATH"))

	if p := pwshPath(); p != "" {
		t.Errorf("pwshPath accepted %q; a pwsh.exe anyone can write must never be launched as SYSTEM", p)
	}
	got, err := shellCommandLine("powershell")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(got), strings.ToLower(untrusted)) {
		t.Errorf("terminal would launch the PATH pwsh as SYSTEM:\n%s", got)
	}
	if !strings.Contains(strings.ToLower(got), `system32\windowspowershell\v1.0\powershell.exe`) {
		t.Errorf("fallback is not the absolute Windows PowerShell in System32:\n%s", got)
	}
}

// pwsh 7 installed where it belongs is still preferred, and so is one an
// administrator put somewhere else under Program Files and added to PATH.
func TestPwshPathPrefersTheAdminOnlyInstall(t *testing.T) {
	programFiles := t.TempDir()
	t.Setenv("ProgramFiles", programFiles)
	t.Setenv("ProgramW6432", "")
	t.Setenv("ProgramFiles(x86)", "")
	t.Setenv("PATH", "")

	installed := filepath.Join(programFiles, "PowerShell", "7", "pwsh.exe")
	if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeExe(t, installed)
	if got := pwshPath(); got != installed {
		t.Errorf("pwshPath() = %q, want the Program Files install %q", got, installed)
	}
	if got, _ := shellCommandLine("pwsh"); !strings.Contains(got, installed) {
		t.Errorf("terminal did not use the installed pwsh:\n%s", got)
	}

	// Somewhere else under Program Files, reachable only through PATH.
	os.Remove(installed)
	elsewhere := filepath.Join(programFiles, "vendor")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeExe(t, filepath.Join(elsewhere, "pwsh.exe"))
	t.Setenv("PATH", elsewhere)
	if got := pwshPath(); got != filepath.Join(elsewhere, "pwsh.exe") {
		t.Errorf("pwshPath() = %q, want the Program Files copy on PATH", got)
	}
}

func TestUnderAnyDir(t *testing.T) {
	dirs := []string{`C:\Program Files`, `C:\Windows`}
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Program Files\PowerShell\7\pwsh.exe`, true},
		{`c:\program files\powershell\7\pwsh.exe`, true}, // Windows paths are case-insensitive
		{`C:\Windows`, true},
		{`C:\Program Files (x86)\evil\pwsh.exe`, false}, // sibling, not a child
		{`C:\Users\temp\pwsh.exe`, false},
		{`C:\Program Files\..\Users\temp\pwsh.exe`, false}, // cannot walk out of a root
		{``, false},
	}
	for _, c := range cases {
		if got := underAnyDir(dirs, c.path); got != c.want {
			t.Errorf("underAnyDir(%q) = %v, want %v", c.path, got, c.want)
		}
	}
	if underAnyDir([]string{""}, `C:\anything`) {
		t.Error("an empty root must not match everything")
	}
}

// A resize the caller cannot have meant used to be clamped into range and
// applied: a viewer measuring a hidden container sent 0x0 and the operator's
// console collapsed to 10x2 with no error anywhere. Linux refuses such a
// frame and keeps the current size; so does Windows now.
func TestValidPTYSizeRejectsSizesNoViewerMeant(t *testing.T) {
	for _, c := range []struct {
		cols, rows int
		ok         bool
	}{
		{120, 30, true},
		{1, 1, true},
		{maxPTYAxis, maxPTYAxis, true},
		{0, 0, false},
		{80, 0, false},
		{0, 24, false},
		{-1, 24, false},
		{80, -5, false},
		{maxPTYAxis + 1, 24, false}, // the console host allocates this for real
		{2000, 4000, false},
		{80, 1 << 20, false},
	} {
		err := validPTYSize(c.cols, c.rows)
		if c.ok && err != nil {
			t.Errorf("validPTYSize(%d,%d) = %v, want accepted", c.cols, c.rows, err)
		}
		if !c.ok && err == nil {
			t.Errorf("validPTYSize(%d,%d) accepted an impossible size", c.cols, c.rows)
		}
	}
}

// The clamp survives, but only where it is safe: the size the session is
// created with, which no viewer can turn into a live console that is already
// working.
func TestClampPTYSizeOnlyGuardsTheInitialSize(t *testing.T) {
	if c, r := clampPTYSize(0, 0); c < 10 || r < 2 {
		t.Errorf("clampPTYSize(0,0) = %dx%d, want a usable floor", c, r)
	}
	if c, r := clampPTYSize(120, 30); c != 120 || r != 30 {
		t.Errorf("clampPTYSize(120,30) = %dx%d, want it untouched", c, r)
	}
	if c, r := clampPTYSize(9999, 9999); c > 1000 || r > 1000 {
		t.Errorf("clampPTYSize(9999,9999) = %dx%d, want it capped", c, r)
	}
}

// A Windows service environment has no TERM at all, so cross-platform tools
// inside a real console fell back to their non-TTY behaviour. Linux pins
// these; Windows now does too.
func TestWithTerminalEnvDeclaresATerminal(t *testing.T) {
	env := withTerminalEnv([]string{`Path=C:\Windows`, "Term=dumb", "USERNAME=SYSTEM"})
	got := map[string]string{}
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok {
			got[strings.ToUpper(k)] = v
		}
	}
	if got["TERM"] != "xterm-256color" {
		t.Errorf("TERM = %q, want xterm-256color", got["TERM"])
	}
	if got["COLORTERM"] != "truecolor" {
		t.Errorf("COLORTERM = %q, want truecolor", got["COLORTERM"])
	}
	if got["PATH"] != `C:\Windows` || got["USERNAME"] != "SYSTEM" {
		t.Errorf("the service environment was not carried through: %v", got)
	}
	// Windows variable names are case-insensitive: "Term=dumb" must have been
	// replaced, not shadowed by a second entry.
	terms := 0
	for _, e := range env {
		if k, _, _ := strings.Cut(e, "="); strings.EqualFold(k, "TERM") {
			terms++
		}
	}
	if terms != 1 {
		t.Errorf("TERM appears %d times; a duplicate entry is undefined for CreateProcess", terms)
	}
	// Entries Windows itself puts in the block ("=C:=C:\dir") survive.
	if len(withTerminalEnv([]string{`=C:=C:\dir`})) != 3 {
		t.Error("a drive-current-directory entry was dropped")
	}
}

// writeFakeExe drops a file where a binary would be. It is never executed -
// only resolved - so its contents do not matter.
func writeFakeExe(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("not a real binary"), 0o644); err != nil {
		t.Fatal(err)
	}
}
