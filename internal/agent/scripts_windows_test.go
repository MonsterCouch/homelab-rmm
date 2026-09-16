//go:build windows

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestScriptInterpretersAreAbsolute: the script runner is the one child of
// the agent an operator aims deliberately, and it runs as SYSTEM. Resolving
// its interpreter by bare name let any writable directory on the machine PATH
// decide which binary that is - the thing systemExe exists to prevent.
func TestScriptInterpretersAreAbsolute(t *testing.T) {
	ps, err := powershellScriptExe()
	if err != nil {
		t.Fatalf("Windows PowerShell is part of the OS: %v", err)
	}
	if !filepath.IsAbs(ps) {
		t.Fatalf("powershell resolved to %q, which PATH still gets to interpret", ps)
	}
	if st, err := os.Stat(ps); err != nil || st.IsDir() {
		t.Fatalf("powershell resolved to %q, which is not an executable: %v", ps, err)
	}
	if _, ok := pwshInstallPath(); !ok {
		// No pwsh 7 here, so the 5.1 fallback must be the System32 copy.
		want := windowsPowerShellPath()
		if !strings.EqualFold(ps, want) {
			t.Fatalf("powershell = %q, want %q", ps, want)
		}
	}
	cmd, err := cmdScriptCommand(context.Background(), `C:\tmp\script.cmd`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(cmd.Path, filepath.Join(systemRoot(), `System32\cmd.exe`)) {
		t.Fatalf("cmd.exe resolved to %q, not the System32 copy", cmd.Path)
	}
	if p, err := pythonScriptExe(); err == nil {
		if !filepath.IsAbs(p) {
			t.Fatalf("python resolved to %q, which PATH still gets to interpret", p)
		}
	} else if !strings.Contains(err.Error(), "LocalSystem") {
		// A device with no Python must say why the one the operator can see
		// in their own session is invisible to the service.
		t.Fatalf("the error must explain the LocalSystem PATH: %v", err)
	}
}

// TestScriptDecodeOutputKeepsNonUTF8Text: a Windows interpreter answers in
// the console code page when its stdout is a pipe, and reading that as UTF-8
// turned every accented character in an event-log message, a path or a user
// name into U+FFFD, with no way to get the real value back.
func TestScriptDecodeOutputKeepsNonUTF8Text(t *testing.T) {
	if got := scriptDecodeOutput([]byte("héllo ✓")); got != "héllo ✓" {
		t.Fatalf("valid UTF-8 (pwsh 7, python) must pass through untouched: %q", got)
	}
	// 0x82 is an accented letter in every OEM code page and is not valid
	// UTF-8; what it is exactly depends on the device, but it is text.
	got := scriptDecodeOutput([]byte{'h', 0x82, 'l', 'l', 'o'})
	if !utf8.ValidString(got) {
		t.Fatalf("decoded output must be valid UTF-8 for the JSON reply: %q", got)
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Fatalf("a code-page byte must be decoded, not replaced: %q", got)
	}
	if len([]rune(got)) != 5 {
		t.Fatalf("decode changed the text length: %q", got)
	}
}

// TestCmdScriptCommandRefusesReparsedArguments: exec quotes with
// CommandLineToArgvW rules that cmd.exe does not implement, so a parameter
// holding a quote used to end the quoted region and run the rest as a second
// command as SYSTEM - invisible in script_runs.args and in the audit entry.
func TestCmdScriptCommandRefusesReparsedArguments(t *testing.T) {
	inject := `a" & echo WINVAL-INJECTED-MARKER & rem "b`
	if _, err := cmdScriptCommand(context.Background(), `C:\tmp\script.cmd`, []string{inject}); err == nil {
		t.Fatal("an argument cmd.exe would re-parse must be refused, not smuggled through")
	}
	cmd, err := cmdScriptCommand(context.Background(), `C:\tmp\script.cmd`, []string{"a & echo MARKER"})
	if err != nil {
		t.Fatal(err)
	}
	line := cmd.SysProcAttr.CmdLine
	if line == "" {
		t.Fatal("a .cmd run must carry its own command line, or exec quotes it for the wrong parser")
	}
	if !strings.HasSuffix(line, ` "a & echo MARKER"`) {
		t.Fatalf("the argument must reach the script as one quoted value: %q", line)
	}
}
