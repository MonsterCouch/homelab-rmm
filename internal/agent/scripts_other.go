//go:build !windows

package agent

import (
	"context"
	"errors"
	"os/exec"
)

// The non-Windows half of the script runner. PATH is the right answer here:
// the agent runs as root, PATH is root's own rather than a machine-wide value
// a normal user can extend, and the interpreters have no fixed location.

// scriptDecodeOutput turns one captured output line into a string. Everything
// on this side speaks UTF-8; only Windows needs a code page.
func scriptDecodeOutput(b []byte) string { return string(b) }

// powershellScriptExe resolves PowerShell 7, the only PowerShell there is off
// Windows.
func powershellScriptExe() (string, error) {
	p, err := exec.LookPath("pwsh")
	if err != nil {
		return "", errors.New("pwsh is not installed on this device")
	}
	return p, nil
}

// pythonScriptExe resolves the interpreter for a python script.
func pythonScriptExe() (string, error) {
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", errors.New("python is not installed on this device")
}

// cmdScriptCommand exists so scripts.go stays platform-free; scriptCommand
// has already refused the language before it can be reached.
func cmdScriptCommand(context.Context, string, []string) (*exec.Cmd, error) {
	return nil, errors.New("cmd scripts only run on Windows")
}

// withScriptEnv is a no-op on non-Windows platforms.
func withScriptEnv(env []string) []string { return env }
