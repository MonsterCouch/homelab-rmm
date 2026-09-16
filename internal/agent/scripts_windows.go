//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// The Windows half of the script runner: how the interpreter's output is
// decoded, which binary each language resolves to, and how a .cmd run's
// command line is quoted.

// scriptDecodeOutput turns one captured output line into a string. Windows
// PowerShell 5.1, cmd.exe and the console tools keep writing the OEM code
// page when their stdout is a pipe rather than a console, so output that is
// not already valid UTF-8 (pwsh 7's is, and so is python's with
// PYTHONIOENCODING set) is decoded the way every other helper's output is.
func scriptDecodeOutput(b []byte) string { return winDecodeOutput(b, cpOEM) }

// powershellScriptExe resolves the PowerShell that runs a script body: pwsh 7
// where it is installed, Windows PowerShell 5.1 - part of the OS, always
// present - otherwise. Both are absolute paths, for the reason systemExe
// gives in exec_windows.go: the agent runs as SYSTEM, so a writable directory
// on the machine PATH must not get to decide what a script run executes.
func powershellScriptExe() (string, error) {
	if p, ok := pwshInstallPath(); ok {
		return p, nil
	}
	return windowsPowerShellPath(), nil
}

// pwshInstallPath looks for PowerShell 7 where its installer puts it, newest
// major version first. PATH is deliberately not consulted, and neither are
// the preview channels: an operator's script should not silently move to a
// preview build because one happens to be installed.
func pwshInstallPath() (string, bool) {
	var best string
	var bestMajor int
	seen := map[string]bool{}
	for _, base := range []string{os.Getenv("ProgramW6432"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
		if base == "" {
			continue
		}
		root := filepath.Join(base, "PowerShell")
		if seen[root] {
			continue
		}
		seen[root] = true
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			major, err := strconv.Atoi(e.Name())
			if err != nil || major < 6 || major <= bestMajor {
				continue
			}
			p := filepath.Join(root, e.Name(), "pwsh.exe")
			if st, err := os.Stat(p); err != nil || st.IsDir() {
				continue
			}
			best, bestMajor = p, major
		}
	}
	return best, best != ""
}

// windowsPowerShellPath is the absolute path of Windows PowerShell 5.1.
func windowsPowerShellPath() string {
	return filepath.Join(systemRoot(), `System32\WindowsPowerShell\v1.0\powershell.exe`)
}

func systemRoot() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return root
	}
	return `C:\Windows`
}

// pythonScriptExe finds a Python for a script run. The agent is a SYSTEM
// service, so it inherits the *machine* PATH only, while both the python.org
// installer and the Store default to a per-user install that never appears
// there: PATH alone reports "not installed" on a device where python runs
// perfectly well in the operator's own session. The py.exe launcher (which
// installs for all users into %SystemRoot%) and the PythonCore registry keys
// are how Windows records an install, so they are asked first and PATH is the
// last resort. The other users' hives under HKEY_USERS are deliberately not
// read: their install directories are writable by the account that owns them,
// so running one as SYSTEM would hand any standard user the service account.
func pythonScriptExe() (string, error) {
	if p := systemRootFile("py.exe"); p != "" {
		return p, nil
	}
	if p, ok := registryPython(); ok {
		return p, nil
	}
	for _, name := range []string{"python3", "python", "py"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no python found on this device: the agent runs as LocalSystem, so a per-user Python install is invisible to it - install Python for all users (or its py.exe launcher), or put it on the machine PATH")
}

// systemRootFile returns %SystemRoot%\name when it is there.
func systemRootFile(name string) string {
	p := filepath.Join(systemRoot(), name)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}

// registryPython reads the PythonCore install keys, newest version first.
// Both hives are asked - HKLM is an all-users install, HKCU the hive of the
// account the agent runs under - and both registry views, because a 32-bit
// Python registers under WOW6432Node.
func registryPython() (string, bool) {
	var best, bestKey string
	for _, root := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
		for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
			access := registry.READ | view
			k, err := registry.OpenKey(root, `SOFTWARE\Python\PythonCore`, access)
			if err != nil {
				continue
			}
			versions, err := k.ReadSubKeyNames(-1)
			k.Close()
			if err != nil {
				continue
			}
			for _, v := range versions {
				p := pythonInstallPath(root, access, v)
				if p == "" || (best != "" && !pythonKeyNewer(v, bestKey)) {
					continue
				}
				best, bestKey = p, v
			}
		}
	}
	return best, best != ""
}

// pythonInstallPath reads one PythonCore version's InstallPath key: modern
// installers record the interpreter in ExecutablePath, older ones only the
// directory in the key's default value.
func pythonInstallPath(root registry.Key, access uint32, version string) string {
	k, err := registry.OpenKey(root, `SOFTWARE\Python\PythonCore\`+version+`\InstallPath`, access)
	if err != nil {
		return ""
	}
	defer k.Close()
	if exe, _, err := k.GetStringValue("ExecutablePath"); err == nil && isFile(exe) {
		return exe
	}
	dir, _, err := k.GetStringValue("")
	if err != nil {
		return ""
	}
	if exe := filepath.Join(dir, "python.exe"); isFile(exe) {
		return exe
	}
	return ""
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// cmdScriptCommand builds the cmd.exe invocation for a .cmd body with its own
// command line, because exec's quoting is the wrong dialect for cmd.exe - see
// the cmdQuote comments in scripts.go. Values cmd would re-parse whatever the
// quoting are refused here rather than smuggled through.
func cmdScriptCommand(ctx context.Context, file string, args []string) (*exec.Cmd, error) {
	for i, a := range args {
		if bad, unsafe := cmdUnsafeArg(a); unsafe {
			return nil, fmt.Errorf("cmd script argument %d contains %q, which cmd.exe re-parses instead of passing to the script: use a powershell script for values like this", i+1, string(bad))
		}
	}
	exe := systemExe("cmd.exe")
	cmd := exec.CommandContext(ctx, exe, append([]string{"/d", "/c", file}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: cmdScriptLine(exe, file, args)}
	return cmd, nil
}
