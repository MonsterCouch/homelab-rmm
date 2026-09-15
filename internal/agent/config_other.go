//go:build !windows

package agent

import "os"

// secureDir is the non-Windows half of the hook implemented for real in
// config_windows.go: here the mode passed to MkdirAll already does the job,
// and a chmod fixes a directory that predates it (or was created with a
// looser umask by hand).
func secureDir(path string) error { return os.Chmod(path, 0o700) }
