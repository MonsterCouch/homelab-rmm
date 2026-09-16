//go:build !windows

package svc

import (
	"os"
	"syscall"
)

// setErrorControl is Windows' business: SERVICE_ERROR_NORMAL has no systemd
// equivalent, and a unit that fails to start is journalled either way.
func setErrorControl(string) error { return nil }

// recommendedImageDir is the location docs/OPERATIONS.md gives for the agent.
func recommendedImageDir() string { return "/opt/homelab-rmm" }

// unprotectedWriters reads the owner and mode of a directory or a file; the
// decision is in unixWriters so it can be tested from any platform.
func unprotectedWriters(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil // an exotic filesystem: nothing to say about it
	}
	return unixWriters(fi.Mode(), int(st.Uid)), nil
}
