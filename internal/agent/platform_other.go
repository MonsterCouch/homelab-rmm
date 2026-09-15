//go:build !windows && !linux

package agent

// This file is the CONTRACT for platform code. Each function below has a
// real implementation in <name>_windows.go and <name>_linux.go; this file
// only lets the package compile on other platforms (with reduced features).

import (
	"context"
	"errors"
	"os/exec"

	"github.com/shirou/gopsutil/v4/host"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

var errUnsupported = errors.New("not supported on this platform")

// platformLabel turns gopsutil host info into a friendly OS label such as
// "Windows 11 Pro 23H2" or "Ubuntu 24.04.1 LTS".
func platformLabel(hi *host.InfoStat) string { return hi.Platform + " " + hi.PlatformVersion }

// platformInventory fills the fields gopsutil cannot: Manufacturer, Model,
// Serial, BIOSVersion, Domain, Software (installed programs), GPUs,
// AntivirusName, LastUser, plus anything else worth showing in inv.Extra.
func platformInventory(inv *protocol.Inventory) {}

// loggedInUsers lists interactive users currently signed in.
func loggedInUsers() []string { return nil }

// pendingReboot reports whether the OS wants a restart (Windows: registry
// keys under Component Based Servicing / Windows Update / PendingFileRename;
// Linux: /var/run/reboot-required or needs-restarting).
func pendingReboot() bool { return false }

// listServices returns every service with state and start type.
func listServices() ([]protocol.Service, error) { return nil, errUnsupported }

// serviceAction performs start|stop|restart|enable|disable|manual and returns
// the service's state afterwards.
func serviceAction(name, action string) (*protocol.Service, error) { return nil, errUnsupported }

// serviceState returns "running", "stopped", "unknown" ... for a service name.
func serviceState(name string) string { return "unknown" }

// queryEventLog reads the Windows event log (System/Application/Security/...)
// or journald on Linux, newest first, honouring Level, Limit, Search, SinceTS.
func queryEventLog(q protocol.EventLogQuery) ([]protocol.EventLogEntry, error) {
	return nil, errUnsupported
}

// scanUpdates lists available OS updates (Windows Update Agent via
// PowerShell COM on Windows; apt/dnf/pacman/zypper on Linux).
func scanUpdates(ctx context.Context) (*protocol.UpdatesScanResult, error) {
	return nil, errUnsupported
}

// installUpdates installs the requested ids (empty = all available) and
// reports per-id outcomes; progress receives human-readable log lines.
func installUpdates(ctx context.Context, req protocol.UpdatesInstall, progress func(string)) (*protocol.UpdatesInstallResult, error) {
	return nil, errUnsupported
}

// powerAction performs reboot|shutdown|lock|logoff after Delay seconds,
// showing Message to logged-in users where the OS supports it.
func powerAction(p protocol.Power) error { return errUnsupported }

// startPTY launches an interactive shell ("" = platform default:
// powershell on Windows, the user's shell or bash on Linux) in a
// pseudo-terminal of the given size.
func startPTY(shell string, cols, rows int) (ptySession, error) { return nil, errUnsupported }

// prepareCommand applies platform process attributes to a script command:
// hide the console window on Windows; put the child in its own process
// group on Linux so a timeout kills the whole tree.
func prepareCommand(cmd *exec.Cmd) {}
