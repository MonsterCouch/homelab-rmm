//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// The PowerShell driving the Windows Update Agent lives in wuascript.go
// (constraint-free, so its shape is tested on the Linux build box).

// scanUpdates lists applicable Windows updates and, when winget is reachable,
// appends any per-user application upgrades it finds. A COM search failure is
// carried in the result's Error field, not returned as a Go error, so the
// operator still sees the reboot-pending flag and the HRESULT.
func scanUpdates(ctx context.Context) (*protocol.UpdatesScanResult, error) {
	// A WUA search over the network can take minutes on its first run; give
	// it a generous ceiling but always less than the wire request's own.
	scanCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
	}
	stdout, _, runErr := runPowerShellScript(scanCtx, wuaScanScript)
	_, other, result := winSplitWUAOutput(stdout)
	res, parseErr := winParseWUAScan(result)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("windows update scan: %w", runErr)
		}
		return nil, parseErr
	}
	if len(other) > 0 && res.Error == "" {
		res.Error = winFirstLine(strings.Join(other, "\n"))
	}
	res.LastScan = time.Now().Unix()
	// The COM flag and the registry markers can disagree (the COM flag lags
	// a servicing operation); report pending if either says so.
	if pendingReboot() {
		res.RebootPending = true
	}
	if wu := scanWinget(scanCtx); len(wu) > 0 {
		res.Updates = append(res.Updates, wu...)
	}
	return res, nil
}

// installUpdates downloads and installs the requested updates (empty list =
// all applicable), streaming progress lines through progress. req.Reboot
// schedules a restart when the install reports one is required.
func installUpdates(ctx context.Context, req protocol.UpdatesInstall, progress func(string)) (*protocol.UpdatesInstallResult, error) {
	var args []string
	for _, id := range req.IDs {
		id = strings.TrimSpace(strings.TrimPrefix(id, "wua:"))
		if strings.HasPrefix(id, "winget:") {
			// winget upgrades are reported as extras but installing them
			// from the SYSTEM account is unreliable; refuse rather than
			// pretend. The scan labels them clearly.
			return nil, errors.New("winget upgrades cannot be installed from the agent service account")
		}
		if !winIsUpdateID(id) {
			return nil, fmt.Errorf("invalid update id %q", id)
		}
		args = append(args, id)
	}
	// The request's context dies with the WebSocket it arrived on. Killing
	// PowerShell in the middle of $installer.Install() because the socket
	// blipped would leave a half-applied cumulative update, so the install
	// keeps the caller's deadline but not its cancellation; a lost socket
	// only loses the reply, and the scan after reconnecting shows the truth.
	installCtx, cancel := detachedDeadline(ctx, 2*time.Hour)
	defer cancel()
	stdout, _, runErr := runPowerShellScriptLines(installCtx, wuaInstallScript, func(line string) {
		if p, ok := strings.CutPrefix(line, "PROGRESS "); ok && progress != nil {
			progress(strings.TrimSpace(p))
		}
	}, args...)
	_, other, result := winSplitWUAOutput(stdout)
	res, parseErr := winParseWUAInstall(result)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("windows update install: %w", runErr)
		}
		return nil, parseErr
	}
	winMarkUnreported(res, args)
	if len(other) > 0 {
		if res.Log != "" {
			res.Log += "\n"
		}
		res.Log += strings.Join(other, "\n")
	}
	if req.Reboot && res.RebootReq {
		if err := scheduleReboot(60, "Homelab RMM: applying Windows updates"); err != nil {
			progress("could not schedule reboot: " + err.Error())
		} else {
			progress("reboot scheduled in 60 seconds")
		}
	}
	return res, nil
}

// detachedDeadline returns a context that inherits ctx's deadline (or gets
// fallback when it has none) and its values, but not its cancellation.
func detachedDeadline(ctx context.Context, fallback time.Duration) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(ctx)
	if d, ok := ctx.Deadline(); ok {
		return context.WithDeadline(base, d)
	}
	return context.WithTimeout(base, fallback)
}

// scheduleReboot asks shutdown.exe for a restart after delaySec seconds.
func scheduleReboot(delaySec int, message string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return runShutdown(ctx, winShutdownArgs("reboot", delaySec, message))
}

// runPowerShellScript writes body to a temp .ps1 and runs it hidden. A
// script file avoids the escaping pitfalls of -Command and keeps the COM
// code readable.
func runPowerShellScript(ctx context.Context, body string, args ...string) (stdout, stderr string, err error) {
	return runPowerShellScriptLines(ctx, body, nil, args...)
}

// runPowerShellScriptLines is runPowerShellScript for a long install: every
// stdout line is handed to onLine as it appears (so PROGRESS lines reach
// the operator live) and the full stdout is also returned for the RESULT
// parse.
func runPowerShellScriptLines(ctx context.Context, body string, onLine func(string), args ...string) (stdout, stderr string, err error) {
	path, cleanup, err := writeTempScript(body)
	if err != nil {
		return "", "", err
	}
	defer cleanup()
	return runHiddenLines(ctx, onLine, powershellPath(), powershellArgs(path, args)...)
}

// writeTempScript writes a UTF-8-BOM .ps1 (so Windows PowerShell reads
// non-ASCII correctly) with an owner-only mode and returns a cleanup.
func writeTempScript(body string) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "rmm-wua-")
	if err != nil {
		return "", func() {}, err
	}
	path = filepath.Join(dir, "wua.ps1")
	content := append([]byte{0xEF, 0xBB, 0xBF}, []byte(body)...)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		os.RemoveAll(dir)
		return "", func() {}, err
	}
	return path, func() { os.RemoveAll(dir) }, nil
}

// powershellPath prefers pwsh 7 and falls back to Windows PowerShell, which
// is always present. Callers pass this through systemExe.
func powershellPath() string {
	if p, err := exec.LookPath("pwsh.exe"); err == nil {
		return p
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, `System32\WindowsPowerShell\v1.0\powershell.exe`)
}

func powershellArgs(script string, args []string) []string {
	return append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}, args...)
}

// scanWinget appends winget upgrades as extra items. winget resolved from
// the SYSTEM account is the exception, not the rule (its App Installer
// package registers per-user), so an absent or failing winget is silent:
// the return is simply empty.
func scanWinget(ctx context.Context) []protocol.Update {
	exe, err := resolveWinget()
	if err != nil {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	// --include-unknown lists apps whose installed version winget cannot
	// read; --accept-source-agreements avoids a first-run prompt that would
	// otherwise hang a non-interactive run.
	stdout, _, err := runHidden(wctx, exe, "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity")
	if err != nil && strings.TrimSpace(stdout) == "" {
		return nil
	}
	return winParseWingetUpgrade(stdout)
}

// resolveWinget finds winget.exe. It is usually not on the SYSTEM PATH; the
// per-machine WindowsApps alias is checked directly before giving up.
func resolveWinget() (string, error) {
	if p, err := exec.LookPath("winget.exe"); err == nil {
		return p, nil
	}
	for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramW6432")} {
		if base == "" {
			continue
		}
		if matches, _ := filepath.Glob(filepath.Join(base, "WindowsApps", "Microsoft.DesktopAppInstaller_*", "winget.exe")); len(matches) > 0 {
			return matches[len(matches)-1], nil
		}
	}
	return "", errNotFoundWinget
}

var errNotFoundWinget = errors.New("winget is not available to the agent service account")
