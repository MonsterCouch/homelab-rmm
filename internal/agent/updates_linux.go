//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// The first package manager found wins. apt-get before dnf so a Debian box
// with a stray dnf package still uses apt; dnf before yum because on RHEL 8+
// yum is a symlink to dnf.
var pmCandidates = []string{"apt-get", "dnf", "yum", "pacman", "zypper"}

// packageManager is detected once; it does not change while we run.
var packageManager = sync.OnceValue(func() string {
	for _, c := range pmCandidates {
		if hasCmd(c) {
			if c == "apt-get" {
				return "apt"
			}
			return c
		}
	}
	return ""
})

var errNoPackageManager = errors.New("no supported package manager found (apt-get, dnf, yum, pacman, zypper)")

// installTimeout bounds one package-manager transaction. A full
// dist-upgrade on a slow disk with a big kernel set is tens of minutes; two
// hours means "wedged", not "slow".
const installTimeout = 2 * time.Hour

// aptDpkgOpts keep dpkg from ever prompting about conffiles: keep the local
// one, or the default when there is no local change.
var aptDpkgOpts = []string{"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}

var aptEnv = []string{"DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", "UCF_FORCE_CONFFOLD=1", "NEEDRESTART_SUSPEND=1"}

// scanUpdates refreshes the package index (a failure there is reported, not
// fatal: the cached index still lists something) and returns what would be
// upgraded.
func scanUpdates(ctx context.Context) (*protocol.UpdatesScanResult, error) {
	res := &protocol.UpdatesScanResult{Updates: []protocol.Update{}, LastScan: time.Now().Unix()}
	pm := packageManager()
	if pm == "" {
		res.Error = errNoPackageManager.Error()
		return res, nil
	}
	if err := pmRefresh(ctx, pm); err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		res.Error = err.Error()
	}
	updates, err := pmList(ctx, pm)
	if err != nil {
		return nil, err
	}
	sort.Slice(updates, func(i, j int) bool { return updates[i].ID < updates[j].ID })
	res.Updates = updates
	res.RebootPending = pendingReboot()
	return res, nil
}

// pmRefresh updates the package index. dnf/yum refresh their metadata on
// check-update by themselves.
func pmRefresh(ctx context.Context, pm string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	var (
		stderr string
		err    error
	)
	switch pm {
	case "apt":
		_, stderr, _, err = runCmdEnv(ctx, aptEnv, "apt-get", "update", "-q")
	case "pacman":
		_, stderr, _, err = runCmd(ctx, "pacman", "-Sy", "--noconfirm")
	case "zypper":
		_, stderr, _, err = runCmd(ctx, "zypper", "-n", "refresh")
	default:
		return nil
	}
	if err != nil {
		return fmt.Errorf("refreshing the package index failed: %s", orFirst(strings.TrimSpace(lastLines(stderr, 5)), err.Error()))
	}
	return nil
}

// pmList returns the upgradable packages from the current index.
func pmList(ctx context.Context, pm string) ([]protocol.Update, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	switch pm {
	case "apt":
		out, stderr, _, err := runCmdEnv(ctx, aptEnv, "apt-get", "-s", "-q", "-o", "Debug::NoLocking=true", "dist-upgrade")
		if err == nil {
			return parseAptSimulate(out), nil
		}
		// Broken dependencies make the simulation exit 100; "apt list" still
		// knows which packages have a newer candidate.
		out2, stderr2, _, err2 := runCmdEnv(ctx, aptEnv, "apt", "list", "--upgradable")
		if err2 != nil {
			return nil, fmt.Errorf("apt-get -s dist-upgrade: %s; apt list: %s", orFirst(firstLine(stderr), err.Error()), orFirst(firstLine(stderr2), err2.Error()))
		}
		return parseAptListUpgradable(out2), nil
	case "dnf", "yum":
		out, stderr, code, err := runCmd(ctx, pm, "-q", "check-update")
		switch code {
		case 0:
			return nil, nil
		case 100:
		default:
			return nil, fmt.Errorf("%s check-update: %s", pm, orFirst(firstLine(stderr), errString(err)))
		}
		updates := parseDnfCheckUpdate(out)
		if sec, _, _, err := runCmd(ctx, pm, "-q", "updateinfo", "list", "--security"); err == nil {
			mark := parseDnfSecurity(sec)
			for i := range updates {
				name, _ := rpmSplitArch(updates[i].ID)
				sev, ok := mark[updates[i].ID]
				if !ok {
					sev, ok = mark[name]
				}
				if ok {
					updates[i].Severity, updates[i].Categories = sev, []string{"Security"}
				}
			}
		}
		for i := range updates {
			updates[i].Source = pm
		}
		return updates, nil
	case "pacman":
		out, stderr, code, err := runCmd(ctx, "pacman", "-Qu")
		if code == 1 && strings.TrimSpace(out) == "" {
			return nil, nil // pacman's "nothing to do"
		}
		if err != nil && code != 1 {
			return nil, fmt.Errorf("pacman -Qu: %s", orFirst(firstLine(stderr), err.Error()))
		}
		return parsePacmanQu(out), nil
	case "zypper":
		out, stderr, code, err := runCmd(ctx, "zypper", "-n", "lu")
		if err != nil && !zypperOK(code) {
			return nil, fmt.Errorf("zypper lu: %s", orFirst(firstLine(stderr), err.Error()))
		}
		return parseZypperLu(out), nil
	}
	return nil, errNoPackageManager
}

// zypperOK: exit codes 100-107 are informational (updates available, reboot
// needed, ...), not failures.
func zypperOK(code int) bool { return code == 0 || (code >= 100 && code <= 107) }

// installUpdates installs the requested package ids, or everything, and
// works out what actually changed by re-listing afterwards: a package that
// is no longer upgradable was installed, whatever the tool's exit code.
func installUpdates(ctx context.Context, req protocol.UpdatesInstall, progress func(string)) (*protocol.UpdatesInstallResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	// Once the caller's context is gone the connection has dropped and nobody
	// is listening: skip the per-line events rather than pay a write timeout
	// on each of them while the install runs on (see pmInstall).
	emit := progress
	progress = func(line string) {
		if ctx.Err() == nil {
			emit(line)
		}
	}
	res := &protocol.UpdatesInstallResult{Installed: []string{}, Failed: map[string]string{}}
	pm := packageManager()
	if pm == "" {
		return nil, errNoPackageManager
	}
	progress("Refreshing package index (" + pm + ")")
	if err := pmRefresh(ctx, pm); err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		progress("warning: " + err.Error())
	}
	before, err := pmList(ctx, pm)
	if err != nil {
		return nil, fmt.Errorf("listing updates before install: %w", err)
	}
	available := map[string]bool{}
	for _, u := range before {
		available[u.ID] = true
	}
	// Only ids the package manager itself just reported reach its command
	// line, so nothing the server sends can turn into an option or a
	// "remove" request.
	var targets []string
	if len(req.IDs) == 0 {
		for _, u := range before {
			targets = append(targets, u.ID)
		}
	} else {
		for _, id := range req.IDs {
			id = strings.TrimSpace(id)
			switch {
			case !validPkgID(id):
				res.Failed[id] = "invalid package id"
			case !available[id]:
				res.Failed[id] = "not an available update"
			default:
				targets = append(targets, id)
			}
		}
	}
	targets = uniqNonEmpty(targets)
	if len(targets) == 0 {
		progress("Nothing to install")
		res.Log = "nothing to install\n"
		res.RebootReq = pendingRebootFresh()
		return res, nil
	}
	progress(fmt.Sprintf("Installing %d package(s) with %s", len(targets), pm))
	log, code, cmdErr := pmInstall(ctx, pm, len(req.IDs) == 0, targets, progress)
	res.Log = log
	if errors.Is(cmdErr, context.DeadlineExceeded) {
		for _, id := range targets {
			res.Failed[id] = fmt.Sprintf("install still running after %s; killed", installTimeout)
		}
		res.RebootReq = pendingRebootFresh()
		return res, nil
	}
	if cmdErr != nil && errors.Is(cmdErr, errNotFound) {
		return nil, cmdErr
	}
	// The connection may have dropped mid-install; the re-scan still runs
	// so the outcome is right for whoever reads the log afterwards.
	after, aerr := pmList(context.WithoutCancel(ctx), pm)
	still := map[string]bool{}
	for _, u := range after {
		still[u.ID] = true
	}
	failText := ""
	if cmdErr != nil {
		failText = fmt.Sprintf("%s (exit %d): %s", cmdErr.Error(), code, lastLines(log, 3))
	}
	for _, id := range targets {
		switch {
		case aerr != nil && cmdErr == nil:
			// Cannot verify, but the tool said it worked.
			res.Installed = append(res.Installed, id)
		case aerr != nil:
			res.Failed[id] = failText
		case still[id]:
			if failText == "" {
				failText = "still reported as upgradable after install"
			}
			res.Failed[id] = failText
		default:
			res.Installed = append(res.Installed, id)
		}
	}
	res.RebootReq = pendingRebootFresh()
	progress(fmt.Sprintf("Done: %d installed, %d failed, reboot required: %v", len(res.Installed), len(res.Failed), res.RebootReq))
	if req.Reboot && res.RebootReq && len(res.Installed) > 0 {
		progress("Reboot requested and required: rebooting in 60 seconds")
		if err := powerAction(protocol.Power{Action: "reboot", Delay: 60, Message: "Rebooting to complete update installation (RMM)"}); err != nil {
			progress("reboot failed: " + err.Error())
		}
	}
	return res, nil
}

// pmInstall runs the actual upgrade, streaming its output.
//
// It is deliberately detached from the caller's cancellation. The only
// thing that cancels a request context is the agent's connection dropping,
// and prepareCommand answers cancellation with SIGKILL to the whole process
// group: doing that to dpkg or rpm mid-transaction leaves the package
// database half-configured ("dpkg was interrupted, you must manually run
// 'dpkg --configure -a'") and every later scan broken. The transaction runs
// to completion under its own deadline instead; at worst the reply is lost
// with the socket, which is recoverable.
func pmInstall(ctx context.Context, pm string, all bool, ids []string, progress func(string)) (log string, code int, err error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), installTimeout)
	defer cancel()
	switch pm {
	case "apt":
		args := append([]string{"-y", "-q"}, aptDpkgOpts...)
		if all {
			args = append(args, "dist-upgrade")
		} else {
			args = append(append(args, "install", "--only-upgrade", "--"), ids...)
		}
		return streamCmd(ctx, aptEnv, progress, "apt-get", args...)
	case "dnf", "yum":
		args := []string{"-y", "upgrade"}
		if !all {
			args = append(append(args, "--"), ids...)
		}
		return streamCmd(ctx, nil, progress, pm, args...)
	case "pacman":
		if all {
			return streamCmd(ctx, nil, progress, "pacman", "-Syu", "--noconfirm")
		}
		return streamCmd(ctx, nil, progress, "pacman", append([]string{"-S", "--noconfirm", "--needed", "--"}, ids...)...)
	case "zypper":
		args := []string{"-n", "--non-interactive-include-reboot-patches", "up", "--auto-agree-with-licenses"}
		if !all {
			args = append(append(args, "--"), ids...)
		}
		log, code, err = streamCmd(ctx, nil, progress, "zypper", args...)
		if err != nil && zypperOK(code) {
			err = nil
		}
		return log, code, err
	}
	return "", -1, errNoPackageManager
}

// pendingRebootFresh bypasses the reboot cache right after an install,
// when the answer has most likely just changed.
func pendingRebootFresh() bool {
	rebootCache.Lock()
	rebootCache.at = time.Time{}
	rebootCache.Unlock()
	return pendingReboot()
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
