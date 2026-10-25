//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/cache"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Windows servicing repair (docs/plans/2026-10-24-phase4c-servicing-repair.md).
//
// The steps are the ones a technician runs by hand when Windows Update fails
// because the component store or the update catalog is damaged. Every command
// is started hidden by absolute path under %SystemRoot%\System32 (the agent
// runs as SYSTEM, so nothing may be found through PATH), and the whole run
// holds pkgOpMutex because DISM and WUA refuse to run beside each other.

// servicingDefaultSteps is what an automatic repair runs: it needs no package
// and no download, and it ends with the scan that shows whether it worked.
var servicingDefaultSteps = []string{protocol.ServicingDismRestore, protocol.ServicingResetComponents, protocol.ServicingRescan}

// servicingStepOrder is the canonical order; a request may name any subset but
// the steps always run in this order, because resetting the catalog before the
// component store is repaired would be undone by the next failure, and a
// rescan before the rest would report nothing useful.
var servicingStepOrder = []string{
	protocol.ServicingDismRestore, protocol.ServicingSFC, protocol.ServicingResetComponents,
	protocol.ServicingAddPackage, protocol.ServicingRescan,
}

// servicingServices are stopped around the catalog reset, in stop order; they
// are started again in reverse.
var servicingServices = []string{"wuauserv", "bits", "cryptsvc", "msiserver"}

// servicingDirs are the two catalog directories the reset renames (relative to
// %SystemRoot%). Nothing else is ever renamed or deleted.
var servicingDirs = []string{"SoftwareDistribution", filepath.Join("System32", "catroot2")}

// Step timeouts.
const (
	servicingDismTimeout    = 60 * time.Minute
	servicingSFCTimeout     = 30 * time.Minute
	servicingResetTimeout   = 10 * time.Minute
	servicingPackageTimeout = 60 * time.Minute
	servicingFetchTimeout   = 30 * time.Minute
	servicingScanTimeout    = 15 * time.Minute

	// dismRebootExit is ERROR_SUCCESS_REBOOT_REQUIRED, which DISM returns on
	// success when the change needs a restart.
	dismRebootExit = 3010

	servicingTailBytes = 2048
)

// The seams the tests replace. servicingExec runs one command and reports its
// exit code (-1 when it could not run or was killed); the default is runHidden.
var (
	servicingExec    = servicingRunHidden
	servicingScan    = scanUpdates
	servicingPending = pendingReboot
	servicingReboot  = func() error { return scheduleReboot(60, "Homelab RMM: finishing Windows servicing repair") }
	servicingNow     = time.Now
	servicingFetch   = servicingFetchPackage
)

var exitedWithRE = regexp.MustCompile(`exited with (-?\d+)`)

// servicingRunHidden is the production executor. runHidden reports a non-zero
// exit only in its error text, so the code is read back out of it.
func servicingRunHidden(ctx context.Context, name string, args ...string) (string, int, error) {
	stdout, stderr, err := runHidden(ctx, name, args...)
	out := stdout
	if strings.TrimSpace(stderr) != "" {
		out += "\n" + stderr
	}
	if err == nil {
		return out, 0, nil
	}
	if m := exitedWithRE.FindStringSubmatch(err.Error()); m != nil {
		if code, convErr := strconv.Atoi(m[1]); convErr == nil {
			return out, code, err
		}
	}
	return out, -1, err
}

func servicingSystemRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}

func servicingExe(name string) string {
	return filepath.Join(servicingSystemRoot(), "System32", name)
}

// servicingTail keeps the end of a command's output. SFC writes UTF-16, which
// arrives with NUL bytes between the letters; DISM redraws a progress bar with
// carriage returns. Both are cleaned so the tail reads as text.
func servicingTail(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	s = strings.Join(lines, "\n")
	if len(s) > servicingTailBytes {
		s = s[len(s)-servicingTailBytes:]
		for len(s) > 0 && s[0]&0xC0 == 0x80 { // do not start inside a UTF-8 sequence
			s = s[1:]
		}
		s = "..." + s
	}
	return s
}

// servicingPlan validates the request and returns the steps to run in
// canonical order.
func servicingPlan(req protocol.ServicingRepair) ([]string, error) {
	steps := req.Steps
	if len(steps) == 0 {
		steps = servicingDefaultSteps
	}
	for _, s := range steps {
		if !slices.Contains(servicingStepOrder, s) {
			return nil, fmt.Errorf("unknown servicing repair step %q", s)
		}
	}
	switch req.Reboot {
	case "", "never", "if_required":
	default:
		return nil, fmt.Errorf("the reboot setting %q is neither never nor if_required", req.Reboot)
	}
	var out []string
	for _, s := range servicingStepOrder {
		if slices.Contains(steps, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// servicingRepair runs the requested steps. A failed step stops the sequence
// unless it is sfc, which is advisory: it often reports violations it cannot
// fix and the later steps are exactly what addresses them.
func servicingRepair(ctx context.Context, cfg *Config, req protocol.ServicingRepair, progress func(string)) (*protocol.ServicingRepairResult, error) {
	steps, err := servicingPlan(req)
	if err != nil {
		return nil, err
	}
	if progress == nil {
		progress = func(string) {}
	}
	pkgOpMutex.Lock()
	defer pkgOpMutex.Unlock()
	// Like an install, a repair keeps the caller's deadline but not its
	// cancellation: killing DISM because the socket blipped can leave the
	// component store half repaired, and the reply is the only thing lost.
	runCtx, cancel := detachedDeadline(ctx, 4*time.Hour)
	defer cancel()

	res := &protocol.ServicingRepairResult{Steps: []protocol.ServicingStep{}}
	failed := false
	for _, name := range steps {
		if failed {
			res.Steps = append(res.Steps, protocol.ServicingStep{Name: name, Status: "skipped", Tail: "an earlier step failed"})
			continue
		}
		progress("servicing repair: " + name)
		start := servicingNow()
		var st protocol.ServicingStep
		switch name {
		case protocol.ServicingDismRestore:
			st = servicingCommand(runCtx, servicingDismTimeout, servicingExe("dism.exe"), "/Online", "/Cleanup-Image", "/RestoreHealth")
		case protocol.ServicingSFC:
			st = servicingCommand(runCtx, servicingSFCTimeout, servicingExe("sfc.exe"), "/scannow")
		case protocol.ServicingResetComponents:
			st = servicingResetComponents(runCtx)
		case protocol.ServicingAddPackage:
			st = servicingAddPackage(runCtx, cfg, req.Package)
		case protocol.ServicingRescan:
			st = servicingRescan(runCtx, res)
		}
		st.Name = name
		st.DurationMS = servicingNow().Sub(start).Milliseconds()
		if st.ExitCode == dismRebootExit && (name == protocol.ServicingDismRestore || name == protocol.ServicingAddPackage) {
			st.Status = "ok"
			res.RebootRequired = true
		}
		res.Steps = append(res.Steps, st)
		progress(fmt.Sprintf("servicing repair: %s %s", name, st.Status))
		if st.Status == "failed" && name != protocol.ServicingSFC {
			failed = true
		}
	}
	if servicingPending() {
		res.RebootRequired = true
	}
	if res.RebootRequired && req.Reboot == "if_required" {
		if err := servicingReboot(); err != nil {
			progress("could not schedule reboot: " + err.Error())
		} else {
			progress("reboot scheduled in 60 seconds")
		}
	}
	return res, nil
}

// servicingCommand runs one executable under its own timeout.
func servicingCommand(ctx context.Context, timeout time.Duration, exe string, args ...string) protocol.ServicingStep {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, code, err := servicingExec(cctx, exe, args...)
	st := protocol.ServicingStep{ExitCode: code, Status: "ok", Tail: servicingTail(out)}
	if err != nil && code != dismRebootExit {
		st.Status = "failed"
		if st.Tail == "" {
			st.Tail = err.Error()
		}
	}
	return st
}

// servicingResetComponents stops the update services, renames the two catalog
// directories to .bak.<ts> and starts the services again. An older .bak from a
// previous repair is deleted first so backups do not pile up; that is the
// only deletion, and it matches only "<dir>.bak.*".
func servicingResetComponents(ctx context.Context) (st protocol.ServicingStep) {
	cctx, cancel := context.WithTimeout(ctx, servicingResetTimeout)
	defer cancel()
	var log []string
	note := func(format string, a ...any) { log = append(log, fmt.Sprintf(format, a...)) }
	st.Status = "ok"
	fail := func() { st.Status, st.ExitCode = "failed", 1 }

	for _, svc := range servicingServices {
		// A service that is not running makes net stop exit non-zero; that is
		// fine. A service that really cannot be stopped shows up as a rename
		// failure below, which is the failure that matters.
		if _, _, err := servicingExec(cctx, servicingExe("net.exe"), "stop", svc, "/y"); err != nil {
			note("stop %s: %v", svc, err)
		}
	}
	// The services come back even when a rename failed: leaving Windows
	// Update stopped on a device is worse than a repair that did nothing.
	defer func() {
		for i := len(servicingServices) - 1; i >= 0; i-- {
			if _, _, err := servicingExec(context.WithoutCancel(ctx), servicingExe("net.exe"), "start", servicingServices[i]); err != nil {
				note("start %s: %v", servicingServices[i], err)
			}
		}
		st.Tail = strings.Join(log, "\n")
	}()

	root := servicingSystemRoot()
	stamp := strconv.FormatInt(servicingNow().Unix(), 10)
	for _, rel := range servicingDirs {
		dir := filepath.Join(root, rel)
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			note("%s does not exist, so there is nothing to rename", dir)
			continue
		}
		olds, _ := filepath.Glob(dir + ".bak.*")
		for _, old := range olds {
			if err := os.RemoveAll(old); err != nil {
				note("could not delete the earlier backup %s: %v", old, err)
				fail()
				return st
			}
		}
		target := dir + ".bak." + stamp
		if err := os.Rename(dir, target); err != nil {
			note("could not rename %s: %v", dir, err)
			fail()
			return st
		}
		note("renamed %s to %s", dir, filepath.Base(target))
	}
	return st
}

// servicingFetchPackage downloads the package through the subnet cache when a
// leader is assigned (with hash verification and origin fallback built in)
// and from the server directly otherwise. The file is verified against the
// named hash and the source it came from is returned.
func servicingFetchPackage(ctx context.Context, cfg *Config, pkg protocol.ServicingPackage, dst string) (string, error) {
	u, err := url.Parse(pkg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("the package URL must be an https URL")
	}
	var fp string
	if cfg != nil {
		fp = cfg.Fingerprint
		if su, err := url.Parse(cfg.ServerURL); cfg.ServerURL != "" && err == nil && !strings.EqualFold(su.Host, u.Host) {
			return "", errors.New("the package must be served by the RMM server this agent reports to")
		}
	}
	c := &cache.Client{}
	if cl := updateCache.Load(); cl != nil {
		cc := *cl
		c = &cc
	}
	c.OriginClient = &http.Client{Timeout: servicingFetchTimeout, Transport: &http.Transport{TLSClientConfig: TLSConfig(fp)}}
	res, err := c.Fetch(ctx, pkg.URL, pkg.SHA256, dst)
	if err != nil {
		os.Remove(dst + ".part")
		return "", err
	}
	if res.Source == "cache" {
		return fmt.Sprintf("cache %s over %s", res.LeaderID, res.Transport), nil
	}
	return "origin", nil
}

// servicingAddPackage fetches the .cab or .msu and adds it with DISM. Without
// a package the step is skipped, not failed: it is simply not applicable.
func servicingAddPackage(ctx context.Context, cfg *Config, pkg *protocol.ServicingPackage) protocol.ServicingStep {
	if pkg == nil || pkg.URL == "" {
		return protocol.ServicingStep{Status: "skipped", Tail: "no package was named"}
	}
	var ext string
	if u, err := url.Parse(pkg.URL); err == nil {
		ext = strings.ToLower(path.Ext(u.Path))
	}
	if ext != ".cab" && ext != ".msu" {
		return protocol.ServicingStep{Status: "failed", ExitCode: -1, Tail: "the package must be a .cab or .msu file"}
	}
	if !sha256HexRE.MatchString(pkg.SHA256) {
		return protocol.ServicingStep{Status: "failed", ExitCode: -1, Tail: "the package needs a SHA-256 hash"}
	}
	dir, err := os.MkdirTemp("", "rmm-servicing-")
	if err != nil {
		return protocol.ServicingStep{Status: "failed", ExitCode: -1, Tail: "could not create a download directory: " + err.Error()}
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "package"+ext)
	fctx, cancel := context.WithTimeout(ctx, servicingFetchTimeout)
	source, err := servicingFetch(fctx, cfg, *pkg, file)
	cancel()
	if err != nil {
		return protocol.ServicingStep{Status: "failed", ExitCode: -1, Tail: "could not fetch the package: " + err.Error()}
	}
	st := servicingCommand(ctx, servicingPackageTimeout, servicingExe("dism.exe"), "/Online", "/Add-Package", "/PackagePath:"+file, "/NoRestart")
	st.Tail = "package fetched from " + source + "\n" + st.Tail
	return st
}

// servicingRescan is the ordinary update scan; a scan that reports an error
// means the repair did not clear the problem, and says so in the step.
func servicingRescan(ctx context.Context, res *protocol.ServicingRepairResult) protocol.ServicingStep {
	sctx, cancel := context.WithTimeout(ctx, servicingScanTimeout)
	defer cancel()
	scan, err := servicingScan(sctx)
	if err != nil {
		return protocol.ServicingStep{Status: "failed", ExitCode: -1, Tail: err.Error()}
	}
	res.Scan = scan
	st := protocol.ServicingStep{Status: "ok", Tail: fmt.Sprintf("%d update(s) reported", len(scan.Updates))}
	if scan.Error != "" {
		st.Status, st.ExitCode, st.Tail = "failed", 1, scan.Error
	}
	if scan.RebootPending {
		res.RebootRequired = true
	}
	return st
}
