package agent

// The check kinds that are the same on every platform (file, command,
// disk_free, reboot_pending) and the dispatcher that resolves a kind to its
// implementation. The per-OS kinds live in baseline_linux.go and
// baseline_windows.go; baseline_other.go stubs them so the package still
// builds on a platform with neither.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"github.com/MonsterCouch/homelab-rmm/internal/baselines"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// goosName is runtime.GOOS, named once so the kinds and their tests agree.
const goosName = runtime.GOOS

// pkgOpMutex serialises everything on the device that touches the package
// database or the servicing stack: a patch install, a baseline `package`
// fix, a `windows_feature` fix. dpkg, rpm, WUA and DISM all take an
// exclusive lock of their own and answer a second caller with an error that
// looks like a failure of the operation rather than of the locking, so the
// agent keeps them apart itself.
var pkgOpMutex sync.Mutex

// errFixPending is a remediation that has started but cannot be confirmed by
// an immediate re-check - a reboot with a 60 s notice is the only one. The
// engine keeps the failing state, records that a fix ran and waits for the
// next pass instead of calling it an error.
var errFixPending = errors.New("the remediation is under way")

type fixPendingError struct{ msg string }

func (e *fixPendingError) Error() string { return e.msg }
func (e *fixPendingError) Unwrap() error { return errFixPending }

func pendingf(format string, args ...any) error {
	return &fixPendingError{msg: fmt.Sprintf(format, args...)}
}

// defaultKindImpl resolves a kind to its implementation, or nil when this
// agent cannot run it on this OS. nil is what makes the result `skipped`
// rather than `error`: an agent older than the server meets kinds it has
// never heard of, and a fleet-wide drift alert is not the way to report
// "upgrade your agents" (A42).
func defaultKindImpl(kind string) *kindImpl {
	if !baselines.KindRunsOn(kind, runtime.GOOS) {
		return nil
	}
	switch kind {
	case "file":
		return &kindImpl{check: fileCheck, fix: fileFix, fixable: fileFixable}
	case "command":
		return &kindImpl{check: commandCheck, fix: commandFix, fixable: commandFixable}
	case "disk_free":
		return &kindImpl{check: diskFreeCheck}
	case "reboot_pending":
		return &kindImpl{check: rebootPendingCheck, fix: rebootPendingFix, fixable: rebootPendingFixable}
	}
	return platformKind(kind)
}

// ---- file ----

func fileFixable(c *checkCtx) (bool, string) {
	var p baselines.FileParams
	if err := c.params(&p); err != nil {
		return false, ""
	}
	if p.State == "absent" {
		return true, ""
	}
	if p.Content == "" && (p.SHA256 != "" || p.Contains != "") {
		return false, "sha256 and contains describe a file without saying what it should hold, so this check cannot be fixed"
	}
	if p.Content == "" && p.Mode == "" && p.Owner == "" {
		return false, "this check has no content, mode or owner to apply"
	}
	if p.Content == "" {
		if _, err := os.Lstat(p.Path); err != nil && os.IsNotExist(err) {
			// Mode and owner apply to a file that exists. Letting the fix
			// run would chmod a path that is not there and report `error`
			// with an ENOENT; the honest answer is the drift the check
			// found, with the reason it cannot be repaired.
			return false, "this check has no content, so a missing file cannot be created"
		}
	}
	return true, ""
}

func fileCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.FileParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	if err := blFilePathSafe(p); err != nil {
		return blError("a safe path", "refused", err.Error())
	}
	want := fileWantLabel(p)
	c.setExpected(want)
	st, err := os.Lstat(p.Path)
	switch {
	case err != nil && os.IsNotExist(err):
		if p.State == "absent" {
			return blPass(want, "absent")
		}
		return blFail(want, "absent", "")
	case err != nil:
		return blError(want, "unreadable", err.Error())
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return blError(want, "symlink", "the path itself is a symbolic link; a baseline never follows one")
	}
	if st.IsDir() {
		return blError(want, "directory", "the path is a directory, not a file")
	}
	if !st.Mode().IsRegular() {
		return blError(want, "not a regular file", "only regular files can be managed by a file check")
	}
	if p.State == "absent" {
		return blFail(want, "present", "")
	}

	var diffs []string
	observed := []string{"present"}
	if p.Content != "" || p.SHA256 != "" || p.Contains != "" {
		body, err := blReadFileBounded(p.Path, st.Size())
		if err != nil {
			return blError(want, "unreadable", err.Error())
		}
		if p.Content != "" {
			if body != p.Content {
				diffs = append(diffs, "content differs")
				observed = append(observed, "content differs")
			} else {
				observed = append(observed, "content matches")
			}
		}
		if p.SHA256 != "" {
			sum := sha256.Sum256([]byte(body))
			got := hex.EncodeToString(sum[:])
			observed = append(observed, "sha256 "+blShortHash(got))
			if !strings.EqualFold(got, p.SHA256) {
				diffs = append(diffs, "sha256 differs")
			}
		}
		if p.Contains != "" {
			if strings.Contains(body, p.Contains) {
				observed = append(observed, "contains the text")
			} else {
				observed = append(observed, "does not contain the text")
				diffs = append(diffs, "the expected text is missing")
			}
		}
	}
	if runtime.GOOS != "windows" {
		if p.Mode != "" {
			got := fmt.Sprintf("%04o", st.Mode().Perm())
			observed = append(observed, "mode "+got)
			if got != blNormMode(p.Mode) {
				diffs = append(diffs, "mode differs")
			}
		}
		if p.Owner != "" {
			got, err := blFileOwner(p.Path)
			if err != nil {
				observed = append(observed, "owner unknown")
				diffs = append(diffs, "owner could not be read: "+err.Error())
			} else {
				observed = append(observed, "owner "+got)
				if !blOwnerMatches(p.Owner, got) {
					diffs = append(diffs, "owner differs")
				}
			}
		}
	} else if p.Mode != "" || p.Owner != "" {
		observed = append(observed, "mode and owner are not checked on Windows")
	}
	obs := strings.Join(observed, ", ")
	if len(diffs) > 0 {
		return blFail(want, obs, strings.Join(diffs, "; "))
	}
	return blPass(want, obs)
}

func fileFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.FileParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	if err := blFilePathSafe(p); err != nil {
		return "", err
	}
	if p.State == "absent" {
		st, err := os.Lstat(p.Path)
		if err != nil {
			if os.IsNotExist(err) {
				return "already absent", nil
			}
			return "", err
		}
		if st.IsDir() {
			return "", errors.New("refusing to delete a directory; a file check removes regular files only")
		}
		if !st.Mode().IsRegular() {
			return "", errors.New("refusing to delete something that is not a regular file")
		}
		if err := os.Remove(p.Path); err != nil {
			return "", err
		}
		return "removed " + p.Path, nil
	}
	var log []string
	if p.Content != "" {
		if err := blWriteFileAtomic(p.Path, p.Content, p.Mode); err != nil {
			return strings.Join(log, "; "), err
		}
		log = append(log, fmt.Sprintf("wrote %d bytes to %s", len(p.Content), p.Path))
	}
	if runtime.GOOS != "windows" {
		if p.Mode != "" {
			m, err := strconv.ParseUint(p.Mode, 8, 32)
			if err != nil {
				return strings.Join(log, "; "), err
			}
			if err := os.Chmod(p.Path, os.FileMode(m)); err != nil {
				return strings.Join(log, "; "), err
			}
			log = append(log, "set mode "+blNormMode(p.Mode))
		}
		if p.Owner != "" {
			if err := blChown(p.Path, p.Owner); err != nil {
				return strings.Join(log, "; "), err
			}
			log = append(log, "set owner "+p.Owner)
		}
	}
	if len(log) == 0 {
		return "", errors.New("nothing to apply: the check gives no content, mode or owner")
	}
	return strings.Join(log, "; "), nil
}

func fileWantLabel(p baselines.FileParams) string {
	if p.State == "absent" {
		return "absent"
	}
	parts := []string{"present"}
	if p.Content != "" {
		parts = append(parts, "content matches")
	}
	if p.SHA256 != "" {
		parts = append(parts, "sha256 "+blShortHash(p.SHA256))
	}
	if p.Contains != "" {
		parts = append(parts, "contains the text")
	}
	if runtime.GOOS != "windows" {
		if p.Mode != "" {
			parts = append(parts, "mode "+blNormMode(p.Mode))
		}
		if p.Owner != "" {
			parts = append(parts, "owner "+p.Owner)
		}
	}
	return strings.Join(parts, ", ")
}

// blFilePathSafe is the agent half of the file-path contract. The server has
// already refused a relative path, a "..", /etc/shadow and friends; what only
// the device can check is that no component of the parent chain is a symlink
// (which is how a local attacker aims a root-owned write at a file of their
// choosing) and that the path is not the agent's own configuration directory.
func blFilePathSafe(p baselines.FileParams) error {
	if err := baselines.CheckFilePath(p.Path, p.State, p.Content); err != nil {
		return err
	}
	if runtime.GOOS == "windows" && baselines.PathStyle(p.Path) != "windows" {
		return errors.New("a Windows device needs a Windows path")
	}
	if runtime.GOOS != "windows" && baselines.PathStyle(p.Path) != "unix" {
		return errors.New("this device needs an absolute unix path")
	}
	// Both sides are canonicalised first. The server compares spellings; only
	// the device can resolve them, and on Windows C:\ProgramData\HOMELA~1 is
	// the same directory as C:\ProgramData\HomelabRMM (A34).
	own := baselines.CleanPath(blCanonPath(ConfigDir()))
	target := baselines.CleanPath(blCanonPath(p.Path))
	if target == own || strings.HasPrefix(target, own+"/") {
		return errors.New("the agent's own configuration directory is not manageable by a baseline")
	}
	return blNoSymlinkParents(p.Path)
}

// blCanonPath resolves p as far as the filesystem allows: the longest
// ancestor that exists is put through filepath.EvalSymlinks - which on
// Windows also expands an NTFS 8.3 short name ("HOMELA~1") to the long name
// and fixes the case - and the components that do not exist yet are appended
// unchanged. A path that resolves to nothing at all is returned as it came,
// so this can only make a comparison stricter, never looser.
func blCanonPath(p string) string { return blCanonPathWith(p, filepath.EvalSymlinks) }

func blCanonPathWith(p string, eval func(string) (string, error)) string {
	dir := filepath.Clean(p)
	var rest []string
	for i := 0; i < 64; i++ {
		if resolved, err := eval(dir); err == nil {
			return filepath.Join(append([]string{resolved}, rest...)...)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		rest = append([]string{filepath.Base(dir)}, rest...)
		dir = parent
	}
	return p
}

// blNoSymlinkParents walks the parent chain with Lstat and refuses the first
// symbolic link it meets. A missing parent is not an error here: the fix
// creates the file, not the directory.
func blNoSymlinkParents(p string) error {
	dir := filepath.Dir(p)
	seen := 0
	for {
		st, err := os.Lstat(dir)
		if err == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%s is a symbolic link; a baseline never writes through one", dir)
			}
			if !st.IsDir() {
				return fmt.Errorf("%s is not a directory", dir)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir || seen > 64 {
			return nil
		}
		dir = parent
		seen++
	}
}

// blWriteFileAtomic writes content through a temporary file in the same
// directory and renames it over the target, so a reader never sees half a
// file and a crash never truncates the old one. An existing file's mode is
// preserved unless the check names one.
func blWriteFileAtomic(path, content, mode string) error {
	dir := filepath.Dir(path)
	perm := os.FileMode(0o644)
	var (
		haveOld bool
		oldSt   os.FileInfo
	)
	if st, err := os.Stat(path); err == nil {
		haveOld, oldSt = true, st
		perm = st.Mode().Perm()
	}
	if mode != "" {
		if m, err := strconv.ParseUint(mode, 8, 32); err == nil {
			perm = os.FileMode(m)
		}
	}
	f, err := os.CreateTemp(dir, ".rmm-baseline-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		f.Close()
		os.Remove(tmp)
	}()
	if _, err := f.WriteString(content); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if haveOld && runtime.GOOS != "windows" {
		if uid, gid, ok := blStatOwner(oldSt); ok {
			// Best effort: keeping the previous owner matters when the agent
			// rewrites a file another account owns, but a filesystem without
			// ownership must not fail the fix.
			_ = os.Chown(tmp, uid, gid)
		}
	}
	return os.Rename(tmp, path)
}

// blReadFileBounded reads a file the check has to inspect, refusing one that
// is too big to hold in memory for a comparison.
func blReadFileBounded(path string, size int64) (string, error) {
	const limit = 16 << 20
	if size > limit {
		return "", fmt.Errorf("the file is %d bytes, too large for a content check (limit %d)", size, limit)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(b) > limit {
		return "", fmt.Errorf("the file grew past the %d byte content-check limit while it was read", limit)
	}
	return string(b), nil
}

func blNormMode(m string) string {
	v, err := strconv.ParseUint(m, 8, 32)
	if err != nil {
		return m
	}
	return fmt.Sprintf("%04o", v)
}

func blShortHash(h string) string {
	if len(h) <= 12 {
		return strings.ToLower(h)
	}
	return strings.ToLower(h[:12]) + "\u2026"
}

// blOwnerMatches compares "user" or "user:group" against the observed
// "user:group", so a check that only names the user still passes.
func blOwnerMatches(want, got string) bool {
	if strings.Contains(want, ":") {
		return want == got
	}
	u, _, _ := strings.Cut(got, ":")
	return want == u
}

// blChown resolves a user[:group] and applies it. Numeric ids are accepted so
// a device with no NSS entry for the account is still manageable.
func blChown(path, owner string) error {
	if runtime.GOOS == "windows" {
		return errors.New("owner is not applied on Windows")
	}
	uname, gname, hasGroup := strings.Cut(owner, ":")
	uid, err := blLookupUID(uname)
	if err != nil {
		return err
	}
	gid := -1
	if hasGroup && gname != "" {
		gid, err = blLookupGID(gname)
		if err != nil {
			return err
		}
	}
	return os.Chown(path, uid, gid)
}

func blLookupUID(name string) (int, error) {
	if n, err := strconv.Atoi(name); err == nil {
		return n, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("user %q: %w", name, err)
	}
	return strconv.Atoi(u.Uid)
}

func blLookupGID(name string) (int, error) {
	if n, err := strconv.Atoi(name); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("group %q: %w", name, err)
	}
	return strconv.Atoi(g.Gid)
}

// ---- command ----

func commandFixable(c *checkCtx) (bool, string) {
	var p baselines.CommandParams
	if err := c.params(&p); err != nil {
		return false, ""
	}
	if strings.TrimSpace(p.Fix) == "" {
		return false, "this check has no fix script"
	}
	return true, ""
}

func commandCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.CommandParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	expected := orText(p.Expected, "exit 0")
	c.setExpected(expected)
	res := c.e.runScript(ctx, c, "check", p.Language, p.Check)
	detail := blScriptDetail(res)
	switch {
	case res.TimedOut:
		// The runner's own deadline fires a full second before the engine's,
		// so the script's partial output is captured here rather than lost
		// when probe abandons the check. The operator is told the CHECK's
		// timeout, not the runner's deliberately shorter internal one.
		return blError(expected, "timed out",
			joinDetail(fmt.Sprintf("timed out after %ds", baselines.ClampTimeout(c.check.TimeoutSec)), detail))
	case res.Error != "":
		return blError(expected, "could not run", joinDetail(res.Error, detail))
	case res.ExitCode == 0:
		return blPass(expected, orText(blFirstNonEmptyLine(res.Stdout), "exit 0"))
	}
	return blFail(expected, orText(blFirstNonEmptyLine(res.Stdout), fmt.Sprintf("exit %d", res.ExitCode)), detail)
}

func commandFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.CommandParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	if strings.TrimSpace(p.Fix) == "" {
		return "", errors.New("this check has no fix script")
	}
	res := c.e.runScript(ctx, c, "fix", p.Language, p.Fix)
	detail := blScriptDetail(res)
	switch {
	case res.TimedOut:
		return detail, errors.New(orText(res.Error, "the fix script timed out"))
	case res.Error != "":
		return detail, errors.New("the fix script could not run: " + res.Error)
	case res.ExitCode != 0:
		return detail, fmt.Errorf("the fix script exited with %d", res.ExitCode)
	}
	return detail, nil
}

func executeFixScript(ctx context.Context, c *checkCtx, lang, body string) (string, error) {
	if strings.TrimSpace(body) == "" {
		return "", errors.New("no remediation script provided")
	}
	if lang == "" {
		if runtime.GOOS == "windows" {
			lang = "powershell"
		} else {
			lang = "bash"
		}
	}
	res := c.e.runScript(ctx, c, "fix", lang, body)
	detail := blScriptDetail(res)
	switch {
	case res.TimedOut:
		return detail, errors.New(orText(res.Error, "the remediation script timed out"))
	case res.Error != "":
		return detail, errors.New("the remediation script could not run: " + res.Error)
	case res.ExitCode != 0:
		return detail, fmt.Errorf("the remediation script exited with %d", res.ExitCode)
	}
	return detail, nil
}

// runScript executes a check or fix body through the same runner the console
// uses: a temp directory, a 0700 file, an interpreter invoked with
// exec.Command arguments - never a shell string.
func (e *baselineEngine) runScript(ctx context.Context, c *checkCtx, phase, lang, body string) *protocol.ScriptResult {
	timeout := baselines.DefaultTimeoutSec
	if d, ok := ctx.Deadline(); ok {
		timeout = blScriptTimeout(time.Until(d))
	}
	req := protocol.ScriptRun{
		RunID:    fmt.Sprintf("baseline-%d-%d-%s", c.spec.ID, c.check.ID, phase),
		Language: lang,
		Body:     body,
		Timeout:  timeout,
		Env: map[string]string{
			"RMM_BASELINE_ID": strconv.FormatInt(c.spec.ID, 10),
			"RMM_CHECK_ID":    strconv.FormatInt(c.check.ID, 10),
		},
	}
	var runner *scriptRunner
	if e.a != nil {
		runner = e.a.runs
	}
	if runner == nil {
		runner = newScriptRunner()
	}
	return runner.run(ctx, req, func(protocol.ScriptChunk) {})
}

// blScriptTimeout is the deadline the script runner gets, in whole seconds,
// derived from what is left of the engine's.
//
// It is at least a FULL SECOND shorter, and that second is the whole point:
// when the runner's deadline fires first it kills the process tree, keeps
// everything the script printed and answers `timed out`, and the check
// reports that partial output. When the engine's deadline wins instead,
// probe abandons the check goroutine and every line the script wrote is lost
// with it. int() truncation alone leaves only the fractional part as
// headroom, which is nothing at all when the caller's deadline happens to
// land on a whole second.
func blScriptTimeout(remaining time.Duration) int {
	s := int(remaining.Seconds()) - 1
	if s < 1 {
		return 1
	}
	return s
}

// blScriptDetail is the last 4 KiB of stderr, then stdout: an operator
// reading a failing check wants the error text first.
func blScriptDetail(res *protocol.ScriptResult) string {
	var parts []string
	if s := strings.TrimSpace(res.Stderr); s != "" {
		parts = append(parts, blTail(s, baselines.MaxDetailBytes))
	}
	if s := strings.TrimSpace(res.Stdout); s != "" {
		parts = append(parts, blTail(s, baselines.MaxDetailBytes))
	}
	return blTail(joinDetail(parts...), baselines.MaxDetailBytes)
}

// ---- disk_free ----

func diskFreeCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.DiskFreeParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	mount := blNormaliseMount(p.Mount)
	want := fmt.Sprintf("at least %.4g%% free on %s", p.MinFreePct, mount)
	c.setExpected(want)
	target, err := blResolveMount(mount)
	if err != nil {
		return blError(want, "unknown mount", err.Error())
	}
	u, err := disk.Usage(target)
	if err != nil {
		return blError(want, "unreadable", err.Error())
	}
	if u.Total == 0 {
		return blError(want, "unreadable", "the filesystem reports a total size of zero")
	}
	freePct := float64(u.Free) / float64(u.Total) * 100
	observed := fmt.Sprintf("%.1f%% free (%s of %s) on %s", freePct, blBytes(u.Free), blBytes(u.Total), mount)
	if freePct < p.MinFreePct {
		return blFail(want, observed, "")
	}
	return blPass(want, observed)
}

// blNormaliseMount puts a mount in the form the device uses: "C:" on
// Windows (accepting "C:\" and "c:"), a "/"-prefixed path elsewhere.
func blNormaliseMount(m string) string { return blNormaliseMountOn(goosName, m) }

// blNormaliseMountOn is blNormaliseMount with the platform spelled out, so
// the Windows rules can be tested from any device.
func blNormaliseMountOn(goos, m string) string {
	m = strings.TrimSpace(m)
	if goos == "windows" {
		n := strings.ReplaceAll(m, "/", `\`)
		n = strings.TrimSuffix(n, `\`)
		if n == "" {
			// A bare separator normalises to nothing. Returning that empty
			// string rendered a blank mount in `expected` and `observed` and
			// sent blResolveMount probing `\`, which disk.Usage happily
			// answers for whatever drive the agent runs from. Keep the
			// operator's own text instead; blMountNamed refuses it next.
			return strings.ToUpper(m)
		}
		if len(n) == 1 {
			n += ":"
		}
		return strings.ToUpper(n)
	}
	m = strings.ReplaceAll(m, `\`, "/")
	if !strings.HasPrefix(m, "/") {
		m = "/" + m
	}
	if len(m) > 1 {
		m = strings.TrimSuffix(m, "/")
	}
	return m
}

// blMountNamed refuses a mount this platform cannot name at all, before any
// disk is probed. "/" and "\" are the unix spelling of the root filesystem
// and name no Windows volume: a mixed-fleet baseline written as
// {"mount":"/","min_free_pct":10} - the natural Linux spelling, and the shape
// of the seeded Linux check - would otherwise report a silent C: measurement
// on every Windows device it matched. An unknown mount is `error`, not a
// drift (A40).
func blMountNamed(goos, mount string) error {
	m := strings.TrimSpace(mount)
	switch {
	case m == "":
		return errors.New("a mount point or drive is required")
	case goos == "windows" && (m == `\` || m == "/"):
		return fmt.Errorf("%s is not a mount point on this device: a Windows mount is a drive such as C:, or the path of a mounted folder", m)
	}
	return nil
}

// blResolveMount maps the normalised mount onto a path disk.Usage accepts,
// and refuses one the device does not have: an unknown mount is an error, not
// a drift (A40).
func blResolveMount(mount string) (string, error) {
	if err := blMountNamed(goosName, mount); err != nil {
		return "", err
	}
	parts, err := disk.Partitions(false)
	if err == nil {
		for _, pt := range parts {
			if strings.EqualFold(blNormaliseMount(pt.Mountpoint), mount) {
				return pt.Mountpoint, nil
			}
		}
	}
	probe := mount
	if runtime.GOOS == "windows" {
		probe = mount + `\`
	}
	if _, uerr := disk.Usage(probe); uerr == nil {
		return probe, nil
	}
	if err != nil {
		return "", fmt.Errorf("%s is not a mount point on this device (%v)", mount, err)
	}
	return "", fmt.Errorf("%s is not a mount point on this device", mount)
}

func blBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// ---- reboot_pending ----

func rebootPendingFixable(c *checkCtx) (bool, string) {
	var p baselines.RebootPendingParams
	if err := c.params(&p); err != nil {
		return false, ""
	}
	if !p.AllowReboot {
		return false, "allow_reboot is off, so the device is not restarted"
	}
	return true, ""
}

func rebootPendingCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.RebootPendingParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	max := p.MaxHours
	if max < 1 {
		max = 1
	}
	want := fmt.Sprintf("no reboot pending for more than %dh", max)
	c.setExpected(want)
	pending := pendingReboot()
	// A preview reads the bookkeeping, it never rewrites it (A8).
	since := c.e.pendingSince(pending, c.preview)
	if !pending {
		return blPass(want, "no reboot pending")
	}
	hours := 0.0
	if since > 0 {
		hours = c.e.now().Sub(time.Unix(since, 0)).Hours()
	}
	observed := fmt.Sprintf("pending for %.1fh", hours)
	if hours <= float64(max) {
		return blPass(want, observed)
	}
	return blFail(want, observed, "")
}

func isEnforceTimeDue(now time.Time, enforceTime string) bool {
	if enforceTime == "" || enforceTime == "immediate" {
		return true
	}
	parts := strings.Split(enforceTime, ":")
	if len(parts) != 2 {
		return true
	}
	h, errH := strconv.Atoi(parts[0])
	m, errM := strconv.Atoi(parts[1])
	if errH != nil || errM != nil {
		return true
	}
	curH, curM, _ := now.Clock()
	curTotal := curH*60 + curM
	targetTotal := h*60 + m
	diff := curTotal - targetTotal
	if diff >= 0 && diff < 120 {
		return true
	}
	return false
}

func rebootPendingFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.RebootPendingParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	if !p.AllowReboot {
		return "", errors.New("allow_reboot is off")
	}
	// None of these three start anything, so none of them is an `error`: the
	// device is still drifted, the detail says why it was left alone, and the
	// next pass tries again (A32).
	if c.e.a != nil {
		if c.e.a.shells != nil && c.e.a.shells.anyOpen() {
			return "", skipf("a remote shell session is open on this device; not restarting it")
		}
		if c.e.a.runs != nil && c.e.a.runs.live() {
			return "", skipf("a script run is in progress on this device; not restarting it")
		}
	}
	if c.e.rebootedRecently() {
		return "", skipf("this device was already restarted by a baseline in the last 24 hours")
	}

	reason := p.Reason
	if reason == "" {
		reason = "clear a pending reboot"
	}

	if p.WarnUser {
		maxP := p.MaxPostpones
		if maxP <= 0 {
			maxP = 3
		}
		count, until := c.e.getPostpones(c.check.ID)
		nowUnix := c.e.now().Unix()
		if count < maxP && until > nowUnix {
			return "", skipf("restart postponed by user until %s (%d of %d postpones used)",
				time.Unix(until, 0).Format("15:04"), count, maxP)
		}

		if count < maxP {
			remaining := maxP - count
			act, promptErr := promptRebootUser(ctx, reason, p.DisplayTimeSec, remaining, maxP)
			if promptErr != nil {
				slog.Warn("reboot prompt error", "check", c.check.ID, "err", promptErr)
			}
			switch act {
			case "postpone":
				newCount := c.e.addPostpone(c.check.ID, p.PostponeDelayMin)
				return "", skipf("user chose to postpone restart (%d of %d postpones used)", newCount, maxP)
			case "timeout":
				newCount := c.e.addPostpone(c.check.ID, p.PostponeDelayMin)
				return "", skipf("reboot prompt timed out; postponed restart (%d of %d postpones used)", newCount, maxP)
			case "reboot":
				slog.Info("user approved immediate restart", "check", c.check.ID)
			case "headless":
				// Headless device, proceed with reboot
			}
		} else {
			if !isEnforceTimeDue(c.e.now(), p.EnforceTime) {
				return "", skipf("postpone limit reached (%d of %d); waiting for scheduled reboot at %s", count, maxP, p.EnforceTime)
			}
		}
	}

	if !pkgOpMutex.TryLock() {
		return "", busyf("another package operation is in progress")
	}
	defer pkgOpMutex.Unlock()
	msg := fmt.Sprintf("Restarting to %s (Homelab RMM baseline)", reason)
	if err := powerAction(protocol.Power{Action: "reboot", Delay: 60, Message: msg}); err != nil {
		return "", err
	}
	c.e.clearPostpones(c.check.ID)
	c.e.markRebooted()
	return "", pendingf("a restart was scheduled with a 60 second notice")
}

// blIsOwnService reports whether a `service` check names the agent's own
// service or unit. Reading its state is fine and useful; changing it is the
// one remediation that cannot be undone from here, because a stopped or
// disabled agent never evaluates a baseline again, never reports and never
// receives the config push that would put it back. It is refused on both
// platforms, the way the agent's own directory is refused by the file kind
// and its own service key by the registry kind.
func blIsOwnService(name string) bool {
	n := strings.TrimSpace(name)
	n = strings.TrimSuffix(n, ".service")
	return strings.EqualFold(n, ServiceName)
}

// errOwnService is that refusal, spelled once so both platforms agree.
var errOwnService = errors.New("refusing to change the RMM agent's own service: the device would stop being managed and could not be told otherwise")

// ---- small shared shapes ----

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// blToggle is the shape of every "should this be on" kind: firewall and
// time_sync on both platforms.
func blToggle(want, observed string, ok bool) kindResult {
	if ok {
		return blPass(want, observed)
	}
	return blFail(want, observed, "")
}

// ---- shared text helpers ----
//
// firstLine/lastLines live in the Linux-only files; these are their
// constraint-free twins, so the shared kinds and the Windows kinds can use
// them too.

func blFirstNonEmptyLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(strings.TrimRight(l, "\r")); l != "" {
			return l
		}
	}
	return ""
}

// blTail keeps the last n bytes of s on a rune boundary, which is what an
// operator wants from a failing tool: the error, not the banner.
func blTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := len(s) - n
	for cut < len(s) && s[cut]&0xC0 == 0x80 {
		cut++
	}
	return "\u2026" + s[cut:]
}
