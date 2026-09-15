//go:build linux

package agent

// The Linux half of the check kinds: service, package, group_members,
// firewall, time_sync and sysctl. Every command runs through runCmd with
// separate arguments (never a shell string) and every name that reaches a
// command line is validated first with the same patterns the rest of the
// Linux platform files use.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/MonsterCouch/homelab-rmm/internal/baselines"
)

// Test seams: the sysctl kind reads the live /proc but must never write the
// real /etc/sysctl.d on a test machine.
var (
	procSysRoot   = "/proc/sys"
	sysctlConfDir = "/etc/sysctl.d"
	// sysctlFileMu keeps two checks of the same pass from doing a
	// read-modify-write of the managed file at the same time.
	sysctlFileMu sync.Mutex
	// etcGroupPath and etcPasswdPath are read directly when getent is absent.
	etcGroupPath  = "/etc/group"
	etcPasswdPath = "/etc/passwd"
)

func sysctlConfPath() string { return sysctlConfDir + "/90-homelab-rmm.conf" }

func platformKind(kind string) *kindImpl {
	switch kind {
	case "service":
		return &kindImpl{check: lnxServiceCheck, fix: lnxServiceFix}
	case "package":
		return &kindImpl{check: lnxPackageCheck, fix: lnxPackageFix}
	case "group_members":
		return &kindImpl{check: lnxGroupCheck, fix: lnxGroupFix}
	case "firewall":
		return &kindImpl{check: lnxFirewallCheck, fix: lnxFirewallFix}
	case "time_sync":
		return &kindImpl{check: lnxTimeSyncCheck, fix: lnxTimeSyncFix}
	case "sysctl":
		return &kindImpl{check: lnxSysctlCheck, fix: lnxSysctlFix}
	}
	return nil
}

// blFileOwner reports "user:group" for a path, falling back to the numeric
// ids when the account has no NSS entry.
func blFileOwner(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	uid, gid, ok := blStatOwner(st)
	if !ok {
		return "", errors.New("the filesystem does not report ownership")
	}
	uname := strconv.Itoa(uid)
	if u, err := user.LookupId(uname); err == nil && u.Username != "" {
		uname = u.Username
	}
	gname := strconv.Itoa(gid)
	if g, err := user.LookupGroupId(gname); err == nil && g.Name != "" {
		gname = g.Name
	}
	return uname + ":" + gname, nil
}

func blStatOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, good := fi.Sys().(*syscall.Stat_t)
	if !good {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// ---- service ----

// lnxUnitName appends .service when the check names a bare unit, which is
// what an operator types.
func lnxUnitName(name string) string {
	if hasUnitSuffix(name) {
		return name
	}
	return name + ".service"
}

func lnxUnitProps(ctx context.Context, name string) (map[string]string, error) {
	out, stderr, _, err := runCmd(ctx, "systemctl", "show", "--no-pager",
		"--property=Id,LoadState,ActiveState,SubState,UnitFileState", "--", name)
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("systemctl show %s: %s", name, orFirst(firstLine(stderr), err.Error()))
	}
	blocks := parseShowBlocks(out)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("systemctl show %s returned nothing", name)
	}
	return blocks[0], nil
}

// lnxUnenablable are the unit-file states with no [Install] section: systemd
// cannot enable or disable them at all, so asking for start_type auto is a
// configuration error, not drift to loop on (A37).
var lnxUnenablable = map[string]bool{
	"static": true, "indirect": true, "generated": true, "transient": true,
}

func lnxServiceCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.ServiceParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	unit := lnxUnitName(p.Name)
	want := lnxServiceWant(p)
	if !validUnitName(unit) {
		return blError(want, "refused", fmt.Sprintf("%q is not a valid systemd unit name", p.Name))
	}
	if !hasCmd("systemctl") {
		return blError(want, "no systemd", errNoSystemd.Error())
	}
	props, err := lnxUnitProps(ctx, unit)
	if err != nil {
		return blError(want, "unknown", err.Error())
	}
	if props["LoadState"] == "not-found" {
		return blError(want, "no such unit", fmt.Sprintf("%s does not exist on this device", unit))
	}
	state := unitState(props["ActiveState"], props["SubState"])
	fileState := props["UnitFileState"]
	startType := unitStartType(fileState)
	if props["LoadState"] == "masked" {
		startType = "disabled"
	}
	observed := state + " / " + startType
	wantStart := p.StartType
	if wantStart == "" {
		wantStart = "any"
	}
	if wantStart == "auto" && lnxUnenablable[fileState] {
		return blError(want, observed,
			fmt.Sprintf("%s is a %s unit: systemd has no [Install] section to enable, so its start type cannot be changed", unit, fileState))
	}
	var diffs []string
	if state != p.State {
		diffs = append(diffs, "the service is "+state)
	}
	if !lnxStartTypeOK(wantStart, startType) {
		diffs = append(diffs, "the start type is "+startType)
	}
	if len(diffs) > 0 {
		return blFail(want, observed, strings.Join(diffs, "; "))
	}
	return blPass(want, observed)
}

func lnxServiceWant(p baselines.ServiceParams) string {
	st := p.StartType
	if st == "" {
		st = "any"
	}
	return p.State + " / " + st
}

// lnxStartTypeOK compares the wanted start type against the observed one.
// "any" always matches; systemd reports static and friends as "manual".
func lnxStartTypeOK(want, got string) bool {
	if want == "" || want == "any" {
		return true
	}
	return want == got
}

func lnxServiceFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.ServiceParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	unit := lnxUnitName(p.Name)
	if !validUnitName(unit) {
		return "", fmt.Errorf("%q is not a valid systemd unit name", p.Name)
	}
	if blIsOwnService(p.Name) {
		return "", errOwnService
	}
	if !hasCmd("systemctl") {
		return "", errNoSystemd
	}
	props, err := lnxUnitProps(ctx, unit)
	if err != nil {
		return "", err
	}
	fileState := props["UnitFileState"]
	startType := unitStartType(fileState)
	if props["LoadState"] == "masked" {
		startType = "disabled"
	}
	var log []string
	switch p.StartType {
	case "", "any":
	case "manual":
		if startType != "manual" {
			return strings.Join(log, "; "), errors.New("systemd has no manual start type; use any")
		}
	case "auto":
		if lnxUnenablable[fileState] {
			return strings.Join(log, "; "), fmt.Errorf("%s is a %s unit and cannot be enabled", unit, fileState)
		}
		if startType != "auto" {
			if out, err := lnxSystemctl(ctx, "enable", unit); err != nil {
				return strings.Join(log, "; "), err
			} else {
				log = append(log, out)
			}
		}
	case "disabled":
		if startType != "disabled" {
			if out, err := lnxSystemctl(ctx, "disable", unit); err != nil {
				return strings.Join(log, "; "), err
			} else {
				log = append(log, out)
			}
		}
	}
	state := unitState(props["ActiveState"], props["SubState"])
	if state != p.State {
		verb := "stop"
		if p.State == "running" {
			verb = "start"
		}
		out, err := lnxSystemctl(ctx, verb, unit)
		if err != nil {
			return strings.Join(log, "; "), err
		}
		log = append(log, out)
	}
	if len(log) == 0 {
		return "", errors.New("nothing to change")
	}
	return strings.Join(log, "; "), nil
}

// lnxSystemctl runs one verb. --no-ask-password makes an unprivileged agent
// fail fast instead of hanging on a polkit prompt nobody can answer.
func lnxSystemctl(ctx context.Context, verb, unit string) (string, error) {
	_, stderr, _, err := runCmd(ctx, "systemctl", "--no-ask-password", verb, "--", unit)
	if err != nil {
		return "", fmt.Errorf("systemctl %s %s: %s", verb, unit, orFirst(firstLine(stderr), err.Error()))
	}
	return "systemctl " + verb + " " + unit, nil
}

// ---- package ----

// lnxPkgQueryTool picks the query tool: dpkg first so a Debian box with a
// stray rpm still uses dpkg, then rpm, then pacman.
func lnxPkgQueryTool() string {
	for _, c := range []string{"dpkg-query", "rpm", "pacman"} {
		if hasCmd(c) {
			return c
		}
	}
	return ""
}

// lnxPkgInstalled asks the device whether a package is installed and at which
// version. A tool that exits non-zero because the package is unknown is not
// an error; a tool that is not there at all is.
func lnxPkgInstalled(ctx context.Context, name string) (bool, string, error) {
	switch lnxPkgQueryTool() {
	case "dpkg-query":
		out, _, _, _ := runCmd(ctx, "dpkg-query", "-W", "-f=${Status}|${Version}\\n", "--", name)
		line := blFirstNonEmptyLine(out)
		status, version, ok := strings.Cut(line, "|")
		if !ok || !strings.Contains(status, " installed") {
			return false, "", nil
		}
		return true, strings.TrimSpace(version), nil
	case "rpm":
		out, _, _, _ := runCmd(ctx, "rpm", "-q", "--qf", "%{VERSION}\\n", "--", name)
		v := blFirstNonEmptyLine(out)
		if v == "" || strings.Contains(v, "not installed") {
			return false, "", nil
		}
		return true, v, nil
	case "pacman":
		out, _, _, _ := runCmd(ctx, "pacman", "-Q", "--", name)
		line := blFirstNonEmptyLine(out)
		if line == "" {
			return false, "", nil
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return true, "", nil
		}
		return true, f[1], nil
	}
	return false, "", errNoPackageManager
}

func lnxPackageCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.PackageParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	if !validPkgID(p.Name) {
		return blError(p.State, "refused", fmt.Sprintf("%q is not a valid package name", p.Name))
	}
	want := p.State
	if p.MinVersion != "" {
		want = "present >= " + p.MinVersion
	}
	present, version, err := lnxPkgInstalled(ctx, p.Name)
	if err != nil {
		return blError(want, "unknown", err.Error())
	}
	observed := "absent"
	if present {
		observed = strings.TrimSpace("present " + version)
	}
	if p.State == "absent" {
		if present {
			return blFail(want, observed, "")
		}
		return blPass(want, observed)
	}
	if !present {
		return blFail(want, observed, "")
	}
	if p.MinVersion == "" {
		return blPass(want, observed)
	}
	cmp, err := baselines.CompareVersions(version, p.MinVersion)
	if err != nil {
		return blError(want, observed, err.Error())
	}
	if cmp < 0 {
		return blFail(want, observed, fmt.Sprintf("%s is older than the required %s", version, p.MinVersion))
	}
	return blPass(want, observed)
}

func lnxPackageFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.PackageParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	if !validPkgID(p.Name) {
		return "", fmt.Errorf("%q is not a valid package name", p.Name)
	}
	pm := packageManager()
	if pm == "" {
		return "", errNoPackageManager
	}
	if !pkgOpMutex.TryLock() {
		return "", busyf("another package operation is in progress")
	}
	defer pkgOpMutex.Unlock()
	install := p.State == "present"
	var (
		env  []string
		name string
		args []string
	)
	switch pm {
	case "apt":
		env, name = aptEnv, "apt-get"
		args = append([]string{"-y", "-q"}, aptDpkgOpts...)
		if install {
			args = append(args, "install", "--", p.Name)
		} else {
			args = append(args, "remove", "--", p.Name)
		}
	case "dnf", "yum":
		name = pm
		verb := "install"
		if !install {
			verb = "remove"
		}
		args = []string{"-y", verb, "--", p.Name}
	case "pacman":
		name = "pacman"
		if install {
			args = []string{"-S", "--noconfirm", "--needed", "--", p.Name}
		} else {
			args = []string{"-R", "--noconfirm", "--", p.Name}
		}
	case "zypper":
		name = "zypper"
		verb := "in"
		if !install {
			verb = "rm"
		}
		args = []string{"-n", verb, p.Name}
	default:
		return "", errNoPackageManager
	}
	log, code, err := streamCmd(ctx, env, nil, name, args...)
	detail := blTail(strings.TrimSpace(log), baselines.MaxDetailBytes)
	if err != nil {
		if pm == "zypper" && zypperOK(code) {
			return detail, nil
		}
		return detail, fmt.Errorf("%s: %w", name, err)
	}
	return detail, nil
}

// ---- group_members ----

// lnxGroupMembers reads the group through getent (which sees LDAP and SSSD
// too) and falls back to /etc/group. The accounts whose PRIMARY group this is
// are members as well, and no tool can remove them from it, so they are
// reported and protected.
func lnxGroupMembers(ctx context.Context, group string) (members, primary []string, err error) {
	var line string
	if hasCmd("getent") {
		// getent answers for LDAP and SSSD as well, which /etc/group cannot;
		// a tool error or an unknown group simply leaves the line empty and
		// the file below is tried next.
		out, _, _, _ := runCmd(ctx, "getent", "group", "--", group)
		line = blFirstNonEmptyLine(out)
	}
	if line == "" {
		b, rerr := os.ReadFile(etcGroupPath)
		if rerr != nil {
			return nil, nil, rerr
		}
		for _, l := range strings.Split(string(b), "\n") {
			if n, _, _, ok := parseGroupLine(l); ok && strings.EqualFold(n, group) {
				line = l
				break
			}
		}
	}
	if line == "" {
		return nil, nil, fmt.Errorf("there is no group called %q on this device", group)
	}
	_, gid, members, ok := parseGroupLine(line)
	if !ok {
		return nil, nil, fmt.Errorf("cannot read the entry for group %q", group)
	}
	if b, rerr := os.ReadFile(etcPasswdPath); rerr == nil {
		primary = parsePasswdPrimary(string(b), gid)
	}
	return members, primary, nil
}

// lnxGroupGuard is what only this device knows: root is untouchable, so is
// the account the agent runs as, so is anyone holding the group as their
// primary group.
func lnxGroupGuard(primary []string) groupGuard {
	g := groupGuard{Builtin: []string{"root"}, Primary: primary}
	if u, err := user.Current(); err == nil && u.Username != "" {
		g.Self = append(g.Self, u.Username)
	}
	if os.Getuid() == 0 {
		g.Self = append(g.Self, "root")
	}
	return g
}

func lnxGroupCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.GroupMembersParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := groupExpectedLabel(p)
	members, primary, err := lnxGroupMembers(ctx, p.Group)
	if err != nil {
		return blError(want, "unknown", err.Error())
	}
	all := append(append([]string{}, members...), primary...)
	plan := planGroupMembers(p.Group, all, p, lnxGroupGuard(primary))
	observed := groupObservedLabel(all)
	if !plan.Drifted(p.EffectiveMode()) {
		return blPass(want, observed)
	}
	return blFail(want, observed, groupDriftDetail(plan, p))
}

func lnxGroupFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.GroupMembersParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	members, primary, err := lnxGroupMembers(ctx, p.Group)
	if err != nil {
		return "", err
	}
	all := append(append([]string{}, members...), primary...)
	plan := planGroupMembers(p.Group, all, p, lnxGroupGuard(primary))
	if plan.Refusal != "" {
		return "", errors.New(plan.Refusal)
	}
	if len(plan.Remove) == 0 {
		return "", errors.New("nothing can be removed: " + orText(groupDriftDetail(plan, p), "the membership already matches"))
	}
	if !hasCmd("gpasswd") {
		return "", errors.New("gpasswd is not available on this device")
	}
	var done []string
	for _, m := range plan.Remove {
		if _, stderr, _, err := runCmd(ctx, "gpasswd", "-d", m, p.Group); err != nil {
			return strings.Join(done, "; "), fmt.Errorf("removing %s from %s: %s", m, p.Group, orFirst(firstLine(stderr), err.Error()))
		}
		done = append(done, "removed "+m)
	}
	return strings.Join(done, "; "), nil
}

// ---- firewall ----

// lnxFirewallTool picks ufw when it is installed, else firewalld. A device
// with neither is `skipped`, never `fail`: nothing has drifted on a machine
// that has no firewall to configure (A40).
func lnxFirewallTool() string {
	switch {
	case hasCmd("ufw"):
		return "ufw"
	case hasCmd("firewall-cmd"):
		return "firewalld"
	}
	return ""
}

func lnxFirewallCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.ToggleParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := "firewall " + onOff(p.Want())
	switch lnxFirewallTool() {
	case "ufw":
		out, stderr, _, err := runCmd(ctx, "ufw", "status")
		if err != nil && strings.TrimSpace(out) == "" {
			return blError(want, "unknown", orFirst(firstLine(stderr), err.Error()))
		}
		active := strings.Contains(strings.ToLower(out), "status: active")
		return blToggle(want, "ufw "+onOff(active), active == p.Want())
	case "firewalld":
		out, _, _, _ := runCmd(ctx, "firewall-cmd", "--state")
		active := strings.Contains(strings.ToLower(out), "running") && !strings.Contains(strings.ToLower(out), "not running")
		return blToggle(want, "firewalld "+onOff(active), active == p.Want())
	}
	return blSkip("no supported firewall")
}

func lnxFirewallFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.ToggleParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	switch lnxFirewallTool() {
	case "ufw":
		args := []string{"disable"}
		if p.Want() {
			// --force skips the "this may disrupt existing ssh connections"
			// prompt, which nobody can answer from a service.
			args = []string{"--force", "enable"}
		}
		out, stderr, _, err := runCmd(ctx, "ufw", args...)
		if err != nil {
			return "", fmt.Errorf("ufw %s: %s", strings.Join(args, " "), orFirst(firstLine(stderr), err.Error()))
		}
		return blFirstNonEmptyLine(out), nil
	case "firewalld":
		verb := "stop"
		if p.Want() {
			verb = "start"
		}
		if !hasCmd("systemctl") {
			return "", errNoSystemd
		}
		return lnxSystemctl(ctx, verb, "firewalld")
	}
	return "", errors.New("no supported firewall on this device")
}

// ---- time_sync ----

func lnxTimeSyncCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.ToggleParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := "time sync " + onOff(p.Want())
	if !hasCmd("timedatectl") {
		return blSkip("timedatectl is not available")
	}
	out, _, _, err := runCmd(ctx, "timedatectl", "show", "-p", "NTP")
	on, ok := lnxParseNTP(out)
	if !ok {
		status, _, _, serr := runCmd(ctx, "timedatectl", "status")
		if on, ok = lnxParseNTPStatus(status); !ok {
			return blError(want, "unknown", orFirst(errString(err), errString(serr)))
		}
	}
	return blToggle(want, "NTP "+onOff(on), on == p.Want())
}

// lnxParseNTP reads "NTP=yes" from "timedatectl show -p NTP".
func lnxParseNTP(out string) (bool, bool) {
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok && strings.EqualFold(k, "NTP") {
			return strings.EqualFold(strings.TrimSpace(v), "yes"), true
		}
	}
	return false, false
}

// lnxParseNTPStatus reads the same fact from the human "timedatectl status"
// on the older releases that have no show verb.
func lnxParseNTPStatus(out string) (bool, bool) {
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.ToLower(strings.TrimSpace(v))
		switch k {
		case "ntp service", "network time on", "ntp enabled":
			return v == "active" || v == "yes" || v == "on", true
		}
	}
	return false, false
}

func lnxTimeSyncFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.ToggleParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	if !hasCmd("timedatectl") {
		return "", errors.New("timedatectl is not available on this device")
	}
	val := "false"
	if p.Want() {
		val = "true"
	}
	_, stderr, _, err := runCmd(ctx, "timedatectl", "set-ntp", val)
	if err != nil {
		return "", fmt.Errorf("timedatectl set-ntp %s: %s", val, orFirst(firstLine(stderr), err.Error()))
	}
	return "timedatectl set-ntp " + val, nil
}

// ---- sysctl ----

func lnxSysctlPath(key string) string {
	return procSysRoot + "/" + strings.ReplaceAll(key, ".", "/")
}

func lnxSysctlCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.SysctlParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := p.Key + " = " + strings.TrimSpace(p.Value)
	b, err := os.ReadFile(lnxSysctlPath(p.Key))
	if err != nil {
		return blError(want, "unknown", fmt.Sprintf("%s is not readable on this device: %v", lnxSysctlPath(p.Key), err))
	}
	got := blNormSysctl(string(b))
	observed := p.Key + " = " + got
	if got == blNormSysctl(p.Value) {
		return blPass(want, observed)
	}
	return blFail(want, observed, "")
}

// blNormSysctl collapses the tabs and spaces a multi-value sysctl uses so
// "4096\t87380\t6291456" compares equal to "4096 87380 6291456".
func blNormSysctl(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func lnxSysctlFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.SysctlParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	value := blNormSysctl(p.Value)
	if !hasCmd("sysctl") {
		return "", errors.New("sysctl is not available on this device")
	}
	if _, stderr, _, err := runCmd(ctx, "sysctl", "-w", p.Key+"="+value); err != nil {
		return "", fmt.Errorf("sysctl -w %s: %s", p.Key, orFirst(firstLine(stderr), err.Error()))
	}
	if err := lnxSysctlPersist(p.Key, value); err != nil {
		return "applied at runtime", fmt.Errorf("the value was applied but not persisted: %w", err)
	}
	return fmt.Sprintf("sysctl -w %s=%s and wrote %s", p.Key, value, sysctlConfPath()), nil
}

// lnxSysctlPersist rewrites the one file the agent owns, merging the managed
// keys so two sysctl checks in the same baseline do not overwrite each
// other's line. The file is written whole, tmp+rename, because a partial
// sysctl drop-in is applied at the next boot exactly as written.
func lnxSysctlPersist(key, value string) error {
	sysctlFileMu.Lock()
	defer sysctlFileMu.Unlock()
	path := sysctlConfPath()
	managed := map[string]string{}
	if b, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			managed[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	managed[key] = value
	keys := make([]string, 0, len(managed))
	for k := range managed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString("# Managed by the Homelab RMM agent (baseline sysctl checks).\n")
	sb.WriteString("# Edits are overwritten; change the baseline instead.\n")
	for _, k := range keys {
		sb.WriteString(k + " = " + managed[k] + "\n")
	}
	if err := os.MkdirAll(sysctlConfDir, 0o755); err != nil {
		return err
	}
	return blWriteFileAtomic(path, sb.String(), "0644")
}
