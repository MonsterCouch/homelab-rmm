//go:build windows

package agent

// The Windows half of the check kinds: service, package, registry,
// group_members, firewall, time_sync and windows_feature. Every external tool
// is resolved through systemExe and invoked with separate arguments, and
// every name that reaches one is validated first.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/MonsterCouch/homelab-rmm/internal/baselines"
)

// winBaselineFixTimeout caps a winget transaction; the check's own timeout is
// about reading state, not about installing software (A38).
const winBaselineFixTimeout = 15 * time.Minute

func platformKind(kind string) *kindImpl {
	switch kind {
	case "service":
		return &kindImpl{check: winServiceCheck, fix: winServiceFix}
	case "package":
		return &kindImpl{check: winPackageCheck, fix: winPackageFix}
	case "registry":
		return &kindImpl{check: winRegistryCheck, fix: winRegistryFix}
	case "group_members":
		return &kindImpl{check: winGroupCheck, fix: winGroupFix}
	case "firewall":
		return &kindImpl{check: winFirewallCheck, fix: winFirewallFix}
	case "time_sync":
		return &kindImpl{check: winTimeSyncCheck, fix: winTimeSyncFix}
	case "windows_feature":
		return &kindImpl{check: winFeatureCheck, fix: winFeatureFix}
	}
	return nil
}

// blFileOwner and blStatOwner have no meaning here: mode and owner are the
// unix half of the file kind, and NTFS ACLs are not expressible as "0644".
func blFileOwner(string) (string, error) {
	return "", errors.New("file ownership is not checked on Windows")
}

func blStatOwner(os.FileInfo) (int, int, bool) { return 0, 0, false }

// ---- service ----

func winServiceState(name string) (state, startType string, err error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", "", fmt.Errorf("open service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	s, err := openService(scm, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return "", "", err
	}
	defer s.Close()
	svcOut := describeService(s, "")
	return svcOut.State, svcOut.StartType, nil
}

func winServiceCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.ServiceParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := p.State + " / " + orText(p.StartType, "any")
	if !winValidServiceName(p.Name) {
		return blError(want, "refused", fmt.Sprintf("%q is not a valid service name", p.Name))
	}
	state, startType, err := winServiceState(p.Name)
	if err != nil {
		if errors.Is(err, errServiceNotFound) {
			return blError(want, "no such service", err.Error())
		}
		return blError(want, "unknown", err.Error())
	}
	observed := state + " / " + startType
	var diffs []string
	if state != p.State {
		diffs = append(diffs, "the service is "+state)
	}
	if !winStartTypeOK(p.StartType, startType) {
		diffs = append(diffs, "the start type is "+startType)
	}
	if len(diffs) > 0 {
		return blFail(want, observed, strings.Join(diffs, "; "))
	}
	return blPass(want, observed)
}

func winServiceFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.ServiceParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	if !winValidServiceName(p.Name) {
		return "", fmt.Errorf("%q is not a valid service name", p.Name)
	}
	if blIsOwnService(p.Name) {
		return "", errOwnService
	}
	state, startType, err := winServiceState(p.Name)
	if err != nil {
		return "", err
	}
	var log []string
	if !winStartTypeOK(p.StartType, startType) {
		// A driver's start type is how the machine boots. Changing one from
		// a baseline is a way to produce an unbootable device, so it is
		// refused whatever the check says.
		if startType == "boot" || startType == "system" {
			return "", errors.New("refusing to change a boot/system start type")
		}
		action := ""
		switch p.StartType {
		case "auto":
			action = "enable"
		case "manual":
			action = "manual"
		case "disabled":
			action = "disable"
		}
		if action == "" {
			// The observed start type satisfies nothing (it reads
			// "unknown"), but the check does not say what it should be, so
			// there is nothing to apply and nothing to guess.
			return strings.Join(log, "; "), fmt.Errorf("the start type reads %q; set start_type explicitly if it should be changed", startType)
		}
		if _, err := serviceAction(p.Name, action); err != nil {
			return strings.Join(log, "; "), err
		}
		log = append(log, "set start type to "+p.StartType)
	}
	if state != p.State {
		action := "stop"
		if p.State == "running" {
			action = "start"
		}
		if _, err := serviceAction(p.Name, action); err != nil {
			return strings.Join(log, "; "), err
		}
		log = append(log, action+"ed the service")
	}
	if len(log) == 0 {
		return "", errors.New("nothing to change")
	}
	return strings.Join(log, "; "), nil
}

// ---- package ----

// winPackagePresent looks in the Uninstall hives first (which is what the
// inventory shows, so the operator sees the same answer) and falls back to
// winget when it resolves for the service account.
func winPackagePresent(ctx context.Context, name string) (bool, string, string) {
	for _, s := range installedSoftware() {
		if strings.EqualFold(strings.TrimSpace(s.Name), name) {
			return true, s.Version, "the Uninstall registry keys"
		}
	}
	exe, err := resolveWinget()
	if err != nil {
		return false, "", "the Uninstall registry keys"
	}
	wctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	stdout, _, _ := runHidden(wctx, exe, "list", "--id", name, "--exact",
		"--accept-source-agreements", "--disable-interactivity")
	if found, version := blWinWingetList(stdout, name); found {
		return true, version, "winget"
	}
	return false, "", "the Uninstall registry keys and winget"
}

func winPackageCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.PackageParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := p.State
	if p.MinVersion != "" {
		want = "present >= " + p.MinVersion
	}
	present, version, source := winPackagePresent(ctx, p.Name)
	observed := "absent"
	if present {
		observed = strings.TrimSpace("present " + version)
	}
	if p.State == "absent" {
		if present {
			return blFail(want, observed, "found through "+source)
		}
		return blPass(want, observed)
	}
	if !present {
		return blFail(want, observed, "not found through "+source)
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

// winPackageFix is refused by default. installUpdates already tells the
// operator that winget upgrades cannot be installed from the agent service
// account; a baseline that quietly tried anyway would report an error on
// every pass of every device. allow_winget is the deliberate opt-in.
func winPackageFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.PackageParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	if !p.AllowWinget {
		return "", errors.New("winget is not usable from the agent service account")
	}
	exe, err := resolveWinget()
	if err != nil {
		return "", errors.New("winget is not usable from the agent service account")
	}
	if !pkgOpMutex.TryLock() {
		return "", busyf("another package operation is in progress")
	}
	defer pkgOpMutex.Unlock()
	wctx, cancel := context.WithTimeout(ctx, winBaselineFixTimeout)
	defer cancel()
	args := []string{"install", "--id", p.Name, "--exact", "--silent",
		"--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"}
	if p.State == "absent" {
		args = []string{"uninstall", "--id", p.Name, "--exact", "--silent",
			"--accept-source-agreements", "--disable-interactivity"}
	}
	stdout, stderr, runErr := runHidden(wctx, exe, args...)
	detail := blTail(strings.TrimSpace(joinDetail(stdout, stderr)), baselines.MaxDetailBytes)
	if runErr != nil {
		return detail, fmt.Errorf("winget %s: %w", args[0], runErr)
	}
	return detail, nil
}

// ---- registry ----

func winRegRoot(path string) (registry.Key, string, error) {
	root, rest, ok := strings.Cut(path, `\`)
	if !ok {
		return 0, "", errors.New("a registry path needs a key under its root")
	}
	switch strings.ToUpper(root) {
	case "HKLM":
		return registry.LOCAL_MACHINE, rest, nil
	case "HKCU":
		// Under the SYSTEM service account this is the SERVICE's own hive,
		// not the signed-in user's; the console says so beside the field.
		return registry.CURRENT_USER, rest, nil
	}
	return 0, "", fmt.Errorf("only HKLM and HKCU are accepted, not %q", root)
}

func winRegistryCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.RegistryParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	if err := baselines.CheckRegistryPath(p.Path); err != nil {
		return blError("a safe registry path", "refused", err.Error())
	}
	wantVal, err := p.Typed()
	if err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := p.Type + " " + wantVal.Display()
	root, sub, err := winRegRoot(p.Path)
	if err != nil {
		return blError(want, "refused", err.Error())
	}
	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) || os.IsNotExist(err) {
			// A missing key is drift, not an error: that is exactly what the
			// check exists to find and, with remediation on, to create.
			return blFail(want, "the key does not exist", "")
		}
		return blError(want, "unreadable", err.Error())
	}
	defer k.Close()
	got, err := winRegRead(k, p.Name, p.Type)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return blFail(want, "the value does not exist", "")
		}
		return blError(want, "unreadable", err.Error())
	}
	observed := p.Type + " " + got.Display()
	if got.Display() == wantVal.Display() {
		return blPass(want, observed)
	}
	return blFail(want, observed, "")
}

// winRegRead reads one value with the type the check declares. An
// expand_string is read UNEXPANDED so the comparison is against what is
// stored, not against what it happens to expand to today.
func winRegRead(k registry.Key, name, kind string) (baselines.RegistryValue, error) {
	v := baselines.RegistryValue{Kind: kind}
	switch kind {
	case "dword":
		n, _, err := k.GetIntegerValue(name)
		if err != nil {
			return v, err
		}
		v.DWord = uint32(n)
		return v, nil
	case "qword":
		n, _, err := k.GetIntegerValue(name)
		if err != nil {
			return v, err
		}
		v.QWord = n
		return v, nil
	case "string", "expand_string":
		s, _, err := k.GetStringValue(name)
		if err != nil {
			return v, err
		}
		v.String = s
		return v, nil
	case "multi_string":
		ss, _, err := k.GetStringsValue(name)
		if err != nil {
			return v, err
		}
		v.Multi = ss
		return v, nil
	}
	return v, fmt.Errorf("unknown registry type %q", kind)
}

func winRegistryFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.RegistryParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	if err := baselines.CheckRegistryPath(p.Path); err != nil {
		return "", err
	}
	val, err := p.Typed()
	if err != nil {
		return "", err
	}
	root, sub, err := winRegRoot(p.Path)
	if err != nil {
		return "", err
	}
	k, _, err := registry.CreateKey(root, sub, registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("open %s for writing: %w", p.Path, err)
	}
	defer k.Close()
	switch p.Type {
	case "dword":
		err = k.SetDWordValue(p.Name, val.DWord)
	case "qword":
		err = k.SetQWordValue(p.Name, val.QWord)
	case "string":
		err = k.SetStringValue(p.Name, val.String)
	case "expand_string":
		err = k.SetExpandStringValue(p.Name, val.String)
	case "multi_string":
		err = k.SetStringsValue(p.Name, val.Multi)
	default:
		err = fmt.Errorf("unknown registry type %q", p.Type)
	}
	if err != nil {
		return "", fmt.Errorf("set %s\\%s: %w", p.Path, p.Name, err)
	}
	return fmt.Sprintf("set %s\\%s to %s", p.Path, p.Name, val.Display()), nil
}

// ---- group_members ----

func winLocalGroupMembers(ctx context.Context, group string) ([]string, error) {
	stdout, stderr, err := runHidden(ctx, "net.exe", "localgroup", group)
	if err != nil && strings.TrimSpace(stdout) == "" {
		return nil, fmt.Errorf("net localgroup %s: %s", group, winFirstLine(stderr, err.Error()))
	}
	return parseNetLocalGroup(stdout), nil
}

// winGroupGuard resolves what must never be removed: the account with the
// well-known administrator RID (500), which is not always called
// "Administrator", and the account the agent service runs as.
func winGroupGuard(members []string) groupGuard {
	g := groupGuard{Builtin: []string{"Administrator"}}
	for _, m := range members {
		sid, _, _, err := windows.LookupSID("", m)
		if err != nil {
			continue
		}
		if s := sid.String(); strings.HasSuffix(s, "-500") {
			g.Builtin = append(g.Builtin, m)
		}
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		g.Self = append(g.Self, u.Username)
		if _, bare, ok := strings.Cut(u.Username, `\`); ok && bare != "" {
			g.Self = append(g.Self, bare)
		}
	}
	return g
}

func winGroupCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.GroupMembersParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := groupExpectedLabel(p)
	members, err := winLocalGroupMembers(ctx, p.Group)
	if err != nil {
		return blError(want, "unknown", err.Error())
	}
	plan := planGroupMembers(p.Group, members, p, winGroupGuard(members))
	observed := groupObservedLabel(members)
	if !plan.Drifted(p.EffectiveMode()) {
		return blPass(want, observed)
	}
	return blFail(want, observed, groupDriftDetail(plan, p))
}

func winGroupFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.GroupMembersParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	members, err := winLocalGroupMembers(ctx, p.Group)
	if err != nil {
		return "", err
	}
	plan := planGroupMembers(p.Group, members, p, winGroupGuard(members))
	if plan.Refusal != "" {
		return "", errors.New(plan.Refusal)
	}
	if len(plan.Remove) == 0 {
		return "", errors.New("nothing can be removed: " + orText(groupDriftDetail(plan, p), "the membership already matches"))
	}
	var done []string
	for _, m := range plan.Remove {
		_, stderr, err := runHidden(ctx, "net.exe", "localgroup", p.Group, m, "/delete")
		if err != nil {
			return strings.Join(done, "; "), fmt.Errorf("removing %s from %s: %s", m, p.Group, winFirstLine(stderr, err.Error()))
		}
		done = append(done, "removed "+m)
	}
	return strings.Join(done, "; "), nil
}

// ---- firewall ----

func winFirewallCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.ToggleParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := "domain/private/public: " + strings.Join([]string{onOff(p.Want()), onOff(p.Want()), onOff(p.Want())}, "/")
	stdout, stderr, err := runHidden(ctx, "netsh.exe", "advfirewall", "show", "allprofiles")
	profiles, complete := blWinFirewallProfiles(stdout)
	if !complete {
		return blError(want, blWinFirewallLabel(profiles), winFirstLine(stderr, errString(err), "netsh did not report all three profiles"))
	}
	observed := blWinFirewallLabel(profiles)
	for _, v := range profiles {
		if v != p.Want() {
			return blFail(want, observed, "")
		}
	}
	return blPass(want, observed)
}

func winFirewallFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.ToggleParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	state := "off"
	if p.Want() {
		state = "on"
	}
	stdout, stderr, err := runHidden(ctx, "netsh.exe", "advfirewall", "set", "allprofiles", "state", state)
	if err != nil {
		return "", fmt.Errorf("netsh advfirewall set allprofiles state %s: %s", state, winFirstLine(stderr, stdout, err.Error()))
	}
	return "set all firewall profiles " + state, nil
}

// ---- time_sync ----

func winTimeSyncCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.ToggleParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := "time sync " + onOff(p.Want())
	state, _, err := winServiceState("w32time")
	if err != nil {
		if errors.Is(err, errServiceNotFound) {
			return blError(want, "no w32time service", err.Error())
		}
		return blError(want, "unknown", err.Error())
	}
	stdout, _, _ := runHidden(ctx, "w32tm.exe", "/query", "/status")
	source, synced := blWinTimeSource(stdout)
	on := state == "running" && synced
	observed := "w32time " + state
	if source != "" {
		observed += ", source " + source
	} else {
		observed += ", no source"
	}
	return blToggle(want, observed, on == p.Want())
}

func winTimeSyncFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.ToggleParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	if !p.Want() {
		if _, err := serviceAction("w32time", "stop"); err != nil {
			return "", err
		}
		return "stopped w32time", nil
	}
	var log []string
	if _, st, err := winServiceState("w32time"); err == nil && st != "auto" && st != "auto_delayed" {
		if _, err := serviceAction("w32time", "enable"); err != nil {
			return "", err
		}
		log = append(log, "set w32time to start automatically")
	}
	if _, err := serviceAction("w32time", "start"); err != nil {
		return strings.Join(log, "; "), err
	}
	log = append(log, "started w32time")
	if stdout, stderr, err := runHidden(ctx, "w32tm.exe", "/resync", "/nowait"); err != nil {
		// A resync that will not run is worth reporting, but the service is
		// up and the next check tells the truth about the source.
		log = append(log, "w32tm /resync: "+winFirstLine(stderr, stdout, err.Error()))
	} else {
		log = append(log, "asked w32time to resynchronise")
	}
	return strings.Join(log, "; "), nil
}

// ---- windows_feature ----

// winFeatureQueryScript prints one JSON object for one optional feature.
const winFeatureQueryScript = `param([string]$Name)
$ErrorActionPreference = 'Stop'
$f = Get-WindowsOptionalFeature -Online -FeatureName $Name
[pscustomobject]@{ name = $f.FeatureName; state = $f.State.ToString() } | ConvertTo-Json -Compress
`

// winFeatureApplyScript enables or disables one optional feature. -NoRestart
// always: a baseline never restarts a device as a side effect.
const winFeatureApplyScript = `param([string]$Name,[string]$Action)
$ErrorActionPreference = 'Stop'
if ($Action -eq 'enable') {
  $r = Enable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart
} else {
  $r = Disable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart
}
"restart_needed=" + $r.RestartNeeded
`

func winFeatureCheck(ctx context.Context, c *checkCtx) kindResult {
	var p baselines.WindowsFeatureParams
	if err := c.params(&p); err != nil {
		return blError("valid parameters", "invalid parameters", err.Error())
	}
	want := p.Name + " " + p.State
	stdout, stderr, err := runPowerShellScript(ctx, winFeatureQueryScript, p.Name)
	state, ok := blWinFeatureState(stdout)
	if !ok {
		return blError(want, "unknown", winFirstLine(stderr, stdout, errString(err), "Get-WindowsOptionalFeature returned nothing"))
	}
	observed := p.Name + " " + state
	if blWinFeatureEnabled(state) == (p.State == "enabled") {
		return blPass(want, observed)
	}
	return blFail(want, observed, "")
}

func winFeatureFix(ctx context.Context, c *checkCtx) (string, error) {
	var p baselines.WindowsFeatureParams
	if err := c.params(&p); err != nil {
		return "", err
	}
	action := "disable"
	if p.State == "enabled" {
		action = "enable"
	}
	if !pkgOpMutex.TryLock() {
		return "", busyf("another package operation is in progress")
	}
	defer pkgOpMutex.Unlock()
	fctx, cancel := context.WithTimeout(ctx, winBaselineFixTimeout)
	defer cancel()
	stdout, stderr, err := runPowerShellScript(fctx, winFeatureApplyScript, p.Name, action)
	detail := blTail(strings.TrimSpace(joinDetail(stdout, stderr)), baselines.MaxDetailBytes)
	if err != nil {
		return detail, fmt.Errorf("%s %s: %s", action, p.Name, winFirstLine(stderr, stdout, err.Error()))
	}
	return detail, nil
}

// errString is the Linux files' helper; the Windows build needs its own.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
