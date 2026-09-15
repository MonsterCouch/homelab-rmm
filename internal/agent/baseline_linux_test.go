//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/baselines"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// realCheck builds a check of one kind against the live device.
func realCheck(t *testing.T, id int64, kind string, params any) (*baselineEngine, *checkCtx) {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	if err := baselines.ValidateCheck(kind, raw); err != nil {
		t.Fatalf("the test's own params do not validate: %v", err)
	}
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)
	e := newBaselineEngine(nil)
	sp := &protocol.BaselineSpec{ID: 1, Name: "t", Version: 1, IntervalSec: 3600}
	ck := &protocol.BaselineCheck{ID: id, Name: "c", Kind: kind, Params: raw, Remediate: true, TimeoutSec: 60}
	sp.Checks = []protocol.BaselineCheck{*ck}
	return e, &checkCtx{e: e, spec: sp, check: ck}
}

func ctx10(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

// ---- file ----

func TestBaselineFileKindRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rmm.conf")
	want := "PermitRootLogin no\n"

	e, c := realCheck(t, 1, "file", map[string]any{
		"path": path, "state": "present", "content": want, "mode": "0640",
	})
	impl := defaultKindImpl("file")
	if impl == nil {
		t.Fatal("the file kind must be implemented here")
	}

	// 1. absent -> fail
	if r := impl.check(ctx10(t), c); r.state != baselines.StateFail || r.observed != "absent" {
		t.Fatalf("a missing file is drift: %+v", r)
	}
	// 2. fix writes it
	detail, err := impl.fix(ctx10(t), c)
	if err != nil {
		t.Fatalf("fix: %v (%s)", err, detail)
	}
	if r := impl.check(ctx10(t), c); r.state != baselines.StatePass {
		t.Fatalf("after the fix the check must pass: %+v", r)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("content wrong: %q %v", got, err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode wrong: %v", st.Mode().Perm())
	}
	// 3. drift the content, the check sees it, the fix puts it back
	if err := os.WriteFile(path, []byte("PermitRootLogin yes\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	r := impl.check(ctx10(t), c)
	if r.state != baselines.StateFail || !strings.Contains(r.detail, "content differs") {
		t.Fatalf("drift not detected: %+v", r)
	}
	if _, err := impl.fix(ctx10(t), c); err != nil {
		t.Fatal(err)
	}
	if r := impl.check(ctx10(t), c); r.state != baselines.StatePass {
		t.Fatalf("the fix did not restore the file: %+v", r)
	}
	// 4. the whole pass through the engine reports `fixed`
	if err := os.WriteFile(path, []byte("drifted\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	sp := *c.spec
	sp.Enforce = true
	rep := e.runPass(ctx10(t), sp, baselines.TriggerSchedule, passOpts{})
	if len(rep.Results) != 1 || rep.Results[0].State != baselines.StateFixed || !rep.Results[0].Fixed {
		t.Fatalf("an enforced pass must report fixed: %+v", rep.Results)
	}
}

func TestBaselineFileKindAbsentAndSafety(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gone.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	impl := defaultKindImpl("file")
	_, c := realCheck(t, 1, "file", map[string]any{"path": path, "state": "absent"})
	if r := impl.check(ctx10(t), c); r.state != baselines.StateFail {
		t.Fatalf("a file that should be absent is drift: %+v", r)
	}
	if _, err := impl.fix(ctx10(t), c); err != nil {
		t.Fatal(err)
	}
	if r := impl.check(ctx10(t), c); r.state != baselines.StatePass {
		t.Fatalf("after removal the check passes: %+v", r)
	}

	// A directory is never removed by a file check.
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	_, c = realCheck(t, 2, "file", map[string]any{"path": sub, "state": "absent"})
	if r := impl.check(ctx10(t), c); r.state != baselines.StateError || !strings.Contains(r.detail, "directory") {
		t.Fatalf("a directory must be an error, not a deletion: %+v", r)
	}

	// A symlinked parent is refused: that is how a local attacker aims a
	// root-owned write somewhere else.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(sub, link); err != nil {
		t.Skip("symlinks are not available here:", err)
	}
	_, c = realCheck(t, 3, "file", map[string]any{"path": filepath.Join(link, "f.conf"), "state": "present", "content": "x"})
	r := impl.check(ctx10(t), c)
	if r.state != baselines.StateError || !strings.Contains(r.detail, "symbolic link") {
		t.Fatalf("a symlinked parent must be refused: %+v", r)
	}
	if _, err := impl.fix(ctx10(t), c); err == nil {
		t.Fatal("the fix must refuse the same path the check refused")
	}
	if _, err := os.Stat(filepath.Join(sub, "f.conf")); err == nil {
		t.Fatal("the refused fix wrote through the symlink anyway")
	}
}

func TestBaselineFileKindRefusesTheAgentDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)
	impl := defaultKindImpl("file")
	raw, _ := json.Marshal(map[string]any{"path": filepath.Join(dir, "agent.json"), "state": "absent"})
	sp := &protocol.BaselineSpec{ID: 1, Version: 1}
	ck := &protocol.BaselineCheck{ID: 1, Kind: "file", Params: raw, TimeoutSec: 30}
	c := &checkCtx{e: newBaselineEngine(nil), spec: sp, check: ck}
	r := impl.check(ctx10(t), c)
	if r.state != baselines.StateError || !strings.Contains(r.detail, "configuration directory") {
		t.Fatalf("the agent's own directory must be refused: %+v", r)
	}
}

// ---- command ----

func TestBaselineCommandKind(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	impl := defaultKindImpl("command")
	marker := filepath.Join(t.TempDir(), "flag")

	_, c := realCheck(t, 5, "command", map[string]any{
		"language": "bash",
		"check":    "echo \"checking $RMM_BASELINE_ID/$RMM_CHECK_ID\"\ntest -f " + marker,
		"fix":      "touch " + marker + " && echo created",
		"expected": "the marker exists",
	})
	r := impl.check(ctx10(t), c)
	if r.state != baselines.StateFail {
		t.Fatalf("a non-zero check exit is drift: %+v", r)
	}
	if r.expected != "the marker exists" {
		t.Fatalf("expected is the label the check carries: %q", r.expected)
	}
	if !strings.Contains(r.observed, "checking 1/5") {
		t.Fatalf("observed is the first stdout line, with the env the contract names: %q", r.observed)
	}
	detail, err := impl.fix(ctx10(t), c)
	if err != nil {
		t.Fatalf("fix: %v (%s)", err, detail)
	}
	if !strings.Contains(detail, "created") {
		t.Fatalf("the fix output belongs in the detail: %q", detail)
	}
	if r := impl.check(ctx10(t), c); r.state != baselines.StatePass {
		t.Fatalf("after the fix the check passes: %+v", r)
	}

	// A failing fix is an error with the stderr in the detail.
	_, c2 := realCheck(t, 6, "command", map[string]any{
		"language": "bash", "check": "exit 3", "fix": "echo nope >&2; exit 9",
	})
	d, err := impl.fix(ctx10(t), c2)
	if err == nil || !strings.Contains(err.Error(), "9") || !strings.Contains(d, "nope") {
		t.Fatalf("a failing fix must report its exit code and stderr: %v %q", err, d)
	}
}

func TestBaselineCommandKindTimesOut(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	e, c := realCheck(t, 7, "command", map[string]any{"language": "bash", "check": "sleep 30"})
	c.check.TimeoutSec = 5
	sp := *c.spec
	sp.Checks[0].TimeoutSec = 5
	start := time.Now()
	rep := e.runPass(context.Background(), sp, baselines.TriggerSchedule, passOpts{})
	if len(rep.Results) != 1 || rep.Results[0].State != baselines.StateError {
		t.Fatalf("a check that outlives its timeout is an error: %+v", rep.Results)
	}
	if !strings.Contains(rep.Results[0].Detail, "timed out") {
		t.Fatalf("the detail must say it timed out: %q", rep.Results[0].Detail)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("the timeout did not bound the script (%s)", d)
	}
}

// ---- sysctl ----

func TestBaselineSysctlKindReadsTheLiveValueAndWritesOnlyTheTestFile(t *testing.T) {
	key := "net.ipv4.ip_forward"
	live, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		t.Skip("no /proc/sys here:", err)
	}
	value := blNormSysctl(string(live))

	impl := defaultKindImpl("sysctl")
	_, c := realCheck(t, 9, "sysctl", map[string]any{"key": key, "value": value})
	if r := impl.check(ctx10(t), c); r.state != baselines.StatePass {
		t.Fatalf("the live value must compare equal to itself: %+v", r)
	}
	other := "1"
	if value == "1" {
		other = "0"
	}
	_, c2 := realCheck(t, 10, "sysctl", map[string]any{"key": key, "value": other})
	if r := impl.check(ctx10(t), c2); r.state != baselines.StateFail {
		t.Fatalf("a different value is drift: %+v", r)
	}
	_, c3 := realCheck(t, 11, "sysctl", map[string]any{"key": "net.ipv4.no_such_key_here", "value": "1"})
	if r := impl.check(ctx10(t), c3); r.state != baselines.StateError {
		t.Fatalf("an unknown key is an error, not drift: %+v", r)
	}

	// The persisted drop-in is written whole and merged, never appended, and
	// the test never touches the real /etc/sysctl.d.
	tmp := t.TempDir()
	old := sysctlConfDir
	sysctlConfDir = tmp
	defer func() { sysctlConfDir = old }()
	if err := lnxSysctlPersist("net.ipv4.ip_forward", "0"); err != nil {
		t.Fatal(err)
	}
	if err := lnxSysctlPersist("net.ipv6.conf.all.disable_ipv6", "1"); err != nil {
		t.Fatal(err)
	}
	if err := lnxSysctlPersist("net.ipv4.ip_forward", "1"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "90-homelab-rmm.conf"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Count(text, "net.ipv4.ip_forward") != 1 {
		t.Fatalf("a key must appear once, merged: %s", text)
	}
	if !strings.Contains(text, "net.ipv4.ip_forward = 1") || !strings.Contains(text, "net.ipv6.conf.all.disable_ipv6 = 1") {
		t.Fatalf("both managed keys must survive: %s", text)
	}
	if i, j := strings.Index(text, "net.ipv4"), strings.Index(text, "net.ipv6"); i > j {
		t.Fatalf("keys must be sorted so the file is stable: %s", text)
	}
}

// ---- package ----

func TestBaselinePackageKindDetectsAnInstalledPackage(t *testing.T) {
	tool := lnxPkgQueryTool()
	if tool == "" {
		t.Skip("no package query tool here")
	}
	name := ""
	for _, candidate := range []string{"coreutils", "bash", "dpkg", "glibc", "filesystem"} {
		present, _, err := lnxPkgInstalled(ctx10(t), candidate)
		if err == nil && present {
			name = candidate
			break
		}
	}
	if name == "" {
		t.Skip("none of the probe packages is installed")
	}
	impl := defaultKindImpl("package")
	_, c := realCheck(t, 12, "package", map[string]any{"name": name, "state": "present"})
	r := impl.check(ctx10(t), c)
	if r.state != baselines.StatePass || !strings.HasPrefix(r.observed, "present") {
		t.Fatalf("%s is installed: %+v", name, r)
	}
	_, c2 := realCheck(t, 13, "package", map[string]any{"name": name, "state": "absent"})
	if r := impl.check(ctx10(t), c2); r.state != baselines.StateFail {
		t.Fatalf("an installed package that should be absent is drift: %+v", r)
	}
	_, c3 := realCheck(t, 14, "package", map[string]any{"name": "rmm-no-such-package", "state": "present"})
	if r := impl.check(ctx10(t), c3); r.state != baselines.StateFail || r.observed != "absent" {
		t.Fatalf("a missing package is drift, not an error: %+v", r)
	}
	// min_version against a version that cannot be parsed is an error, never
	// a drift that would "self-heal" by installing something.
	_, c4 := realCheck(t, 15, "package", map[string]any{"name": name, "state": "present", "min_version": "9999.0"})
	if r := impl.check(ctx10(t), c4); r.state != baselines.StateFail && r.state != baselines.StateError {
		t.Fatalf("an impossible min_version is drift or an error, not a pass: %+v", r)
	}
}

// ---- group_members ----

func TestBaselineGroupMembersReadsTheRealGroupFile(t *testing.T) {
	b, err := os.ReadFile("/etc/group")
	if err != nil {
		t.Skip("no /etc/group here")
	}
	// Pick a group that exists on this device.
	group := ""
	for _, line := range strings.Split(string(b), "\n") {
		if n, _, _, ok := parseGroupLine(line); ok && n == "root" {
			group = n
			break
		}
	}
	if group == "" {
		t.Skip("no root group on this device")
	}
	members, primary, err := lnxGroupMembers(ctx10(t), group)
	if err != nil {
		t.Fatalf("reading %s: %v", group, err)
	}
	all := append(append([]string{}, members...), primary...)
	if len(all) == 0 {
		t.Skip("the root group has no members here")
	}

	// The check itself, against the live device: an allow-list of exactly
	// what is there must pass.
	impl := defaultKindImpl("group_members")
	_, c := realCheck(t, 16, "group_members", map[string]any{"group": group, "allowed": all, "mode": "subset"})
	if r := impl.check(ctx10(t), c); r.state != baselines.StatePass {
		t.Fatalf("an allow-list of the observed membership must pass: %+v", r)
	}

	// And an EMPTY allow-list is drift - but the planner must refuse to act
	// on it, because removing everyone from root is not a remediation. This
	// is asserted on the plan, never by running gpasswd.
	p := baselines.GroupMembersParams{Group: group, Allowed: nil, Mode: "subset"}
	plan := planGroupMembers(group, all, p, lnxGroupGuard(primary))
	if !plan.Drifted(p.EffectiveMode()) {
		t.Fatal("an empty allow-list over a populated group is drift")
	}
	if len(plan.Remove) != 0 {
		t.Fatalf("nothing may be removed from %s: %+v", group, plan.Remove)
	}
	if plan.Refusal == "" && len(plan.Kept) == 0 {
		t.Fatalf("the refusal must be explicit: %+v", plan)
	}
	_, c2 := realCheck(t, 17, "group_members", map[string]any{"group": group, "allowed": []string{}, "mode": "subset"})
	if r := impl.check(ctx10(t), c2); r.state != baselines.StateFail {
		t.Fatalf("an empty allow-list is reported as drift: %+v", r)
	}
	if _, err := impl.fix(ctx10(t), c2); err == nil {
		t.Fatal("the fix must refuse rather than empty the root group")
	}

	// A group that does not exist is an error, not silent drift.
	_, c3 := realCheck(t, 18, "group_members", map[string]any{"group": "rmmnosuchgroup"})
	if r := impl.check(ctx10(t), c3); r.state != baselines.StateError {
		t.Fatalf("a missing group is an error: %+v", r)
	}
}

func TestBaselineGroupPlanSafetyRules(t *testing.T) {
	p := baselines.GroupMembersParams{Group: "Administrators", Allowed: []string{"rmm-admin"}}
	g := groupGuard{Builtin: []string{"Administrator"}, Self: []string{"svc-rmm"}, Primary: []string{"pinned"}}
	plan := planGroupMembers("Administrators", []string{"Administrator", "svc-rmm", "pinned", `CORP\jdoe`, "eve", "rmm-admin"}, p, g)
	if len(plan.Remove) != 1 || plan.Remove[0] != "eve" {
		t.Fatalf("only the ordinary extra account may be removed: %+v", plan.Remove)
	}
	for _, kept := range []string{"Administrator", "svc-rmm", "pinned", `CORP\jdoe`} {
		if !inFold(plan.Kept, kept) {
			t.Fatalf("%s must be kept: %+v", kept, plan.Kept)
		}
		if plan.Reasons[kept] == "" {
			t.Fatalf("%s must carry a reason", kept)
		}
	}
	// allow_domain opts the domain principal in.
	p.AllowDomain = true
	plan = planGroupMembers("Administrators", []string{"Administrator", `CORP\jdoe`, "rmm-admin"}, p, g)
	if len(plan.Remove) != 1 || plan.Remove[0] != `CORP\jdoe` {
		t.Fatalf("allow_domain must make the domain account removable: %+v", plan.Remove)
	}
	// Emptying a critical group is refused wholesale.
	plan = planGroupMembers("sudo", []string{"eve", "mallory"}, baselines.GroupMembersParams{Group: "sudo"}, groupGuard{})
	if plan.Refusal == "" || len(plan.Remove) != 0 {
		t.Fatalf("emptying sudo must be refused: %+v", plan)
	}
	// A non-critical group may be emptied.
	plan = planGroupMembers("docker", []string{"eve"}, baselines.GroupMembersParams{Group: "docker"}, groupGuard{})
	if plan.Refusal != "" || len(plan.Remove) != 1 {
		t.Fatalf("docker is not a critical group: %+v", plan)
	}
	// exact mode reports missing members and never adds them.
	plan = planGroupMembers("docker", []string{"eve"}, baselines.GroupMembersParams{Group: "docker", Allowed: []string{"alice"}, Mode: "exact"}, groupGuard{})
	if len(plan.Missing) != 1 || plan.Missing[0] != "alice" {
		t.Fatalf("exact mode must report the missing member: %+v", plan)
	}
	if !plan.Drifted("exact") {
		t.Fatal("a missing member is drift in exact mode")
	}
	if plan.Drifted("subset") == false {
		t.Fatal("eve is an extra in both modes")
	}
	// subset mode ignores missing members entirely.
	plan = planGroupMembers("docker", nil, baselines.GroupMembersParams{Group: "docker", Allowed: []string{"alice"}}, groupGuard{})
	if plan.Drifted("subset") {
		t.Fatalf("subset mode never asks for a member to be added: %+v", plan)
	}
}

// ---- disk_free ----

func TestBaselineDiskFreeKind(t *testing.T) {
	impl := defaultKindImpl("disk_free")
	_, c := realCheck(t, 20, "disk_free", map[string]any{"mount": "/", "min_free_pct": 0.0001})
	r := impl.check(ctx10(t), c)
	if r.state != baselines.StatePass {
		t.Fatalf("the root filesystem has some free space: %+v", r)
	}
	if !strings.Contains(r.observed, "free") {
		t.Fatalf("observed must say how much is free: %q", r.observed)
	}
	_, c2 := realCheck(t, 21, "disk_free", map[string]any{"mount": "/", "min_free_pct": 99.99})
	if r := impl.check(ctx10(t), c2); r.state != baselines.StateFail {
		t.Fatalf("99.99%% free is drift on any real device: %+v", r)
	}
	_, c3 := realCheck(t, 22, "disk_free", map[string]any{"mount": "/rmm-no-such-mount", "min_free_pct": 10})
	if r := impl.check(ctx10(t), c3); r.state != baselines.StateError {
		t.Fatalf("an unknown mount is an error, not drift: %+v", r)
	}
	if blNormaliseMount("srv") != "/srv" || blNormaliseMount("/srv/") != "/srv" {
		t.Fatal("mount normalisation is wrong")
	}
}

// ---- reboot_pending ----

func TestBaselineRebootPendingKind(t *testing.T) {
	impl := defaultKindImpl("reboot_pending")
	e, c := realCheck(t, 23, "reboot_pending", map[string]any{"max_hours": 72, "allow_reboot": false})
	r := impl.check(ctx10(t), c)
	if r.state != baselines.StatePass && r.state != baselines.StateFail {
		t.Fatalf("reboot_pending answers pass or fail, got %+v", r)
	}
	// With allow_reboot off the kind vetoes its own fix, so the engine can
	// never restart the machine this test is running on.
	if ok, why := impl.fixable(c); ok || !strings.Contains(why, "allow_reboot") {
		t.Fatalf("allow_reboot off must veto the fix: %v %q", ok, why)
	}
	sp := *c.spec
	sp.Enforce = true
	rep := e.runPass(ctx10(t), sp, baselines.TriggerSchedule, passOpts{})
	if rep.Results[0].Fixed {
		t.Fatal("the engine must not have restarted anything")
	}
}

// ---- firewall and time_sync degrade rather than lie ----

func TestBaselineFirewallAndTimeSyncDegrade(t *testing.T) {
	impl := defaultKindImpl("firewall")
	_, c := realCheck(t, 24, "firewall", map[string]any{"enabled": true})
	r := impl.check(ctx10(t), c)
	switch r.state {
	case baselines.StateSkipped:
		if r.observed != "no supported firewall" {
			t.Fatalf("the skip must say why: %q", r.observed)
		}
	case baselines.StatePass, baselines.StateFail, baselines.StateError:
	default:
		t.Fatalf("unexpected state %+v", r)
	}
	impl = defaultKindImpl("time_sync")
	_, c = realCheck(t, 25, "time_sync", map[string]any{"enabled": true})
	r = impl.check(ctx10(t), c)
	if !baselines.ValidState(r.state) {
		t.Fatalf("time_sync returned an unknown state: %+v", r)
	}
}

// ---- service ----

func TestBaselineServiceKindOnThisDevice(t *testing.T) {
	if !hasCmd("systemctl") {
		t.Skip("no systemd here")
	}
	impl := defaultKindImpl("service")
	_, c := realCheck(t, 26, "service", map[string]any{"name": "rmm-no-such-unit", "state": "running"})
	r := impl.check(ctx10(t), c)
	if r.state != baselines.StateError {
		t.Fatalf("a unit that does not exist is an error, not a fleet-wide drift alert: %+v", r)
	}
	if !strings.Contains(r.detail, "rmm-no-such-unit") {
		t.Fatalf("the detail must name the unit: %q", r.detail)
	}
	// start_type manual is check-only on Linux.
	_, c2 := realCheck(t, 27, "service", map[string]any{"name": "rmm-no-such-unit", "state": "running", "start_type": "manual"})
	if _, err := impl.fix(ctx10(t), c2); err == nil {
		t.Fatal("a fix against a missing unit must fail")
	}
}

// ---- fresh-eyes verification (2026-09-15) ----

// The device-side half of "a group_members check can never lock the operator
// out". It runs the REAL reader over the REAL /etc/group for every critical
// group this box has, with the most dangerous check anyone can write - an
// empty allow list, remediation on - and asserts on the PLAN. Nothing here
// runs gpasswd; the group file is hashed before and after to prove it.
func TestBaselineGroupEmptyAllowListNeverStripsACriticalGroup(t *testing.T) {
	before, err := os.ReadFile("/etc/group")
	if err != nil {
		t.Skip("no /etc/group here")
	}
	tried := 0
	for _, group := range []string{"root", "sudo", "wheel", "adm", "shadow"} {
		members, primary, err := lnxGroupMembers(ctx10(t), group)
		if err != nil {
			continue // not a group on this device
		}
		all := append(append([]string{}, members...), primary...)
		if len(all) == 0 {
			continue
		}
		tried++
		for _, mode := range []string{"subset", "exact"} {
			p := baselines.GroupMembersParams{Group: group, Allowed: nil, Mode: mode}
			plan := planGroupMembers(group, all, p, lnxGroupGuard(primary))
			if !plan.Drifted(p.EffectiveMode()) {
				t.Fatalf("%s/%s: an empty allow list over %v is drift", group, mode, all)
			}
			for _, r := range plan.Remove {
				if strings.EqualFold(r, "root") {
					t.Fatalf("%s/%s: root is never removable: %+v", group, mode, plan)
				}
			}
			if criticalGroups[group] && len(plan.Remove) > 0 {
				t.Fatalf("%s/%s: a critical group would be stripped to %d members: %+v",
					group, mode, len(all)-len(plan.Remove), plan)
			}
			if criticalGroups[group] && plan.Refusal == "" && len(plan.Kept) == 0 {
				t.Fatalf("%s/%s: nothing was removed and nothing says why: %+v", group, mode, plan)
			}
			// The check itself, end to end on this device, reports drift and
			// claims no fix.
			_, c := realCheck(t, 900, "group_members", map[string]any{"group": group, "allowed": []string{}, "mode": mode})
			if r := defaultKindImpl("group_members").check(ctx10(t), c); r.state != baselines.StateFail {
				t.Fatalf("%s/%s: the check must report drift: %+v", group, mode, r)
			}
		}
	}
	if tried == 0 {
		t.Skip("no populated critical group on this device")
	}
	after, err := os.ReadFile("/etc/group")
	if err != nil || string(after) != string(before) {
		t.Fatalf("/etc/group changed during a read-only test (err %v)", err)
	}
}

// The agent re-validates the path itself: the server's 400 is the first of
// two refusals, not the only one. A spec that reached the device anyway - an
// older server, a rolled-back database, a hostile one - is refused here.
func TestBaselineFilePathIsRefusedOnTheDeviceToo(t *testing.T) {
	impl := defaultKindImpl("file")
	sp := &protocol.BaselineSpec{ID: 1, Version: 1}
	for _, path := range []string{
		"etc/passwd",                    // relative
		"../../etc/shadow",              // climbs
		"/etc/../etc/shadow",            // climbs to a denied file
		"/etc/foo/../../root/.ssh/keys", // climbs out of /etc
		"/etc/shadow",                   // who is root
		"/etc/sudoers",                  // who is root
		"/proc/sys/kernel/core_pattern", // not a real file tree
		`C:\Windows\System32\cmd.exe`,   // not this platform's path style
		"",                              // nothing at all
	} {
		raw, _ := json.Marshal(map[string]any{"path": path, "state": "present", "content": "x\n"})
		ck := &protocol.BaselineCheck{ID: 1, Kind: "file", Params: raw, TimeoutSec: 30}
		c := &checkCtx{e: newBaselineEngine(nil), spec: sp, check: ck}
		r := impl.check(ctx10(t), c)
		if r.state != baselines.StateError {
			t.Fatalf("path %q must be an error on the device, got %+v", path, r)
		}
		if _, err := impl.fix(ctx10(t), c); err == nil {
			t.Fatalf("path %q: the fix must refuse what the check refused", path)
		}
	}
}
