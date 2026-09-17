package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSeedBashScriptsParse runs every bash body through `bash -n`: the
// bodies are typed by hand and a stray quote would only surface on a device.
func TestSeedBashScriptsParse(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	dir := t.TempDir()
	for _, sc := range allSeedScripts() {
		if sc.Language != "bash" && sc.Language != "sh" {
			continue
		}
		file := filepath.Join(dir, "script.sh")
		if err := os.WriteFile(file, []byte(sc.Body), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bash, "-n", file).CombinedOutput(); err != nil {
			t.Errorf("%q: bash -n: %v\n%s", sc.Name, err, out)
		}
	}
}

// TestSeedPowerShellScriptsParse uses PowerShell's own parser so a syntax
// error in a Windows script is caught before it ships. pwsh is what GitHub's
// ubuntu runners have; on Windows the same parser ships as Windows PowerShell
// 5.1, and that is the platform most of this library targets, so look for
// both rather than skipping exactly where the check matters most.
func TestSeedPowerShellScriptsParse(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		pwsh, err = exec.LookPath("powershell")
	}
	if err != nil {
		t.Skip("neither pwsh nor powershell is installed")
	}
	dir := t.TempDir()
	checker := filepath.Join(dir, "check.ps1")
	const checkerBody = `param([string]$Path)
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
if ($errors) {
    $errors | ForEach-Object { Write-Output ('line {0}: {1}' -f $_.Extent.StartLineNumber, $_.Message) }
    exit 1
}
exit 0
`
	if err := os.WriteFile(checker, []byte(checkerBody), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sc := range allSeedScripts() {
		if sc.Language != "powershell" {
			continue
		}
		file := filepath.Join(dir, "script.ps1")
		if err := os.WriteFile(file, []byte(sc.Body), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", checker, "-Path", file).CombinedOutput()
		if err != nil {
			t.Errorf("%q: PowerShell parse failed: %v\n%s", sc.Name, err, out)
		}
	}
}

func countRows(t *testing.T, db *DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestSeedDefaults(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Running twice must be a no-op the second time.
	for i := 1; i <= 2; i++ {
		if err := seedDefaults(db); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if got := countRows(t, db, "scripts"); got != len(allSeedScripts()) {
			t.Fatalf("run %d: scripts = %d, want %d", i, got, len(allSeedScripts()))
		}
		if got := countRows(t, db, "alert_rules"); got != len(defaultAlertRules) {
			t.Fatalf("run %d: alert_rules = %d, want %d", i, got, len(defaultAlertRules))
		}
		if got := countRows(t, db, "groups"); got != len(defaultGroups) {
			t.Fatalf("run %d: groups = %d, want %d", i, got, len(defaultGroups))
		}
		if got := countRows(t, db, "patch_policies"); got != len(defaultPatchPolicies) {
			t.Fatalf("run %d: patch_policies = %d, want %d", i, got, len(defaultPatchPolicies))
		}
	}
	if db.Setting(seededKey, "") != "1" {
		t.Fatalf("seeded flag not set")
	}
	if len(defaultAlertRules) != 7 || len(defaultGroups) != 2 || len(defaultPatchPolicies) != 1 {
		t.Fatalf("unexpected default counts: rules=%d groups=%d policies=%d", len(defaultAlertRules), len(defaultGroups), len(defaultPatchPolicies))
	}
	if len(allSeedScripts()) < 30 {
		t.Fatalf("script library has %d entries, want at least 30", len(allSeedScripts()))
	}
}

func TestSeedRespectsOperatorDeletions(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := seedDefaults(db); err != nil {
		t.Fatal(err)
	}
	// An operator who removes the defaults must not get them back on restart.
	if _, err := db.Exec(`DELETE FROM scripts`); err != nil {
		t.Fatal(err)
	}
	if err := seedDefaults(db); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, db, "scripts"); got != 0 {
		t.Fatalf("scripts re-seeded after deletion: %d", got)
	}
	// A retry after a partial first run fills only the tables that are still
	// empty and never duplicates what is already there.
	if err := db.SetSetting(seededKey, ""); err != nil {
		t.Fatal(err)
	}
	if err := seedDefaults(db); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, db, "scripts"); got != len(allSeedScripts()) {
		t.Fatalf("empty scripts table not refilled: %d", got)
	}
	if got := countRows(t, db, "alert_rules"); got != len(defaultAlertRules) {
		t.Fatalf("alert rules duplicated: %d", got)
	}
	if got := countRows(t, db, "groups"); got != len(defaultGroups) {
		t.Fatalf("groups duplicated: %d", got)
	}
}

func TestSeedScriptsAreWellFormed(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := seedDefaults(db); err != nil {
		t.Fatal(err)
	}
	scripts, err := db.ListScripts()
	if err != nil {
		t.Fatal(err)
	}
	validOS := map[string]bool{"": true, "windows": true, "linux": true}
	validCategory := map[string]bool{"Maintenance": true, "Diagnostics": true, "Updates": true, "Security": true, "Users": true, "Software": true}
	seenName := map[string]bool{}
	seenCategory := map[string]bool{}
	for _, sc := range scripts {
		if !validLanguages[sc.Language] {
			t.Errorf("%q: invalid language %q", sc.Name, sc.Language)
		}
		if !validOS[sc.OSFilter] {
			t.Errorf("%q: invalid os_filter %q", sc.Name, sc.OSFilter)
		}
		if !validCategory[sc.Category] {
			t.Errorf("%q: unexpected category %q", sc.Name, sc.Category)
		}
		seenCategory[sc.Category] = true
		if seenName[sc.Name] {
			t.Errorf("duplicate script name %q", sc.Name)
		}
		seenName[sc.Name] = true
		if strings.TrimSpace(sc.Description) == "" || strings.TrimSpace(sc.Body) == "" {
			t.Errorf("%q: empty description or body", sc.Name)
		}
		if sc.TimeoutSec <= 0 {
			t.Errorf("%q: timeout %d", sc.Name, sc.TimeoutSec)
		}
		// The interpreter is chosen by language; the filter must agree with it
		// so a task never dispatches a PowerShell body to a Linux box.
		switch sc.Language {
		case "powershell", "cmd":
			if sc.OSFilter != "windows" {
				t.Errorf("%q: %s script must be windows-only, has %q", sc.Name, sc.Language, sc.OSFilter)
			}
		case "bash", "sh":
			if sc.OSFilter != "linux" {
				t.Errorf("%q: %s script must be linux-only, has %q", sc.Name, sc.Language, sc.OSFilter)
			}
		}
		if strings.Contains(sc.Body, "\r") {
			t.Errorf("%q: body contains carriage returns", sc.Name)
		}
		if strings.Contains(sc.Body, "`") {
			t.Errorf("%q: body contains a backtick", sc.Name)
		}
		for _, p := range sc.Params {
			if strings.TrimSpace(p.Name) == "" {
				t.Errorf("%q: parameter with empty name", sc.Name)
			}
			if p.Required && p.Default != "" && p.Name != "mode" {
				// required + default is allowed but rare; flag anything unexpected
				t.Logf("%q: required parameter %q has a default", sc.Name, p.Name)
			}
		}
		// A PowerShell script that declares params must bind them positionally.
		if sc.Language == "powershell" && len(sc.Params) > 0 && !strings.HasPrefix(sc.Body, "param(") {
			t.Errorf("%q: has params but body does not start with param(", sc.Name)
		}
	}
	for c := range validCategory {
		if !seenCategory[c] {
			t.Errorf("no script in category %q", c)
		}
	}
}

func TestSeedRulesAndPolicy(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := seedDefaults(db); err != nil {
		t.Fatal(err)
	}
	rules, err := db.ListAlertRules()
	if err != nil {
		t.Fatal(err)
	}
	validSeverity := map[string]bool{"info": true, "warning": true, "critical": true}
	kinds := map[string]bool{}
	for _, r := range rules {
		kinds[r.Kind] = true
		if !validRuleKinds[r.Kind] {
			t.Errorf("%q: invalid kind %q", r.Name, r.Kind)
		}
		if !validSeverity[r.Severity] {
			t.Errorf("%q: invalid severity %q", r.Name, r.Severity)
		}
		if !r.Targets.All {
			t.Errorf("%q: must target all devices", r.Name)
		}
		if !r.Enabled || !r.AutoResolve {
			t.Errorf("%q: must be enabled with auto-resolve", r.Name)
		}
		if r.Kind == "reboot_required" && r.NotifyEmail {
			t.Errorf("%q: reboot rule must not email", r.Name)
		}
		if r.Kind != "reboot_required" && !r.NotifyEmail {
			t.Errorf("%q: should notify by email", r.Name)
		}
		switch r.Kind {
		case "cpu", "memory":
			if r.Params.Threshold != 90 || r.Params.Minutes != 10 {
				t.Errorf("%q: want 90%% for 10 min, got %v/%d", r.Name, r.Params.Threshold, r.Params.Minutes)
			}
		case "disk":
			if r.Params.Threshold != 90 || r.Params.Mount != "" || r.Severity != "critical" {
				t.Errorf("%q: want 90%% any mount critical", r.Name)
			}
		case "offline":
			if r.Params.Minutes != 10 {
				t.Errorf("%q: want 10 min grace, got %d", r.Name, r.Params.Minutes)
			}
		}
	}
	for _, k := range []string{"cpu", "memory", "disk", "offline", "reboot_required", "script_failed", "patch_failed"} {
		if !kinds[k] {
			t.Errorf("missing default rule of kind %q", k)
		}
	}

	groups, err := db.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, g := range groups {
		names[g.Name] = true
	}
	if !names["Servers"] || !names["Workstations"] {
		t.Errorf("groups = %v, want Servers and Workstations", names)
	}

	pols, err := db.ListPatchPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) != 1 {
		t.Fatalf("policies = %d", len(pols))
	}
	p := pols[0]
	if p.Name != "Scan every 6 hours" || !p.Targets.All || !p.Enabled {
		t.Errorf("unexpected policy %+v", p)
	}
	if err := validateCron(p.ScanSchedule); err != nil {
		t.Errorf("scan schedule %q: %v", p.ScanSchedule, err)
	}
	if p.InstallSchedule != "" || p.Mode != "approved" || p.Reboot != "never" {
		t.Errorf("default policy must be scan-only: %+v", p)
	}
}
