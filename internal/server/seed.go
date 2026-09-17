package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// seededKey is the settings row that records that seedDefaults has run, so
// an operator who deletes a default script or rule never sees it come back.
const seededKey = "seeded"

// seedDefaults gives a fresh installation something to work with: a starter
// script library, a sensible set of alert rules, two groups and a scan-only
// patch policy. It runs once per database (guarded by the "seeded" setting)
// and, within that run, only fills tables that are still empty, so a retry
// after a partial failure cannot duplicate rows and a database created
// before seeding existed keeps whatever the operator already built.
//
// Call it after openDB and before the alert engine and scheduler are
// constructed: both read their tables once at startup.
func seedDefaults(db *DB) error {
	// Baselines carry their OWN guard key. Every v0.1.0 database already has
	// seeded=1, so hanging them off that key would mean the starter baselines
	// never appear on an upgrade - only on a database created from scratch.
	if err := seedBaselines(db); err != nil {
		return fmt.Errorf("seed baselines: %w", err)
	}
	if db.Setting(seededKey, "") == "1" {
		return nil
	}
	steps := []struct {
		name string
		fn   func(*DB) error
	}{
		{"scripts", seedScripts},
		{"alert rules", seedAlertRules},
		{"groups", seedGroups},
		{"patch policies", seedPatchPolicies},
	}
	for _, st := range steps {
		if err := st.fn(db); err != nil {
			return fmt.Errorf("seed %s: %w", st.name, err)
		}
	}
	if err := db.SetSetting(seededKey, "1"); err != nil {
		return fmt.Errorf("seed: record completion: %w", err)
	}
	slog.Info("seeded defaults", "scripts", len(allSeedScripts()), "alert_rules", len(defaultAlertRules), "groups", len(defaultGroups), "patch_policies", len(defaultPatchPolicies))
	return nil
}

// tableEmpty reports whether a table has no rows. The name is always one of
// our own constants, never user input, so string concatenation is safe here.
func tableEmpty(db *DB, table string) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		return false, err
	}
	return n == 0, nil
}

// ---- baselines ----

// seededBaselinesKey is separate from seededKey on purpose: baselines shipped
// after 0.1.0, and every database from that release already records seeded=1.
const seededBaselinesKey = "seeded_baselines"

// seedBaseline is a starter desired-state definition. Both ship DISABLED and
// NOT ENFORCED, and every destructive check in them ships with remediate off:
// a seeded baseline must never change a device before an operator has read it,
// enabled it and turned enforcement on deliberately.
type seedBaseline struct {
	Name        string
	Description string
	Targets     Targets
	IntervalSec int
	Checks      []baselineCheckInput
}

func seedBaselines(db *DB) error {
	if db.Setting(seededBaselinesKey, "") == "1" {
		return nil
	}
	empty, err := tableEmpty(db, "baselines")
	if err != nil {
		return err
	}
	if !empty {
		// An operator already has baselines: record that seeding is done
		// rather than adding ours beside theirs on every start.
		return db.SetSetting(seededBaselinesKey, "1")
	}
	for _, b := range defaultBaselines {
		in := baselineInput{Name: b.Name, Description: b.Description, Targets: b.Targets,
			IntervalSec: b.IntervalSec, Checks: b.Checks, AllowEmptyTargets: true}
		// The same validator the API uses: a typo in a seeded check must fail
		// here, not on a device.
		if err := validateBaselineInput(&in); err != nil {
			return fmt.Errorf("%q: %w", b.Name, err)
		}
		res, err := db.Exec(`INSERT INTO baselines(name, description, targets, enforce, interval_sec, notify_email, enabled, version, created_at, updated_at)
			VALUES(?,?,?,0,?,0,0,1,?,?)`, in.Name, in.Description, jsonText(in.Targets), in.IntervalSec, now(), now())
		if err != nil {
			return fmt.Errorf("%q: %w", b.Name, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		for i, c := range in.Checks {
			if _, err := db.Exec(`INSERT INTO baseline_checks(baseline_id, position, name, kind, params, remediate, severity, os_filter, timeout_sec)
				VALUES(?,?,?,?,?,?,?,?,?)`, id, i, c.Name, c.Kind, string(c.Params), c.Remediate, c.Severity, c.OSFilter, c.TimeoutSec); err != nil {
				return fmt.Errorf("%q check %q: %w", b.Name, c.Name, err)
			}
		}
	}
	slog.Info("seeded baselines", "count", len(defaultBaselines))
	return db.SetSetting(seededBaselinesKey, "1")
}

func seedParams(v string) json.RawMessage { return json.RawMessage(v) }

var defaultBaselines = []seedBaseline{
	{
		Name:        "Windows workstation hygiene",
		Description: "Firewall, time sync, SMB1, the print spooler, local administrators, pending reboots and free space on C:. Disabled and not enforced: read it, adjust it, then enable it.",
		Targets:     Targets{All: true, OS: "windows"},
		IntervalSec: 3600,
		Checks: []baselineCheckInput{
			{Name: "Windows Firewall on for all profiles", Kind: "firewall", Params: seedParams(`{"enabled":true}`), Remediate: true, Severity: "critical", OSFilter: "windows", TimeoutSec: 60},
			{Name: "Time synchronisation on", Kind: "time_sync", Params: seedParams(`{"enabled":true}`), Remediate: true, Severity: "warning", OSFilter: "windows", TimeoutSec: 60},
			// Destructive or disruptive: report only until an operator says otherwise.
			{Name: "SMB1 server disabled", Kind: "registry", Params: seedParams(`{"path":"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters","name":"SMB1","type":"dword","value":0}`), Remediate: false, Severity: "critical", OSFilter: "windows", TimeoutSec: 60},
			{Name: "Print Spooler stopped and set to manual", Kind: "service", Params: seedParams(`{"name":"Spooler","state":"stopped","start_type":"manual"}`), Remediate: false, Severity: "warning", OSFilter: "windows", TimeoutSec: 60},
			{Name: "Review members of Administrators", Kind: "group_members", Params: seedParams(`{"group":"Administrators","allowed":["Administrator"],"mode":"subset"}`), Remediate: false, Severity: "warning", OSFilter: "windows", TimeoutSec: 60},
			{Name: "No reboot pending for more than 72 hours", Kind: "reboot_pending", Params: seedParams(`{"max_hours":72,"allow_reboot":false}`), Remediate: false, Severity: "warning", OSFilter: "windows", TimeoutSec: 60},
			{Name: "C: at least 10% free", Kind: "disk_free", Params: seedParams(`{"mount":"C:","min_free_pct":10}`), Remediate: false, Severity: "warning", OSFilter: "windows", TimeoutSec: 60},
		},
	},
	{
		Name:        "Linux server hygiene",
		Description: "SSH, time sync, firewall, IP forwarding, unattended upgrades, free space and who is in sudo/wheel. Disabled and not enforced; the membership checks are report-only on purpose.",
		Targets:     Targets{All: true, OS: "linux"},
		IntervalSec: 3600,
		Checks: []baselineCheckInput{
			// The unit is ssh.service on Debian/Ubuntu and sshd.service on
			// RHEL/SUSE. Both ship at severity info, which never opens an
			// alert (A20), so the family that does not have the unit reports
			// its error quietly instead of drift-alerting the whole fleet.
			{Name: "SSH server running and enabled (Debian/Ubuntu: ssh)", Kind: "service", Params: seedParams(`{"name":"ssh","state":"running","start_type":"auto"}`), Remediate: false, Severity: "info", OSFilter: "linux", TimeoutSec: 60},
			{Name: "SSH server running and enabled (RHEL/SUSE: sshd)", Kind: "service", Params: seedParams(`{"name":"sshd","state":"running","start_type":"auto"}`), Remediate: false, Severity: "info", OSFilter: "linux", TimeoutSec: 60},
			{Name: "Time synchronisation on", Kind: "time_sync", Params: seedParams(`{"enabled":true}`), Remediate: true, Severity: "warning", OSFilter: "linux", TimeoutSec: 60},
			{Name: "Firewall on where one is installed", Kind: "firewall", Params: seedParams(`{"enabled":true}`), Remediate: true, Severity: "warning", OSFilter: "linux", TimeoutSec: 60},
			{Name: "IP forwarding off", Kind: "sysctl", Params: seedParams(`{"key":"net.ipv4.ip_forward","value":"0"}`), Remediate: true, Severity: "warning", OSFilter: "linux", TimeoutSec: 60},
			{Name: "unattended-upgrades installed (Debian/Ubuntu)", Kind: "package", Params: seedParams(`{"name":"unattended-upgrades","state":"present"}`), Remediate: false, Severity: "info", OSFilter: "linux", TimeoutSec: 120},
			{Name: "Root filesystem at least 10% free", Kind: "disk_free", Params: seedParams(`{"mount":"/","min_free_pct":10}`), Remediate: false, Severity: "warning", OSFilter: "linux", TimeoutSec: 60},
			// Report only, with an EMPTY allowed list: a shipped allow-list
			// over sudo/wheel plus one enforce toggle is a fleet-wide
			// privilege-removal button. This reports who is there; the
			// operator decides.
			{Name: "Review members of sudo (report only)", Kind: "group_members", Params: seedParams(`{"group":"sudo","allowed":[],"mode":"subset"}`), Remediate: false, Severity: "info", OSFilter: "linux", TimeoutSec: 60},
			{Name: "Review members of wheel (report only)", Kind: "group_members", Params: seedParams(`{"group":"wheel","allowed":[],"mode":"subset"}`), Remediate: false, Severity: "info", OSFilter: "linux", TimeoutSec: 60},
		},
	},
}

// allSeedScripts is the whole seeded library: the cross-platform and Linux
// entries in this file, then the Windows ones. Homelab RMM is Windows-first,
// so that half lives in its own file and is where the library grows.
func allSeedScripts() []Script {
	out := make([]Script, 0, len(defaultScripts)+len(windowsScripts))
	out = append(out, defaultScripts...)
	out = append(out, windowsScripts...)
	return out
}

func seedScripts(db *DB) error {
	empty, err := tableEmpty(db, "scripts")
	if err != nil || !empty {
		return err
	}
	for _, sc := range allSeedScripts() {
		sc := sc // SaveScript sets ID and timestamps on the copy
		if err := db.SaveScript(&sc); err != nil {
			return fmt.Errorf("%q: %w", sc.Name, err)
		}
	}
	return nil
}

func seedAlertRules(db *DB) error {
	empty, err := tableEmpty(db, "alert_rules")
	if err != nil || !empty {
		return err
	}
	for _, r := range defaultAlertRules {
		if !validRuleKinds[r.Kind] {
			return fmt.Errorf("%q: invalid kind %q", r.Name, r.Kind)
		}
		if _, err := db.Exec(`INSERT INTO alert_rules(name, kind, params, targets, severity, notify_email, auto_resolve, enabled, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			r.Name, r.Kind, jsonText(r.Params), jsonText(r.Targets), r.Severity, r.NotifyEmail, r.AutoResolve, r.Enabled, now()); err != nil {
			return fmt.Errorf("%q: %w", r.Name, err)
		}
	}
	return nil
}

func seedGroups(db *DB) error {
	empty, err := tableEmpty(db, "groups")
	if err != nil || !empty {
		return err
	}
	for _, g := range defaultGroups {
		// name is UNIQUE; OR IGNORE keeps a concurrent operator-created group intact
		if _, err := db.Exec(`INSERT OR IGNORE INTO groups(name, description, created_at) VALUES(?,?,?)`, g.Name, g.Description, now()); err != nil {
			return fmt.Errorf("%q: %w", g.Name, err)
		}
	}
	return nil
}

func seedPatchPolicies(db *DB) error {
	empty, err := tableEmpty(db, "patch_policies")
	if err != nil || !empty {
		return err
	}
	for _, p := range defaultPatchPolicies {
		for _, expr := range []string{p.ScanSchedule, p.InstallSchedule} {
			if expr != "" {
				if err := validateCron(expr); err != nil {
					return fmt.Errorf("%q: schedule %q: %w", p.Name, expr, err)
				}
			}
		}
		if _, err := db.Exec(`INSERT INTO patch_policies(name, targets, scan_schedule, install_schedule, mode, reboot, enabled, created_at) VALUES(?,?,?,?,?,?,?,?)`,
			p.Name, jsonText(p.Targets), p.ScanSchedule, p.InstallSchedule, p.Mode, p.Reboot, p.Enabled, now()); err != nil {
			return fmt.Errorf("%q: %w", p.Name, err)
		}
	}
	return nil
}

// ---- default data ----

var allDevices = Targets{All: true}

var defaultGroups = []Group{
	{Name: "Servers", Description: "Always-on machines: hypervisors, NAS, containers hosts."},
	{Name: "Workstations", Description: "Desktops and laptops that people sit at."},
}

// defaultAlertRules cover the failures a home lab actually hits. Sustained
// thresholds use ten minutes so a backup job or a compile does not page
// anyone; disk is immediate because it rarely recovers on its own.
var defaultAlertRules = []AlertRule{
	{Name: "High CPU", Kind: "cpu", Params: RuleParams{Threshold: 90, Minutes: 10}, Targets: allDevices, Severity: "warning", NotifyEmail: true, AutoResolve: true, Enabled: true},
	{Name: "High memory", Kind: "memory", Params: RuleParams{Threshold: 90, Minutes: 10}, Targets: allDevices, Severity: "warning", NotifyEmail: true, AutoResolve: true, Enabled: true},
	{Name: "Disk almost full", Kind: "disk", Params: RuleParams{Threshold: 90}, Targets: allDevices, Severity: "critical", NotifyEmail: true, AutoResolve: true, Enabled: true},
	{Name: "Device offline", Kind: "offline", Params: RuleParams{Minutes: 10}, Targets: allDevices, Severity: "warning", NotifyEmail: true, AutoResolve: true, Enabled: true},
	{Name: "Reboot required", Kind: "reboot_required", Targets: allDevices, Severity: "info", NotifyEmail: false, AutoResolve: true, Enabled: true},
	{Name: "Script failed", Kind: "script_failed", Targets: allDevices, Severity: "warning", NotifyEmail: true, AutoResolve: true, Enabled: true},
	{Name: "Patch failed", Kind: "patch_failed", Targets: allDevices, Severity: "warning", NotifyEmail: true, AutoResolve: true, Enabled: true},
}

// The default policy only scans: installing is an explicit decision the
// operator makes by approving patches or adding an install schedule.
var defaultPatchPolicies = []PatchPolicy{
	{Name: "Scan every 6 hours", Targets: allDevices, ScanSchedule: "0 */6 * * *", InstallSchedule: "", Mode: "approved", Reboot: "never", Enabled: true},
}

// Script bodies below run on real machines. Rules they follow:
//   - parameters arrive as positional arguments in declared order, and the UI
//     sends an empty string for a parameter the operator left blank, so every
//     script re-applies its default when the value is empty;
//   - PowerShell bodies avoid the backtick entirely (it cannot appear inside a
//     Go raw string) and resolve System32 tools by full path because the agent
//     runs as SYSTEM with whatever PATH the service got;
//   - bash bodies use $(...) instead of backticks and never assume a
//     particular distribution beyond GNU coreutils.
var defaultScripts = []Script{
	// ---------------------------------------------------------------- Windows
	{
		Name:        "Clear temp files and Recycle Bin",
		Description: "Deletes the contents of the system temp folder and every user's temp folder, then empties the Recycle Bin on all drives. Files that are in use are skipped.",
		Category:    "Maintenance",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  900,
		Body: `# Clear temp folders and the Recycle Bin. Files in use are skipped, not forced.
$ErrorActionPreference = 'SilentlyContinue'
$targets = New-Object System.Collections.Generic.List[string]
$targets.Add((Join-Path $env:SystemRoot 'Temp'))
Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive '\Users') -Directory -Force | ForEach-Object {
    $targets.Add((Join-Path $_.FullName 'AppData\Local\Temp'))
}
$freed = 0
$skipped = 0
foreach ($dir in $targets) {
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Recurse -Force -File)) {
        Remove-Item -LiteralPath $f.FullName -Force
        if (Test-Path -LiteralPath $f.FullName) { $skipped++ } else { $freed += $f.Length }
    }
    # remove sub-folders that are now empty, deepest first
    Get-ChildItem -LiteralPath $dir -Recurse -Force -Directory | Sort-Object { $_.FullName.Length } -Descending | ForEach-Object {
        if (-not (Get-ChildItem -LiteralPath $_.FullName -Force | Select-Object -First 1)) {
            Remove-Item -LiteralPath $_.FullName -Force
        }
    }
}
# Recycle Bin: measure, then Clear-RecycleBin (Windows 10+) with a fallback to the
# hidden $Recycle.Bin folder on each fixed drive.
$binBytes = 0
$fixed = Get-PSDrive -PSProvider FileSystem | Where-Object { $null -ne $_.Free }
foreach ($d in $fixed) {
    $bin = Join-Path $d.Root '$Recycle.Bin'
    if (Test-Path -LiteralPath $bin) {
        $binBytes += (Get-ChildItem -LiteralPath $bin -Recurse -Force -File | Measure-Object -Property Length -Sum).Sum
    }
}
if (Get-Command Clear-RecycleBin -ErrorAction SilentlyContinue) { Clear-RecycleBin -Force }
foreach ($d in $fixed) {
    $bin = Join-Path $d.Root '$Recycle.Bin'
    if (Test-Path -LiteralPath $bin) { Get-ChildItem -LiteralPath $bin -Force | Remove-Item -Recurse -Force }
}
'Temp folders: freed {0:N1} MB; {1} file(s) in use were skipped.' -f ($freed / 1MB), $skipped
'Recycle Bin: about {0:N1} MB released.' -f ($binBytes / 1MB)
`,
	},
	{
		Name:        "Restart Print Spooler",
		Description: "Stops the Print Spooler service, removes stuck jobs from the spool folder and starts the service again.",
		Category:    "Maintenance",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  120,
		Body: `# Restart the spooler and clear the queue. Stuck .SPL/.SHD files are the usual
# reason a printer "stops working".
$ErrorActionPreference = 'Stop'
Stop-Service -Name Spooler -Force
Start-Sleep -Seconds 2
$spool = Join-Path $env:SystemRoot 'System32\spool\PRINTERS'
$jobs = @(Get-ChildItem -LiteralPath $spool -File -Force -ErrorAction SilentlyContinue)
$jobs | Remove-Item -Force -ErrorAction SilentlyContinue
Start-Service -Name Spooler
$svc = Get-Service -Name Spooler
"Spooler is $($svc.Status); removed $($jobs.Count) queued file(s)."
if ($svc.Status -ne 'Running') { exit 1 }
`,
	},
	{
		Name:        "DISM and SFC health check",
		Description: "Repairs the Windows component store with DISM /RestoreHealth, then verifies protected system files with SFC /scannow. Expect 15-45 minutes; output streams as it runs.",
		Category:    "Diagnostics",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  3600,
		Body: `# DISM first so SFC has a healthy store to repair from.
$ErrorActionPreference = 'Continue'
$sys32 = Join-Path $env:SystemRoot 'System32'
Write-Output '== DISM /Online /Cleanup-Image /RestoreHealth =='
& (Join-Path $sys32 'dism.exe') /Online /Cleanup-Image /RestoreHealth /NoRestart
$dism = $LASTEXITCODE
Write-Output "DISM exit code: $dism"
Write-Output ''
Write-Output '== SFC /scannow =='
# sfc.exe writes UTF-16; without this its output arrives as letters separated by NULs.
$prev = [Console]::OutputEncoding
try { [Console]::OutputEncoding = [System.Text.Encoding]::Unicode } catch {}
& (Join-Path $sys32 'sfc.exe') /scannow | ForEach-Object { ($_ -replace '\0', '') } | Where-Object { $_.Trim() -ne '' }
$sfc = $LASTEXITCODE
try { [Console]::OutputEncoding = $prev } catch {}
Write-Output "SFC exit code: $sfc"
if ($dism -ne 0 -or $sfc -ne 0) {
    Write-Output 'A tool reported a problem; see CBS.log under Windows\Logs\CBS.'
    exit 1
}
Write-Output 'Component store and system files are healthy.'
`,
	},
	{
		Name:        "Largest folders on the system drive",
		Description: "Sizes every top-level folder of a drive (default: the system drive), lists the biggest ones and the ten largest files, and reports free space. Slow on large drives.",
		Category:    "Diagnostics",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  1800,
		Params: []ScriptParam{
			{Name: "path", Description: "Folder or drive to scan", Default: "C:\\"},
			{Name: "count", Description: "How many folders to list", Default: "10"},
		},
		Body: `param([string]$Path = '', [string]$Count = '10')
$ErrorActionPreference = 'SilentlyContinue'
if (-not $Path) { $Path = $env:SystemDrive + '\' }
$n = 0
if (-not [int]::TryParse($Count, [ref]$n) -or $n -le 0) { $n = 10 }
if (-not (Test-Path -LiteralPath $Path)) { Write-Output "Path not found: $Path"; exit 2 }
$rows = foreach ($dir in Get-ChildItem -LiteralPath $Path -Directory -Force) {
    $sum = (Get-ChildItem -LiteralPath $dir.FullName -Recurse -File -Force | Measure-Object -Property Length -Sum).Sum
    [pscustomobject]@{ 'Size (GB)' = [math]::Round(($sum / 1GB), 2); Folder = $dir.FullName }
}
"== Largest folders under $Path (top $n) =="
$rows | Sort-Object 'Size (GB)' -Descending | Select-Object -First $n | Format-Table -AutoSize | Out-String -Width 200
"== Largest files under $Path (top 10) =="
Get-ChildItem -LiteralPath $Path -Recurse -File -Force | Sort-Object Length -Descending | Select-Object -First 10 |
    ForEach-Object { '{0,10:N1} MB  {1}' -f ($_.Length / 1MB), $_.FullName }
$drive = Get-PSDrive -PSProvider FileSystem | Where-Object { $Path -like ($_.Root + '*') } | Select-Object -First 1
if ($drive) {
    ''
    'Free on {0} {1:N1} GB of {2:N1} GB' -f $drive.Root, ($drive.Free / 1GB), (($drive.Used + $drive.Free) / 1GB)
}
`,
	},
	{
		Name:        "Flush DNS and renew IP",
		Description: "Flushes the DNS resolver cache and re-registers the host in DNS. Set renew to 'yes' to also release and renew DHCP leases: the agent's connection drops for a few seconds while that happens, so the run can show as failed even though it worked.",
		Category:    "Maintenance",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  120,
		Params: []ScriptParam{
			{Name: "renew", Description: "Also release/renew DHCP leases (yes/no)", Default: "no"},
		},
		Body: `param([string]$Renew = 'no')
$ErrorActionPreference = 'Continue'
$ipconfig = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
& $ipconfig /flushdns
if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) { Clear-DnsClientCache }
& $ipconfig /registerdns
if ($Renew -match '^(y|yes|true|1)$') {
    Write-Output 'Releasing and renewing DHCP leases...'
    & $ipconfig /release | Out-Null
    & $ipconfig /renew
}
Write-Output ''
Write-Output '== IPv4 addresses =='
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike 'Loopback*' } |
    Select-Object InterfaceAlias, IPAddress, PrefixOrigin | Format-Table -AutoSize | Out-String -Width 120
`,
	},
	{
		Name:        "Windows Update history",
		Description: "Lists the most recent entries from the Windows Update history with their result (Succeeded, Failed, ...).",
		Category:    "Updates",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  120,
		Params: []ScriptParam{
			{Name: "count", Description: "Number of entries to show", Default: "20"},
		},
		Body: `param([string]$Count = '20')
$ErrorActionPreference = 'Stop'
$n = 0
if (-not [int]::TryParse($Count, [ref]$n) -or $n -le 0) { $n = 20 }
$session = New-Object -ComObject 'Microsoft.Update.Session'
$searcher = $session.CreateUpdateSearcher()
$total = $searcher.GetTotalHistoryCount()
if ($total -eq 0) { Write-Output 'No update history on this device.'; exit 0 }
$searcher.QueryHistory(0, [math]::Min($n, $total)) |
    Where-Object { $_.Title } |
    ForEach-Object {
        $result = switch ([int]$_.ResultCode) {
            1 { 'In progress' }
            2 { 'Succeeded' }
            3 { 'Succeeded with errors' }
            4 { 'Failed' }
            5 { 'Aborted' }
            default { 'Unknown' }
        }
        [pscustomobject]@{ Date = $_.Date.ToLocalTime().ToString('yyyy-MM-dd HH:mm'); Result = $result; Title = $_.Title }
    } | Format-Table -AutoSize -Wrap | Out-String -Width 200
`,
	},
	{
		Name:        "Fast Startup on/off",
		Description: "Enables or disables Windows Fast Startup (hybrid boot). Disabling it makes Shut down a real shutdown, which Wake-on-LAN and remote reboots depend on.",
		Category:    "Maintenance",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  60,
		Params: []ScriptParam{
			{Name: "mode", Description: "enable or disable", Default: "disable", Required: true},
		},
		Body: `param([string]$Mode = 'disable')
$ErrorActionPreference = 'Stop'
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
switch ($Mode.Trim().ToLower()) {
    'enable'  { $value = 1; $state = 'enabled' }
    'disable' { $value = 0; $state = 'disabled' }
    default   { Write-Output "mode must be 'enable' or 'disable' (got '$Mode')"; exit 2 }
}
Set-ItemProperty -Path $key -Name HiberbootEnabled -Value $value -Type DWord
$now = (Get-ItemProperty -Path $key -Name HiberbootEnabled).HiberbootEnabled
"Fast Startup is now $state (HiberbootEnabled=$now). Takes effect at the next shutdown."
`,
	},
	{
		Name:        "List local administrators",
		Description: "Lists every member of the local Administrators group, including domain users and nested groups. Uses the group SID so it works on non-English Windows.",
		Category:    "Security",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  60,
		Body: `# S-1-5-32-544 is Administrators on every Windows regardless of language.
$ErrorActionPreference = 'Stop'
try {
    Get-LocalGroupMember -SID 'S-1-5-32-544' |
        Select-Object Name, ObjectClass, PrincipalSource |
        Format-Table -AutoSize | Out-String -Width 200
} catch {
    # Get-LocalGroupMember fails outright when the group holds an orphaned SID;
    # ADSI still enumerates the rest.
    $name = (Get-LocalGroup -SID 'S-1-5-32-544').Name
    $group = [ADSI]"WinNT://./$name,group"
    @($group.psbase.Invoke('Members')) | ForEach-Object {
        $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null) -replace '^WinNT://', ''
    }
}
`,
	},
	{
		Name:        "Create local user",
		Description: "Creates a local user account and optionally makes it a local administrator. The password is visible in this run's arguments in the console; have the user change it at first sign-in.",
		Category:    "Users",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  60,
		Params: []ScriptParam{
			{Name: "username", Description: "Account name", Required: true},
			{Name: "password", Description: "Initial password", Required: true},
			{Name: "admin", Description: "Add to Administrators (yes/no)", Default: "no"},
			{Name: "fullname", Description: "Display name (optional)"},
		},
		Body: `param([string]$Username = '', [string]$Password = '', [string]$Admin = 'no', [string]$FullName = '')
$ErrorActionPreference = 'Stop'
if (-not $Username -or -not $Password) { Write-Output 'username and password are required.'; exit 2 }
if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) { Write-Output "User '$Username' already exists."; exit 1 }
$secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
$params = @{ Name = $Username; Password = $secure; AccountNeverExpires = $true }
if ($FullName) { $params.FullName = $FullName }
New-LocalUser @params | Out-Null
# S-1-5-32-545 = Users (localized name), so the account can sign in interactively.
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $Username -ErrorAction SilentlyContinue
if ($Admin -match '^(y|yes|true|1)$') {
    Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $Username
    Write-Output "Created '$Username' and added it to Administrators."
} else {
    Write-Output "Created '$Username' as a standard user."
}
`,
	},
	{
		Name:        "winget upgrade all",
		Description: "Upgrades every package winget can update, silently. The agent runs as SYSTEM, so winget is located inside the App Installer package when it is not on PATH.",
		Category:    "Updates",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  3600,
		Body: `$ErrorActionPreference = 'Continue'
$winget = Get-Command winget.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $winget) {
    $arch = 'x64'
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
    $apps = Join-Path $env:ProgramFiles 'WindowsApps'
    $pkg = Get-ChildItem -LiteralPath $apps -Directory -Filter "Microsoft.DesktopAppInstaller_*_${arch}__8wekyb3d8bbwe" -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($pkg) { $winget = Join-Path $pkg.FullName 'winget.exe' }
}
if (-not $winget -or -not (Test-Path -LiteralPath $winget)) {
    Write-Output 'winget is not installed (App Installer package missing).'
    exit 1
}
Write-Output "Using $winget"
& $winget upgrade --all --silent --accept-package-agreements --accept-source-agreements --disable-interactivity --include-unknown
$rc = $LASTEXITCODE
if ($rc -eq -1978335189) { Write-Output 'No applicable upgrades.'; exit 0 }   # APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE
exit $rc
`,
	},
	{
		Name:        "BitLocker status",
		Description: "Reports BitLocker protection status, encryption progress, method and key protectors for every volume.",
		Category:    "Security",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  60,
		Body: `$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    # Home editions have no BitLocker module; manage-bde still reports device encryption.
    & (Join-Path $env:SystemRoot 'System32\manage-bde.exe') -status
    exit $LASTEXITCODE
}
Get-BitLockerVolume |
    Select-Object MountPoint, VolumeType, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod,
        @{ Name = 'KeyProtectors'; Expression = { ($_.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', ' } } |
    Format-Table -AutoSize | Out-String -Width 200
`,
	},
	// ------------------------------------------------------------------ Linux
	{
		Name:        "Upgrade all packages",
		Description: "Refreshes the package index and upgrades everything with whichever package manager the system uses (apt, dnf, yum, pacman or zypper), non-interactively. Reports whether a reboot is now required.",
		Category:    "Updates",
		Language:    "bash",
		OSFilter:    "linux",
		TimeoutSec:  3600,
		Body: `#!/bin/bash
# Full upgrade with the native package manager. No set -e: the reboot check at
# the end must run even when the upgrade itself fails.
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 APT_LISTCHANGES_FRONTEND=none
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -q &&
    apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade &&
    apt-get -y -q autoremove
elif command -v dnf >/dev/null 2>&1; then
    dnf -y upgrade --refresh
elif command -v yum >/dev/null 2>&1; then
    yum -y update
elif command -v pacman >/dev/null 2>&1; then
    pacman -Syu --noconfirm
elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive refresh && zypper --non-interactive update
else
    echo "No supported package manager found (apt-get, dnf, yum, pacman, zypper)." >&2
    exit 1
fi
rc=$?
if [ -f /var/run/reboot-required ] || [ -f /run/reboot-required ]; then
    echo "Reboot required."
elif command -v needs-restarting >/dev/null 2>&1 && ! needs-restarting -r >/dev/null 2>&1; then
    echo "Reboot required."
fi
exit $rc
`,
	},
	{
		Name:        "Disk usage report",
		Description: "Shows filesystem usage, then the largest directories and files under a path (default /) to find what is filling the disk, plus any filesystem short on inodes.",
		Category:    "Diagnostics",
		Language:    "bash",
		OSFilter:    "linux",
		TimeoutSec:  900,
		Params: []ScriptParam{
			{Name: "path", Description: "Directory to analyse", Default: "/"},
			{Name: "count", Description: "How many directories to list", Default: "15"},
		},
		Body: `#!/bin/bash
set -uo pipefail
TARGET="${1:-/}"
COUNT="${2:-15}"
case "$COUNT" in ''|*[!0-9]*) COUNT=15 ;; esac
[ -d "$TARGET" ] || { echo "not a directory: $TARGET" >&2; exit 2; }
echo "== Filesystems =="
df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -h
echo
echo "== Largest directories under $TARGET (top $COUNT, same filesystem) =="
du -xh --max-depth=2 "$TARGET" 2>/dev/null | sort -rh | head -n "$COUNT"
echo
echo "== Largest files under $TARGET (top 10) =="
find "$TARGET" -xdev -type f -printf '%s\t%p\n' 2>/dev/null | sort -rn | head -n 10 |
    awk -F'\t' '{ printf "%9.1f MB  %s\n", $1 / 1048576, $2 }'
echo
echo "== Filesystems above 80% inode use =="
df -i -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR == 1 || $5 + 0 > 80'
`,
	},
	{
		Name:        "Top processes by memory",
		Description: "Memory and load summary, then the processes using the most resident memory and the most CPU.",
		Category:    "Diagnostics",
		Language:    "bash",
		OSFilter:    "linux",
		TimeoutSec:  60,
		Params: []ScriptParam{
			{Name: "count", Description: "Processes per list", Default: "15"},
		},
		Body: `#!/bin/bash
set -uo pipefail
COUNT="${1:-15}"
case "$COUNT" in ''|*[!0-9]*) COUNT=15 ;; esac
echo "== Memory =="
free -h
echo
echo "== Load =="
uptime
echo
echo "== Top $COUNT by resident memory =="
ps -eo pid,user,rss,pmem,pcpu,etime,comm --sort=-rss | head -n $((COUNT + 1)) |
    awk 'NR == 1 { printf "%7s %-14s %9s %5s %5s %12s  %s\n", "PID", "USER", "RSS", "%MEM", "%CPU", "ELAPSED", "COMMAND"; next }
         { printf "%7s %-14s %8.1fM %5s %5s %12s  %s\n", $1, $2, $3 / 1024, $4, $5, $6, $7 }'
echo
echo "== Top $COUNT by CPU =="
ps -eo pid,user,pcpu,pmem,etime,comm --sort=-pcpu | head -n $((COUNT + 1))
`,
	},
	{
		Name:        "SSH and fail2ban status",
		Description: "Shows the effective sshd settings that matter (port, root login, password auth), active SSH sessions, failed logins in the last 24 hours by source address, and fail2ban jail status.",
		Category:    "Security",
		Language:    "bash",
		OSFilter:    "linux",
		TimeoutSec:  120,
		Body: `#!/bin/bash
set -uo pipefail
echo "== sshd =="
for unit in ssh sshd; do
    state=$(systemctl is-active "$unit" 2>/dev/null) && { echo "$unit.service: $state"; break; }
done
if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | grep -iE '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|allowusers|allowgroups) ' ||
        { [ -f /etc/ssh/sshd_config ] && grep -iE '^[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries|AllowUsers|AllowGroups)[[:space:]]' /etc/ssh/sshd_config; }
else
    echo "sshd is not installed."
fi
echo
echo "== Active SSH sessions =="
who | grep -E 'pts/' || echo "(none)"
echo
echo "== Failed SSH logins, last 24 hours =="
if command -v journalctl >/dev/null 2>&1; then
    log=$(journalctl --since '24 hours ago' --no-pager -q -t sshd -t sshd-session 2>/dev/null | grep -iE 'failed password|invalid user|authentication failure')
elif [ -f /var/log/auth.log ]; then
    log=$(grep -iE 'failed password|invalid user|authentication failure' /var/log/auth.log)
else
    log=""
fi
if [ -n "$log" ]; then
    echo "total: $(printf '%s\n' "$log" | wc -l)"
    printf '%s\n' "$log" | grep -oE 'from [0-9a-fA-F.:]+' | awk '{ print $2 }' | sort | uniq -c | sort -rn | head -n 10
else
    echo "(none)"
fi
echo
echo "== fail2ban =="
if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client status 2>&1
    for jail in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do
        echo "-- $jail --"
        fail2ban-client status "$jail" 2>&1 | grep -E 'Currently (failed|banned)|Total (failed|banned)|Banned IP list'
    done
else
    echo "fail2ban is not installed."
fi
`,
	},
	{
		Name:        "Docker containers and prune",
		Description: "Lists containers, images and Docker disk usage, then removes dangling images and stopped containers that were created more than the given age ago. Set prune to 'no' to only report.",
		Category:    "Maintenance",
		Language:    "bash",
		OSFilter:    "linux",
		TimeoutSec:  600,
		Params: []ScriptParam{
			{Name: "prune", Description: "Remove dangling images and old stopped containers (yes/no)", Default: "yes"},
			{Name: "older_than", Description: "Only prune stopped containers created more than this long ago (Go duration, e.g. 168h)", Default: "168h"},
		},
		Body: `#!/bin/bash
set -uo pipefail
PRUNE="${1:-yes}"
UNTIL="${2:-168h}"
command -v docker >/dev/null 2>&1 || { echo "docker is not installed."; exit 1; }
docker info >/dev/null 2>&1 || { echo "the docker daemon is not reachable." >&2; exit 1; }
echo "== Containers =="
docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
echo
echo "== Images =="
docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}'
echo
echo "== Disk usage =="
docker system df
case "$PRUNE" in
    y|Y|yes|YES|true|1)
        echo
        echo "== Pruning stopped containers created more than $UNTIL ago, and dangling images =="
        docker container prune -f --filter "until=$UNTIL"
        docker image prune -f
        docker builder prune -f --filter "until=$UNTIL" >/dev/null 2>&1 || true
        echo
        echo "== Disk usage after prune =="
        docker system df
        ;;
    *)
        echo
        echo "(prune skipped)"
        ;;
esac
`,
	},
	{
		Name:        "Journal errors since boot",
		Description: "Failed systemd units, error-or-worse journal entries since the last boot grouped by source, and the most recent entries in full.",
		Category:    "Diagnostics",
		Language:    "bash",
		OSFilter:    "linux",
		TimeoutSec:  120,
		Params: []ScriptParam{
			{Name: "count", Description: "Recent entries to show", Default: "100"},
		},
		Body: `#!/bin/bash
set -uo pipefail
COUNT="${1:-100}"
case "$COUNT" in ''|*[!0-9]*) COUNT=100 ;; esac
if ! command -v journalctl >/dev/null 2>&1; then
    echo "journalctl is not available; showing classic logs instead"
    for f in /var/log/syslog /var/log/messages; do
        [ -f "$f" ] && grep -iE 'error|crit|fail' "$f" | tail -n "$COUNT"
    done
    exit 0
fi
echo "== Booted =="
uptime -s 2>/dev/null || who -b
echo
echo "== Failed units =="
systemctl --failed --no-pager --no-legend 2>/dev/null || echo "(systemctl unavailable)"
echo
echo "== Errors since boot by source (priority err and worse) =="
journalctl -b -p err --no-pager -q -o short-iso 2>/dev/null | awk '{ print $3 }' | sed 's/\[.*//; s/:$//' | sort | uniq -c | sort -rn | head -n 20
echo
echo "== Most recent $COUNT error entries =="
journalctl -b -p err --no-pager -q -o short-iso -n "$COUNT" 2>/dev/null
`,
	},
}
