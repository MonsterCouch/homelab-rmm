package server

// windowsScripts is the Windows half of the seeded library. Homelab RMM is
// Windows-first, so this is where the library grows; the cross-platform and
// Linux entries stay in seed.go beside the alert rules and baselines they were
// written with.
//
// Rules every script here follows, because they run as SYSTEM on machines the
// operator may not be sitting at:
//
//   - Anything destructive is report-only until a parameter says otherwise.
//     The default run of every script in this file is safe to fire at the whole
//     fleet.
//   - Output is meant to be read in the run log, so sections are headed
//     "== Section ==" and tables are rendered rather than dumped as objects.
//   - A script that could not do its job exits non-zero, so the run is marked
//     failed and the script-failure alert rule sees it.
//   - No script reboots, and none installs anything the operator did not name.
var windowsScripts = []Script{
	// ------------------------------------------------------------ Diagnostics
	{
		Name:        "System health summary",
		Description: "One-page overview of a device: uptime and last boot, pending reboot and why, CPU and memory pressure, free space on every fixed disk, and the five processes using the most memory. The first thing to run when someone says a machine is slow.",
		Category:    "Diagnostics",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  180,
		Body: `$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
"== Identity =="
"{0}  ({1} {2})" -f $env:COMPUTERNAME, $cs.Manufacturer, $cs.Model
"{0}  build {1}" -f $os.Caption, $os.BuildNumber

""
"== Uptime =="
$boot = $os.LastBootUpTime
$up = (Get-Date) - $boot
"last boot : {0:yyyy-MM-dd HH:mm}" -f $boot
"uptime    : {0}d {1}h {2}m" -f $up.Days, $up.Hours, $up.Minutes
if ($up.TotalDays -gt 30) { "note      : up for over 30 days; updates may be waiting on a restart" }

""
"== Pending reboot =="
$reasons = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'servicing (CBS)' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) { $reasons += 'pending file renames' }
if ($reasons) { "REBOOT PENDING: " + ($reasons -join ', ') } else { "none" }

""
"== Memory =="
$totalMB = [math]::Round($os.TotalVisibleMemorySize / 1KB)
$freeMB  = [math]::Round($os.FreePhysicalMemory / 1KB)
"total {0} MB, free {1} MB ({2}% used)" -f $totalMB, $freeMB, [math]::Round(100 - ($freeMB / $totalMB * 100))

""
"== CPU =="
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
"load {0}%  ({1})" -f $cpu, (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)

""
"== Fixed disks =="
Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    $pct = if ($_.Size) { [math]::Round($_.FreeSpace / $_.Size * 100) } else { 0 }
    $flag = if ($pct -lt 10) { '  LOW' } else { '' }
    "{0}  {1} GB free of {2} GB  ({3}% free){4}" -f $_.DeviceID,
        [math]::Round($_.FreeSpace / 1GB, 1), [math]::Round($_.Size / 1GB, 1), $pct, $flag
}

""
"== Top 5 processes by memory =="
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 |
    ForEach-Object { "{0,-30} {1,8:N0} MB" -f $_.ProcessName, ($_.WorkingSet64 / 1MB) }
`,
	},
	{
		Name:        "Recent event log errors",
		Description: "Errors and critical events from the System and Application logs, grouped by source and event id with a count and the most recent message. Turns 'check the event log' into a short list of what is actually recurring.",
		Category:    "Diagnostics",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  300,
		Params: []ScriptParam{
			{Name: "hours", Description: "How far back to look", Default: "24"},
			{Name: "log", Description: "System, Application, or both", Default: "both"},
		},
		Body: `param([string]$Hours = '24', [string]$Log = 'both')
$ErrorActionPreference = 'SilentlyContinue'
$h = 24; [void][int]::TryParse($Hours, [ref]$h); if ($h -le 0) { $h = 24 }
$logs = switch ($Log.ToLower()) { 'system' { @('System') } 'application' { @('Application') } default { @('System','Application') } }
$since = (Get-Date).AddHours(-$h)
$any = $false
foreach ($l in $logs) {
    # Level 1 = Critical, 2 = Error.
    $events = Get-WinEvent -FilterHashtable @{LogName=$l; Level=1,2; StartTime=$since} -ErrorAction SilentlyContinue
    "== $l : last $h h =="
    if (-not $events) { "no errors"; "" ; continue }
    $any = $true
    $events | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
        $newest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $msg = ($newest.Message -replace '\s+', ' ')
        if ($msg.Length -gt 160) { $msg = $msg.Substring(0, 160) + '...' }
        "{0,4}x  {1} (id {2})" -f $_.Count, $newest.ProviderName, $newest.Id
        "      last {0:yyyy-MM-dd HH:mm}: {1}" -f $newest.TimeCreated, $msg
    }
    ""
}
if (-not $any) { "Nothing to report." }
`,
	},
	{
		Name:        "Network connectivity test",
		Description: "Walks the path outward: active adapter and address, default gateway, DNS servers and whether they resolve, then latency to the gateway and to the internet. Says which hop failed rather than just 'no internet'.",
		Category:    "Diagnostics",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  180,
		Params: []ScriptParam{
			{Name: "target", Description: "Host to test reachability against", Default: "1.1.1.1"},
			{Name: "resolve", Description: "Name to resolve as a DNS check", Default: "www.microsoft.com"},
		},
		Body: `param([string]$Target = '1.1.1.1', [string]$Resolve = 'www.microsoft.com')
$ErrorActionPreference = 'SilentlyContinue'
if (-not $Target) { $Target = '1.1.1.1' }
if (-not $Resolve) { $Resolve = 'www.microsoft.com' }
$failed = 0

"== Adapters that are up =="
$up = Get-NetAdapter | Where-Object Status -eq 'Up'
if (-not $up) { "NONE - the device has no connected network adapter"; exit 1 }
$up | ForEach-Object {
    $ips = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4).IPAddress -join ', '
    "{0,-28} {1,8} Mbps  {2}" -f $_.Name, [math]::Round($_.LinkSpeed / 1e6), $ips
}

""
"== Default gateway =="
$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
if (-not $gw) { "NONE - no default route"; $failed++ } else {
    $ok = Test-Connection -ComputerName $gw -Count 2 -Quiet
    "{0}  {1}" -f $gw, $(if ($ok) { 'reachable' } else { 'UNREACHABLE'; $failed++ })
}

""
"== DNS =="
$servers = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses }).ServerAddresses | Select-Object -Unique
if (-not $servers) { "no DNS servers configured"; $failed++ } else { $servers | ForEach-Object { "server $_" } }
$r = Resolve-DnsName -Name $Resolve -Type A -ErrorAction SilentlyContinue
if ($r) { "resolved $Resolve -> " + (($r | Where-Object IPAddress).IPAddress -join ', ') }
else { "FAILED to resolve $Resolve"; $failed++ }

""
"== Reachability =="
$p = Test-Connection -ComputerName $Target -Count 4 -ErrorAction SilentlyContinue
if ($p) {
    $avg = [math]::Round(($p | Measure-Object -Property ResponseTime -Average).Average)
    "$Target reachable, average {0} ms" -f $avg
} else { "$Target UNREACHABLE"; $failed++ }

""
"== Result =="
if ($failed -eq 0) { "All checks passed." } else { "$failed check(s) failed."; exit 1 }
`,
	},
	{
		Name:        "Battery and power report",
		Description: "Battery wear on a laptop: design capacity against what it now charges to, cycle count where the firmware reports it, and the current power plan. Wear above about 30% is the usual answer to 'it does not last any more'. Reports cleanly on a desktop with no battery.",
		Category:    "Diagnostics",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  180,
		Body: `$ErrorActionPreference = 'SilentlyContinue'
$bat = Get-CimInstance Win32_Battery
if (-not $bat) { "No battery: this device is not running on one."; exit 0 }

"== Battery =="
$bat | ForEach-Object { "{0}  status {1}  charge {2}%" -f $_.Name, $_.BatteryStatus, $_.EstimatedChargeRemaining }

"== Capacity =="
$full = Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity
$spec = Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData
if ($full -and $spec) {
    $f = ($full | Select-Object -First 1).FullChargedCapacity
    $d = ($spec | Select-Object -First 1).DesignedCapacity
    if ($d -gt 0) {
        $wear = [math]::Round(100 - ($f / $d * 100), 1)
        "design         : {0} mWh" -f $d
        "full charge now: {0} mWh" -f $f
        "wear           : {0}%" -f $wear
        if ($wear -ge 30) { "NOTE: over 30% wear; runtime will be noticeably short and a replacement is reasonable." }
    }
} else { "The firmware does not expose capacity data through WMI." }

""
"== Power plan =="
powercfg /getactivescheme
`,
	},
	{
		Name:        "Problem devices",
		Description: "Hardware Windows is unhappy about: every device with a Device Manager error code, what the code means, and the driver in use. The quick answer to a missing camera, dead Wi-Fi or a yellow triangle after an update.",
		Category:    "Diagnostics",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  180,
		Body: `$ErrorActionPreference = 'SilentlyContinue'
$meanings = @{
    1='not configured correctly'; 3='driver may be corrupted, or low memory'; 10='cannot start'
    12='cannot find enough free resources'; 14='needs a restart'; 16='cannot identify all resources'
    18='drivers need reinstalling'; 19='registry configuration is corrupt'; 21='being removed'
    22='disabled'; 24='not present, not working properly, or missing a driver'
    28='drivers are not installed'; 31='Windows cannot load the driver'; 43='the driver reported a failure'
    45='not currently connected'
}
$bad = Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
if (-not $bad) { "No problem devices: every device reports error code 0."; exit 0 }
"== Problem devices =="
foreach ($d in $bad) {
    $code = $d.ConfigManagerErrorCode
    $what = if ($meanings.ContainsKey([int]$code)) { $meanings[[int]$code] } else { 'unknown error code' }
    "{0}" -f $d.Name
    "    code {0}: {1}" -f $code, $what
    "    id   {0}" -f $d.PNPDeviceID
}
""
"{0} device(s) report a problem. Many codes are benign (45 = not currently connected)," -f @($bad).Count
"so this reports rather than failing the run; alert on it with a baseline if it matters."
`,
	},
	{
		Name:        "Disk health and SMART",
		Description: "Physical disk health as the firmware reports it: health status, media type, wear on an SSD and reallocated sectors or read errors where the disk exposes them. Catches a failing drive before the data goes.",
		Category:    "Diagnostics",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  300,
		Body: `$ErrorActionPreference = 'SilentlyContinue'
$disks = Get-PhysicalDisk
if (-not $disks) { "Get-PhysicalDisk returned nothing; this device may use a controller the Storage stack does not enumerate."; exit 1 }
$bad = 0
foreach ($d in $disks) {
    "== {0} ==" -f $d.FriendlyName
    "size        : {0} GB" -f [math]::Round($d.Size / 1GB)
    "media       : {0}" -f $d.MediaType
    "bus         : {0}" -f $d.BusType
    "health      : {0}" -f $d.HealthStatus
    "operational : {0}" -f ($d.OperationalStatus -join ', ')
    if ($d.HealthStatus -ne 'Healthy') { $bad++ }
    $c = $d | Get-StorageReliabilityCounter
    if ($c) {
        if ($null -ne $c.Wear)             { "wear        : {0}%" -f $c.Wear }
        if ($null -ne $c.Temperature)      { "temperature : {0} C" -f $c.Temperature }
        if ($c.ReadErrorsUncorrected)      { "UNCORRECTED READ ERRORS: {0}" -f $c.ReadErrorsUncorrected; $bad++ }
        if ($c.WriteErrorsUncorrected)     { "UNCORRECTED WRITE ERRORS: {0}" -f $c.WriteErrorsUncorrected; $bad++ }
        if ($c.PowerOnHours)               { "power on    : {0} hours" -f $c.PowerOnHours }
    }
    ""
}
if ($bad -gt 0) { "$bad problem(s) found - back the device up before doing anything else."; exit 1 }
"All disks report healthy."
`,
	},
	{
		Name:        "Startup programs",
		Description: "Everything set to run at sign-in, from the Run keys, the Startup folders and logon scheduled tasks, with the command each one runs. The list to read when a machine takes minutes to become usable.",
		Category:    "Diagnostics",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  180,
		Body: `$ErrorActionPreference = 'SilentlyContinue'
"== Run keys =="
$keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($k in $keys) {
    $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if (-not $p) { continue }
    $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
        "{0}" + [Environment]::NewLine + "    {1}" + [Environment]::NewLine + "    [{2}]" -f $_.Name, $_.Value, $k
    }
}

""
"== Startup folders =="
@(
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'),
    (Join-Path $env:AppData 'Microsoft\Windows\Start Menu\Programs\StartUp')
) | ForEach-Object {
    Get-ChildItem -LiteralPath $_ -File -ErrorAction SilentlyContinue | ForEach-Object { "{0}" + [Environment]::NewLine + "    [{1}]" -f $_.Name, $_.DirectoryName }
}

""
"== Scheduled tasks that run at logon =="
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and ($_.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' }) } |
    ForEach-Object {
        $act = ($_.Actions | ForEach-Object { $_.Execute }) -join '; '
        "{0}{1}" + [Environment]::NewLine + "    {2}" -f $_.TaskPath, $_.TaskName, $act
    }
`,
	},
	{
		Name:        "Windows activation status",
		Description: "Whether Windows is licensed, by what channel, and how long any grace period has left. Answers the 'activate Windows' watermark without a trip to Settings.",
		Category:    "Diagnostics",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  120,
		Body: `$ErrorActionPreference = 'SilentlyContinue'
$states = @{0='Unlicensed';1='Licensed';2='Out-of-box grace';3='Out-of-tolerance grace';4='Non-genuine grace';5='Notification';6='Extended grace'}
$p = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND Name LIKE 'Windows%'"
if (-not $p) { "No licensed Windows product found with a product key installed."; exit 1 }
foreach ($x in $p) {
    "== {0} ==" -f $x.Name
    "description : {0}" -f $x.Description
    "partial key : {0}" -f $x.PartialProductKey
    $s = [int]$x.LicenseStatus
    "status      : {0} ({1})" -f $s, $(if ($states.ContainsKey($s)) { $states[$s] } else { 'unknown' })
    if ($x.GracePeriodRemaining -gt 0) { "grace left  : {0} days" -f [math]::Round($x.GracePeriodRemaining / 1440) }
    ""
}
$lic = $p | Where-Object { $_.LicenseStatus -eq 1 }
if (-not $lic) { "Windows is NOT in a licensed state."; exit 1 }
"Windows is licensed."
`,
	},

	// ------------------------------------------------------------ Maintenance
	{
		Name:        "Restart a service",
		Description: "Restarts a named service and reports what happened, stopping and starting dependents in the right order. Refuses the RMM agent's own service, because stopping it would cut the connection this run is travelling over.",
		Category:    "Maintenance",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  300,
		Params: []ScriptParam{
			{Name: "service", Description: "Service name (not display name), e.g. Spooler", Required: true},
		},
		Body: `param([string]$Service = '')
$ErrorActionPreference = 'Stop'
if (-not $Service) { Write-Output "A service name is required."; exit 2 }
if ($Service -ieq 'HomelabRMMAgent') {
    Write-Output "Refusing: that is this agent's own service, and stopping it would cut the connection carrying this run."
    exit 2
}
$svc = Get-Service -Name $Service -ErrorAction SilentlyContinue
if (-not $svc) { Write-Output "No such service: $Service"; exit 2 }
"== Before =="
"{0} ({1}) : {2}" -f $svc.Name, $svc.DisplayName, $svc.Status
$deps = $svc.DependentServices | Where-Object Status -eq 'Running'
if ($deps) { "dependents running: " + (($deps | ForEach-Object Name) -join ', ') }

try {
    Restart-Service -Name $Service -Force -ErrorAction Stop
} catch {
    Write-Output "Restart failed: $($_.Exception.Message)"
    exit 1
}
Start-Sleep -Seconds 2
$after = Get-Service -Name $Service
""
"== After =="
"{0} : {1}" -f $after.Name, $after.Status
foreach ($d in $deps) {
    $s = Get-Service -Name $d.Name -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Running') {
        "starting dependent {0}" -f $s.Name
        Start-Service -Name $s.Name -ErrorAction SilentlyContinue
    }
}
if ($after.Status -ne 'Running') { "Service is not running after the restart."; exit 1 }
"Restarted."
`,
	},
	{
		Name:        "Clear Windows Update cache",
		Description: "The standard fix for updates that download forever or fail with the same error: stops the update services, renames SoftwareDistribution and catroot2 so Windows rebuilds them, and starts everything again. Reports how much was freed. No reboot.",
		Category:    "Maintenance",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  900,
		Body: `$ErrorActionPreference = 'SilentlyContinue'
$services = 'wuauserv','bits','cryptsvc','msiserver'
"== Stopping update services =="
foreach ($s in $services) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
    "{0,-12} {1}" -f $s, (Get-Service -Name $s).Status
}

$sd = Join-Path $env:SystemRoot 'SoftwareDistribution'
$cr = Join-Path $env:SystemRoot 'System32\catroot2'
$freed = 0
""
"== Renaming caches =="
foreach ($dir in @($sd, $cr)) {
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    $size = (Get-ChildItem -LiteralPath $dir -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    $bak = "$dir.old"
    Remove-Item -LiteralPath $bak -Recurse -Force -ErrorAction SilentlyContinue
    Rename-Item -LiteralPath $dir -NewName (Split-Path $bak -Leaf) -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $dir) { "{0}: could not rename (in use)" -f $dir }
    else {
        $freed += $size
        "{0}: renamed, {1} MB will be reclaimed" -f $dir, [math]::Round($size / 1MB)
        Remove-Item -LiteralPath $bak -Recurse -Force -ErrorAction SilentlyContinue
    }
}

""
"== Starting services =="
foreach ($s in $services) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    Start-Service -Name $s -ErrorAction SilentlyContinue
    "{0,-12} {1}" -f $s, (Get-Service -Name $s).Status
}
""
"Freed about {0} MB. Run a patch scan to repopulate the cache." -f [math]::Round($freed / 1MB)
`,
	},
	{
		Name:        "Component store cleanup",
		Description: "Runs DISM StartComponentCleanup to remove superseded update payloads from WinSxS, the usual reason C: quietly fills on an older install. Reports the size before and after. Slow, and safe to run on a live machine.",
		Category:    "Maintenance",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  3600,
		Params: []ScriptParam{
			{Name: "reset_base", Description: "Also ResetBase, which makes every installed update permanent and unremovable (yes/no)", Default: "no"},
		},
		Body: `param([string]$ResetBase = 'no')
$ErrorActionPreference = 'Continue'
$sys = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
"== Before =="
"free on {0}: {1} GB" -f $env:SystemDrive, [math]::Round($sys.FreeSpace / 1GB, 1)

""
"== Analysing the component store =="
& dism.exe /Online /Cleanup-Image /AnalyzeComponentStore | Where-Object { $_ -match ':' }

$args = @('/Online','/Cleanup-Image','/StartComponentCleanup')
if ($ResetBase -match '^(y|yes|true|1)$') {
    $args += '/ResetBase'
    ""
    "ResetBase requested: installed updates become permanent and cannot be uninstalled afterwards."
}
""
"== Cleaning =="
& dism.exe @args | Where-Object { $_ -match 'complete|error|Error' }
$code = $LASTEXITCODE

$sys2 = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
""
"== After =="
"free on {0}: {1} GB  (reclaimed {2} GB)" -f $env:SystemDrive,
    [math]::Round($sys2.FreeSpace / 1GB, 1), [math]::Round(($sys2.FreeSpace - $sys.FreeSpace) / 1GB, 2)
if ($code -ne 0) { "DISM exited $code"; exit 1 }
`,
	},
	{
		Name:        "Reset network stack",
		Description: "The heavy-handed network fix: resets Winsock and the TCP/IP stack, clears the DNS cache and re-registers the adapter. Use when a machine has network settings that no longer make sense. REQUIRES A REBOOT to take effect, and says so rather than rebooting.",
		Category:    "Maintenance",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  300,
		Params: []ScriptParam{
			{Name: "confirm", Description: "Set to yes to actually reset; anything else reports what would run", Default: "no"},
		},
		Body: `param([string]$Confirm = 'no')
$ErrorActionPreference = 'Continue'
$steps = @(
    @{ Name = 'winsock reset';   Cmd = 'netsh'; Args = @('winsock','reset') },
    @{ Name = 'IPv4 reset';      Cmd = 'netsh'; Args = @('int','ip','reset') },
    @{ Name = 'IPv6 reset';      Cmd = 'netsh'; Args = @('int','ipv6','reset') },
    @{ Name = 'flush DNS';       Cmd = 'ipconfig'; Args = @('/flushdns') },
    @{ Name = 'register DNS';    Cmd = 'ipconfig'; Args = @('/registerdns') }
)
if ($Confirm -notmatch '^(y|yes|true|1)$') {
    "Report only. These steps would run:"
    $steps | ForEach-Object { "  {0}: {1} {2}" -f $_.Name, $_.Cmd, ($_.Args -join ' ') }
    ""
    "Re-run with confirm=yes to apply. A REBOOT is required afterwards."
    exit 0
}
foreach ($s in $steps) {
    "== {0} ==" -f $s.Name
    & $s.Cmd @($s.Args) 2>&1 | Select-Object -Last 3
}
""
"Done. THE DEVICE MUST BE REBOOTED for the stack reset to take effect."
`,
	},
	{
		Name:        "Group Policy update",
		Description: "Forces a policy refresh for both computer and user and reports whether it applied, then prints when policy was last applied and from which domain controller. The first thing to try when a policy change has not reached a machine.",
		Category:    "Maintenance",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  600,
		Body: `$ErrorActionPreference = 'Continue'
$cs = Get-CimInstance Win32_ComputerSystem
if (-not $cs.PartOfDomain) { "This device is not domain joined ({0}), so there is no domain policy to refresh." -f $cs.Workgroup; exit 0 }
"== Refreshing policy =="
$out = & gpupdate.exe /force /wait:120 2>&1
$out | ForEach-Object { $_ }
if ($LASTEXITCODE -ne 0) { "gpupdate exited $LASTEXITCODE"; exit 1 }
""
"== Last applied =="
$g = Get-CimInstance -Namespace root\rsop\computer -ClassName RSOP_Session -ErrorAction SilentlyContinue
try {
    $r = & gpresult.exe /r /scope:computer 2>&1
    $r | Where-Object { $_ -match 'Last time Group Policy was applied|Group Policy was applied from|Domain Name|Site Name' } | ForEach-Object { $_.Trim() }
} catch { "gpresult is unavailable on this edition." }
`,
	},

	// --------------------------------------------------------------- Security
	{
		Name:        "Microsoft Defender status",
		Description: "Whether real-time protection is on, how old the signatures are, when the last scan ran and anything currently in quarantine. Reports cleanly on a machine where a third-party product has taken over, instead of claiming Defender is broken.",
		Category:    "Security",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  300,
		Body: `$ErrorActionPreference = 'SilentlyContinue'
"== Registered antivirus products =="
$av = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct
if ($av) {
    foreach ($p in $av) {
        # productState bit 12 (0x1000) set means real-time protection is on.
        $state = [Convert]::ToString($p.productState, 16).PadLeft(6, '0')
        $on = ($p.productState -band 0x1000) -ne 0
        "{0,-32} realtime={1}  state=0x{2}" -f $p.displayName, $on, $state
    }
} else { "none registered" }

$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if (-not $mp) { "" + [Environment]::NewLine + "Defender's PowerShell module is unavailable; another product has probably replaced it."; exit 0 }

""
"== Defender =="
"realtime protection : {0}" -f $mp.RealTimeProtectionEnabled
"antivirus enabled   : {0}" -f $mp.AntivirusEnabled
"tamper protection   : {0}" -f $mp.IsTamperProtected
"engine version      : {0}" -f $mp.AMEngineVersion
"signature version   : {0}" -f $mp.AntivirusSignatureVersion
$age = $mp.AntivirusSignatureAge
"signature age       : {0} day(s)" -f $age
if ($age -gt 3) { "NOTE: signatures are more than three days old." }
"last quick scan     : {0}" -f $mp.QuickScanEndTime
"last full scan      : {0}" -f $mp.FullScanEndTime

""
"== Active threats =="
$t = Get-MpThreatDetection -ErrorAction SilentlyContinue
if (-not $t) { "none" } else {
    $t | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10 | ForEach-Object {
        "{0:yyyy-MM-dd HH:mm}  {1}  (action {2})" -f $_.InitialDetectionTime, $_.ThreatID, $_.ActionSuccess
    }
}
if ($mp.RealTimeProtectionEnabled -eq $false -and -not $av) { "" + [Environment]::NewLine + "Nothing is providing real-time protection."; exit 1 }
`,
	},
	{
		Name:        "Firewall status",
		Description: "The state of all three firewall profiles, the default inbound action on each, and a count of enabled allow rules. Optionally turns any profile that is off back on.",
		Category:    "Security",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  180,
		Params: []ScriptParam{
			{Name: "enable", Description: "Set to yes to switch on any profile that is off", Default: "no"},
		},
		Body: `param([string]$Enable = 'no')
$ErrorActionPreference = 'SilentlyContinue'
$profiles = Get-NetFirewallProfile
if (-not $profiles) { "The firewall service is not available on this device."; exit 1 }
"== Profiles =="
foreach ($p in $profiles) {
    "{0,-8} enabled={1,-5} inbound={2,-6} outbound={3}" -f $p.Name, $p.Enabled, $p.DefaultInboundAction, $p.DefaultOutboundAction
}
$off = $profiles | Where-Object { -not $_.Enabled }

""
"== Enabled inbound allow rules =="
$rules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue
"{0} rule(s)" -f @($rules).Count

if ($off) {
    ""
    "{0} profile(s) are OFF: {1}" -f @($off).Count, (($off | ForEach-Object Name) -join ', ')
    if ($Enable -match '^(y|yes|true|1)$') {
        Set-NetFirewallProfile -Name ($off | ForEach-Object Name) -Enabled True -ErrorAction SilentlyContinue
        "switched on; now:"
        Get-NetFirewallProfile | ForEach-Object { "  {0,-8} enabled={1}" -f $_.Name, $_.Enabled }
    } else {
        "Re-run with enable=yes to switch them on."
        exit 1
    }
} else { "" + [Environment]::NewLine + "All profiles are on." }
`,
	},
	{
		Name:        "Remote Desktop status",
		Description: "Whether RDP is accepting connections, whether Network Level Authentication is required, which port it listens on and who is in the Remote Desktop Users group. Can also turn RDP off, which is the safe direction to change it remotely.",
		Category:    "Security",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  180,
		Params: []ScriptParam{
			{Name: "disable", Description: "Set to yes to turn RDP off (enabling remotely is deliberately not offered)", Default: "no"},
		},
		Body: `param([string]$Disable = 'no')
$ErrorActionPreference = 'SilentlyContinue'
$ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdp = (Get-ItemProperty -Path $ts -Name fDenyTSConnections).fDenyTSConnections
$nla = (Get-ItemProperty -Path "$ts\WinStations\RDP-Tcp" -Name UserAuthentication).UserAuthentication
$port = (Get-ItemProperty -Path "$ts\WinStations\RDP-Tcp" -Name PortNumber).PortNumber
"== Remote Desktop =="
"accepting connections : {0}" -f $(if ($rdp -eq 0) { 'YES' } else { 'no' })
"network level auth    : {0}" -f $(if ($nla -eq 1) { 'required' } else { 'NOT required' })
"port                  : {0}" -f $port
if ($rdp -eq 0 -and $nla -ne 1) { "WARNING: RDP is on without NLA, which accepts a session before authentication." }

""
"== Remote Desktop Users =="
$m = Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction SilentlyContinue
if ($m) { $m | ForEach-Object { "  {0} ({1})" -f $_.Name, $_.ObjectClass } } else { "  (empty: only administrators can connect)" }

""
"== Firewall rules =="
Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue |
    ForEach-Object { "  {0,-45} enabled={1}" -f $_.DisplayName, $_.Enabled }

if ($Disable -match '^(y|yes|true|1)$') {
    ""
    "== Disabling =="
    Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 1
    Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
    "RDP is now refused and its firewall rules are disabled."
}
`,
	},
	{
		Name:        "Listening ports and owners",
		Description: "Every TCP port in the listening state with the process behind it, its path and its publisher. The quickest way to find what opened a port, and which listeners are reachable rather than loopback-only.",
		Category:    "Security",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  180,
		Params: []ScriptParam{
			{Name: "scope", Description: "all, or external to hide loopback-only listeners", Default: "external"},
		},
		Body: `param([string]$Scope = 'external')
$ErrorActionPreference = 'SilentlyContinue'
$conns = Get-NetTCPConnection -State Listen
if ($Scope -ne 'all') { $conns = $conns | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' } }
if (-not $conns) { "No listening TCP ports match."; exit 0 }
$procs = @{}
Get-Process | ForEach-Object { $procs[$_.Id] = $_ }
"== Listening TCP ({0}) ==" -f $Scope
$conns | Sort-Object LocalPort | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    $name = if ($p) { $p.ProcessName } else { '?' }
    $path = if ($p) { $p.Path } else { '' }
    $pub = ''
    if ($path) {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
        if ($sig -and $sig.SignerCertificate) { $pub = ($sig.SignerCertificate.Subject -split ',')[0] -replace '^CN=', '' }
        elseif ($sig) { $pub = $sig.Status }
    }
    "{0,-22} {1,-6} {2,-22} {3}" -f ("$($_.LocalAddress):$($_.LocalPort)"), $_.OwningProcess, $name, $pub
    if ($path) { "    $path" }
}
`,
	},
	{
		Name:        "Local accounts audit",
		Description: "Every local account with whether it is enabled, when the password was last set, whether it never expires, and who holds administrator rights. Flags enabled accounts with very old passwords and any administrator that is not expected.",
		Category:    "Security",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  180,
		Params: []ScriptParam{
			{Name: "max_password_age_days", Description: "Flag enabled accounts whose password is older than this", Default: "365"},
		},
		Body: `param([string]$MaxPasswordAgeDays = '365')
$ErrorActionPreference = 'SilentlyContinue'
$maxAge = 365; [void][int]::TryParse($MaxPasswordAgeDays, [ref]$maxAge)
"== Local accounts =="
$flagged = 0
Get-LocalUser | Sort-Object Name | ForEach-Object {
    $age = if ($_.PasswordLastSet) { [math]::Round(((Get-Date) - $_.PasswordLastSet).TotalDays) } else { $null }
    $bits = @()
    if ($_.PasswordNeverExpires) { $bits += 'never expires' }
    if ($null -eq $_.PasswordLastSet) { $bits += 'password never set' }
    if ($_.Enabled -and $null -ne $age -and $age -gt $maxAge) { $bits += "password $age days old"; $flagged++ }
    "{0,-22} enabled={1,-5} lastset={2,-12} {3}" -f $_.Name, $_.Enabled,
        $(if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'never' }), ($bits -join ', ')
}

""
"== Administrators =="
Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { "  {0} ({1}, {2})" -f $_.Name, $_.ObjectClass, $_.PrincipalSource }

""
"== Password policy =="
& net.exe accounts | ForEach-Object { $_ }

if ($flagged -gt 0) { "" + [Environment]::NewLine + "$flagged enabled account(s) have a password older than $maxAge days." }
`,
	},

	// ------------------------------------------------------------------ Users
	{
		Name:        "User profiles and sizes",
		Description: "Every local profile with its size, owner and when it was last used, largest first. The report to read before asking where a full disk went, and the input to deciding which stale profiles could go.",
		Category:    "Users",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  1800,
		Body: `$ErrorActionPreference = 'SilentlyContinue'
"== Profiles =="
$rows = foreach ($p in Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special }) {
    $path = $p.LocalPath
    $size = (Get-ChildItem -LiteralPath $path -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    $name = try { (New-Object System.Security.Principal.SecurityIdentifier($p.SID)).Translate([System.Security.Principal.NTAccount]).Value } catch { $p.SID }
    [pscustomobject]@{
        Name    = $name
        Path    = $path
        SizeGB  = [math]::Round(($size / 1GB), 2)
        LastUse = if ($p.LastUseTime) { ([datetime]$p.LastUseTime).ToString('yyyy-MM-dd') } else { 'unknown' }
        Loaded  = $p.Loaded
    }
}
$rows | Sort-Object SizeGB -Descending | ForEach-Object {
    "{0,8:N2} GB  {1,-12} {2,-30} {3}" -f $_.SizeGB, $_.LastUse, $_.Name, $_.Path + $(if ($_.Loaded) { '  [in use]' } else { '' })
}
""
"total: {0:N1} GB across {1} profile(s)" -f (($rows | Measure-Object SizeGB -Sum).Sum), @($rows).Count
`,
	},
	{
		Name:        "Remove stale user profiles",
		Description: "Deletes local profiles not used for a given number of days, using the Windows profile API so the registry entry goes with the folder. Reports what it would remove and changes nothing until confirm=yes. Never touches a loaded profile, a special profile or an administrator's.",
		Category:    "Users",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  1800,
		Params: []ScriptParam{
			{Name: "older_than_days", Description: "Only profiles unused for at least this many days", Default: "180"},
			{Name: "confirm", Description: "Set to yes to actually delete; anything else reports only", Default: "no"},
		},
		Body: `param([string]$OlderThanDays = '180', [string]$Confirm = 'no')
$ErrorActionPreference = 'SilentlyContinue'
$days = 180; [void][int]::TryParse($OlderThanDays, [ref]$days); if ($days -lt 30) { $days = 30 }
$cut = (Get-Date).AddDays(-$days)
$apply = $Confirm -match '^(y|yes|true|1)$'

$admins = @(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { $_.Name })
$candidates = foreach ($p in Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and -not $_.Loaded }) {
    $last = if ($p.LastUseTime) { [datetime]$p.LastUseTime } else { $null }
    if ($null -eq $last -or $last -ge $cut) { continue }
    $name = try { (New-Object System.Security.Principal.SecurityIdentifier($p.SID)).Translate([System.Security.Principal.NTAccount]).Value } catch { $p.SID }
    if ($admins -contains $name) { continue }   # never an administrator's profile
    [pscustomobject]@{ Obj = $p; Name = $name; Path = $p.LocalPath; Last = $last }
}

if (-not $candidates) { "No profile has been unused for $days days (excluding loaded, special and administrator profiles)."; exit 0 }
"== Profiles unused for $days days =="
$candidates | ForEach-Object { "{0:yyyy-MM-dd}  {1,-30} {2}" -f $_.Last, $_.Name, $_.Path }

if (-not $apply) { "" + [Environment]::NewLine + "Report only. Re-run with confirm=yes to delete these {0} profile(s)." -f @($candidates).Count; exit 0 }

""
"== Deleting =="
$ok = 0; $fail = 0
foreach ($c in $candidates) {
    try {
        Remove-CimInstance -InputObject $c.Obj -ErrorAction Stop
        "removed {0}" -f $c.Path; $ok++
    } catch {
        "FAILED  {0}: {1}" -f $c.Path, $_.Exception.Message; $fail++
    }
}
""
"removed $ok, failed $fail"
if ($fail -gt 0) { exit 1 }
`,
	},

	// ---------------------------------------------------------------- Software
	{
		Name:        "Find installed software",
		Description: "Searches every place Windows records an installed program, both registry hives and both architectures, for a name fragment, and reports version, publisher and install date. Answers 'which machines still have this' across a fleet.",
		Category:    "Software",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  300,
		Params: []ScriptParam{
			{Name: "name", Description: "Part of the display name, e.g. Chrome. Empty lists everything.", Default: ""},
		},
		Body: `param([string]$Name = '')
$ErrorActionPreference = 'SilentlyContinue'
$keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$rows = foreach ($k in $keys) {
    Get-ItemProperty -Path $k -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and (-not $_.SystemComponent -or $_.SystemComponent -eq 0) } |
        ForEach-Object {
            [pscustomobject]@{
                Name      = $_.DisplayName
                Version   = $_.DisplayVersion
                Publisher = $_.Publisher
                Installed = $_.InstallDate
                Uninstall = $_.UninstallString
            }
        }
}
$rows = $rows | Sort-Object Name -Unique
if ($Name) { $rows = $rows | Where-Object { $_.Name -like "*$Name*" } }
if (-not $rows) { "No installed program matches '$Name'."; exit 0 }
"== {0} match(es) ==" -f @($rows).Count
$rows | ForEach-Object {
    "{0}" -f $_.Name
    "    version {0}   publisher {1}   installed {2}" -f $_.Version, $_.Publisher, $_.Installed
    if ($Name -and $_.Uninstall) { "    uninstall: {0}" -f $_.Uninstall }
}
`,
	},
	{
		Name:        "Install a package with winget",
		Description: "Installs or upgrades one named package with winget, accepting the package and source agreements so it runs unattended. Resolves winget by absolute path, because the agent runs as SYSTEM where it is not on PATH.",
		Category:    "Software",
		Language:    "powershell",
		OSFilter:    "windows",
		TimeoutSec:  1800,
		Params: []ScriptParam{
			{Name: "id", Description: "Exact winget package id, e.g. Google.Chrome", Required: true},
		},
		Body: `param([string]$Id = '')
$ErrorActionPreference = 'Continue'
if (-not $Id) { "A winget package id is required, e.g. Google.Chrome"; exit 2 }

# The agent runs as SYSTEM, where winget is not on PATH: it lives under the
# per-machine WindowsApps directory that the App Installer package provisions.
$winget = Get-Command winget.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $winget) {
    $candidate = Get-ChildItem (Join-Path $env:ProgramFiles 'WindowsApps') -Filter winget.exe -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if ($candidate) { $winget = $candidate.FullName }
}
if (-not $winget) { "winget is not available to the SYSTEM account on this device (App Installer may not be provisioned)."; exit 1 }
"using $winget"

& $winget install --id $Id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
$code = $LASTEXITCODE
if ($code -eq 0) { "Installed or already current: $Id" }
elseif ($code -eq -1978335189) { "Already installed and up to date: $Id" }
else { "winget exited $code for $Id"; exit 1 }
`,
	},
}
