package agent

// wuascript.go holds the PowerShell that drives the Windows Update Agent
// COM API. The scripts are plain constants with no build constraint so the
// Linux build box can test their shape for real (winparse_test.go); the
// Windows side that runs them is updates_windows.go.
//
// Both scripts print exactly one "RESULT <json>" line, which the Go side
// parses with winParseWUAScan / winParseWUAInstall; the install script also
// prints "PROGRESS <text>" lines that are forwarded to the operator as they
// appear. Every collection that is appended to is a
// System.Collections.ArrayList: "@()" is a fixed-size System.Object[] whose
// Add() throws "Collection was of a fixed size", which would turn every scan
// on a device with a KB-numbered update into an empty list with a baffling
// error.

// wuaScanScript searches for applicable software updates. It never throws
// to the host: a search failure is reported in the JSON so the operator
// sees the HRESULT instead of a blank scan. $ErrorActionPreference is Stop
// so a COM error lands in the catch rather than scrolling warnings.
const wuaScanScript = `
$ErrorActionPreference = 'Stop'
$out = [ordered]@{ updates = @(); reboot_pending = $false; error = ''; error_hresult = '' }
try {
	$si = New-Object -ComObject Microsoft.Update.SystemInfo
	$out.reboot_pending = [bool]$si.RebootRequired
} catch {}
try {
	$session  = New-Object -ComObject Microsoft.Update.Session
	$searcher = $session.CreateUpdateSearcher()
	$result   = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
	$list = New-Object System.Collections.ArrayList
	foreach ($u in $result.Updates) {
		$kb = New-Object System.Collections.ArrayList
		foreach ($k in $u.KBArticleIDs) { [void]$kb.Add("$k") }
		$cats = New-Object System.Collections.ArrayList
		foreach ($c in $u.Categories) { [void]$cats.Add("$($c.Name)") }
		$size = 0; try { $size = [double]$u.MaxDownloadSize } catch {}
		$reboot = 0; try { $reboot = [int]$u.InstallationBehavior.RebootBehavior } catch {}
		$desc = ''; if ($u.Description) { $desc = "$($u.Description)"; if ($desc.Length -gt 500) { $desc = $desc.Substring(0, 500) } }
		[void]$list.Add([ordered]@{
			id              = "$($u.Identity.UpdateID)"
			revision        = [int]$u.Identity.RevisionNumber
			title           = "$($u.Title)"
			kb              = @($kb)
			severity        = "$($u.MsrcSeverity)"
			categories      = @($cats)
			size            = $size
			downloaded      = [bool]$u.IsDownloaded
			reboot_behavior = $reboot
			description     = $desc
			mandatory       = [bool]$u.IsMandatory
		})
	}
	$out.updates = @($list)
} catch {
	$ex = $_.Exception
	if ($ex.InnerException) { $ex = $ex.InnerException }
	$out.error = "$($_.Exception.Message)"
	if ($ex -is [System.Runtime.InteropServices.COMException]) { $out.error_hresult = ('0x{0:X8}' -f $ex.HResult) }
}
Write-Output ("RESULT " + ($out | ConvertTo-Json -Depth 6 -Compress))
`

// wuaInstallScript downloads and installs the updates whose UpdateIDs are
// passed as arguments (none = every applicable software update). A download
// failure is reported per update (result 4) rather than dropped, and a
// failure after some results exist still reports those results. The
// argument list is validated to be GUIDs on the Go side, so the -match here
// is defence in depth, not the only guard.
const wuaInstallScript = `
$ErrorActionPreference = 'Stop'
function Progress($m) { Write-Output ("PROGRESS " + $m) }
$out = [ordered]@{ results = @(); reboot_required = $false; error = ''; error_hresult = '' }
$results = New-Object System.Collections.ArrayList
try {
	$want = New-Object System.Collections.ArrayList
	foreach ($a in $args) { if ("$a" -match '^[0-9A-Fa-f-]{36}$') { [void]$want.Add("$a".ToLower()) } }
	$session  = New-Object -ComObject Microsoft.Update.Session
	$searcher = $session.CreateUpdateSearcher()
	Progress 'Searching for applicable updates'
	$result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
	$coll = New-Object -ComObject Microsoft.Update.UpdateColl
	foreach ($u in $result.Updates) {
		$id = "$($u.Identity.UpdateID)".ToLower()
		if ($want.Count -gt 0 -and -not $want.Contains($id)) { continue }
		if ($u.EulaAccepted -eq $false) { try { $u.AcceptEula() } catch {} }
		[void]$coll.Add($u)
	}
	if ($coll.Count -eq 0) {
		$out.error = 'none of the requested updates are applicable'
		Write-Output ("RESULT " + ($out | ConvertTo-Json -Depth 6 -Compress)); return
	}
	Progress ("Downloading " + $coll.Count + " update(s)")
	$downloader = $session.CreateUpdateDownloader()
	$downloader.Updates = $coll
	$dr = $downloader.Download()
	$toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
	for ($i = 0; $i -lt $coll.Count; $i++) {
		$u = $coll.Item($i)
		if ($u.IsDownloaded) { [void]$toInstall.Add($u); Progress ("Downloaded: " + $u.Title); continue }
		$hr = 0; try { $hr = [int]$dr.GetUpdateResult($i).HResult } catch {}
		[void]$results.Add([ordered]@{ id = "$($u.Identity.UpdateID)"; title = "$($u.Title)"; result = 4; hresult = $hr; reboot = $false; error = 'download failed' })
		Progress ("Download failed: " + $u.Title)
	}
	if ($toInstall.Count -eq 0) { throw 'no updates could be downloaded' }
	Progress ("Installing " + $toInstall.Count + " update(s)")
	$installer = $session.CreateUpdateInstaller()
	$installer.Updates = $toInstall
	try { $installer.ForceQuiet = $true } catch {}
	try { $installer.AllowSourcePrompts = $false } catch {}
	$ir = $installer.Install()
	$out.reboot_required = [bool]$ir.RebootRequired
	for ($i = 0; $i -lt $toInstall.Count; $i++) {
		$u = $toInstall.Item($i)
		$r = $ir.GetUpdateResult($i)
		$hr = 0; try { $hr = [int]$r.HResult } catch {}
		[void]$results.Add([ordered]@{
			id      = "$($u.Identity.UpdateID)"
			title   = "$($u.Title)"
			result  = [int]$r.ResultCode
			hresult = $hr
			reboot  = [bool]$r.RebootRequired
			error   = ''
		})
		Progress ("Result for " + $u.Title + ": code " + [int]$r.ResultCode)
	}
	$out.results = @($results)
} catch {
	$ex = $_.Exception
	if ($ex.InnerException) { $ex = $ex.InnerException }
	$out.error = "$($_.Exception.Message)"
	if ($ex -is [System.Runtime.InteropServices.COMException]) { $out.error_hresult = ('0x{0:X8}' -f $ex.HResult) }
	if ($results.Count -gt 0) { $out.results = @($results) }
}
Write-Output ("RESULT " + ($out | ConvertTo-Json -Depth 6 -Compress))
`
