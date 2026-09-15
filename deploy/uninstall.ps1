<#
.SYNOPSIS
    Removes the Homelab RMM agent (default) or server (-Server) from this Windows machine.

.DESCRIPTION
    Stops and unregisters the Windows service, deletes the program files and
    keeps configuration / data unless -Purge is given. Run from an elevated
    PowerShell. Windows PowerShell 5.1 compatible.

    Agent:  service HomelabRMMAgent, binary %ProgramFiles%\HomelabRMM\rmm-agent.exe,
            config %ProgramData%\HomelabRMM\agent.json (+ agent.log)
    Server: service HomelabRMMServer, data %ProgramData%\HomelabRMM
            (rmm.db, server.crt, server.key, server.log, agents\)

    Afterwards delete the device in the console (Devices -> device -> Delete)
    so it does not linger as offline.

.EXAMPLE
    .\uninstall.ps1                 # agent, keep agent.json
    .\uninstall.ps1 -Purge          # agent and its identity/log
    .\uninstall.ps1 -Server         # server, keep the data directory
    .\uninstall.ps1 -Server -Purge  # server and everything under %ProgramData%\HomelabRMM
#>
[CmdletBinding()]
param(
    [switch]$Server,
    [switch]$Purge,
    [string]$ProgramDir = (Join-Path $env:ProgramFiles 'HomelabRMM'),
    [string]$DataDir = (Join-Path $env:ProgramData 'HomelabRMM')
)
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated (Administrator) PowerShell.'
}

function Remove-RmmService([string]$Name, [string]$Exe) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Stopped') { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
        # the binary unregisters itself cleanly; sc.exe is the fallback
        $done = $false
        if ($Exe -and (Test-Path -LiteralPath $Exe)) {
            # 5.1 turns redirected stderr into a terminating error under 'Stop'; the
            # exit code is the verdict here, so relax the preference for this call.
            $prev = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                & $Exe uninstall 2>&1 | Out-Null
                $done = ($LASTEXITCODE -eq 0)
            } catch { $done = $false } finally { $ErrorActionPreference = $prev }
        }
        if (-not $done) {
            & sc.exe delete $Name | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warning "sc.exe delete $Name failed ($LASTEXITCODE); remove it by hand" }
        }
        Start-Sleep -Seconds 1
        Write-Host "service $Name removed"
    } else {
        Write-Host "service $Name is not installed"
    }
}

if ($Server) {
    # the service's binary path tells us where the server was extracted
    $exe = ''
    $reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\HomelabRMMServer' -ErrorAction SilentlyContinue
    if ($reg -and $reg.ImagePath -match '^"?([^"]+rmm-server\.exe)') { $exe = $Matches[1] }
    Remove-RmmService 'HomelabRMMServer' $exe
    if ($exe -and (Test-Path -LiteralPath $exe)) {
        $dir = Split-Path -Parent $exe
        Remove-Item -LiteralPath $exe -Force
        $agents = Join-Path $dir 'agents'
        if (Test-Path -LiteralPath $agents) { Remove-Item -LiteralPath $agents -Recurse -Force }
        Write-Host "removed $exe and its agents folder (other files in $dir were left alone)"
    }
    if ($Purge) {
        if (Test-Path -LiteralPath $DataDir) { Remove-Item -LiteralPath $DataDir -Recurse -Force }
        Write-Host "removed $DataDir (database, certificate, logs)"
    } else {
        Write-Host "kept $DataDir (rmm.db, server.crt/key, server.log; -Purge removes it)"
    }
} else {
    $exe = Join-Path $ProgramDir 'rmm-agent.exe'
    Remove-RmmService 'HomelabRMMAgent' $exe
    foreach ($f in @($exe, "$exe.new", "$exe.old")) {
        if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
    }
    if ((Test-Path -LiteralPath $ProgramDir) -and -not (Get-ChildItem -LiteralPath $ProgramDir -Force | Select-Object -First 1)) {
        Remove-Item -LiteralPath $ProgramDir -Force
    }
    Write-Host "agent removed from $ProgramDir"
    # only the agent's own files: the server shares this folder when both run on one box
    $agentFiles = @('agent.json', 'agent.json.tmp', 'agent.log', 'agent.log.1') | ForEach-Object { Join-Path $DataDir $_ }
    if ($Purge) {
        foreach ($f in $agentFiles) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
        if ((Test-Path -LiteralPath $DataDir) -and -not (Get-ChildItem -LiteralPath $DataDir -Force | Select-Object -First 1)) {
            Remove-Item -LiteralPath $DataDir -Force
        }
        Write-Host "removed agent.json and agent.log from $DataDir"
    } else {
        Write-Host "kept $DataDir\agent.json (this device's identity; -Purge removes it)"
    }
}
