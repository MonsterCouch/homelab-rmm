# Renew the Tailscale (Let's Encrypt) certificate the Homelab RMM server
# serves, and restart the service only if the certificate actually changed.
#
# Why this exists: `tailscale cert` issues a 90-day certificate, and the server
# reads its certificate once at startup. Without something like this the
# console starts failing three months after a working install, which is exactly
# the kind of outage nobody connects to a decision made a quarter earlier.
#
# Install it as a scheduled task running as SYSTEM, weekly. Running it more
# often is harmless: Tailscale only re-issues when the certificate is close to
# expiry, and this restarts the service only when the file on disk differs.
#
#   $args = '-NoProfile -ExecutionPolicy Bypass -File "C:\path\renew-tailscale-cert.ps1" -Domain <name>'
#   $a = New-ScheduledTaskAction -Execute powershell.exe -Argument $args
#   $t = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
#   $p = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
#   Register-ScheduledTask -TaskName 'Homelab RMM cert renewal' -Action $a -Trigger $t -Principal $p
[CmdletBinding()]
param(
    # The tailnet name the certificate is for, e.g. host.tailnet-name.ts.net.
    # Defaults to this machine's own name as Tailscale reports it.
    [string]$Domain = '',
    [string]$CertDir = 'C:\ProgramData\HomelabRMM-Server\certs',
    [string]$ServiceName = 'HomelabRMMServer',
    [string]$Tailscale = 'C:\Program Files\Tailscale\tailscale.exe',
    [string]$LogFile = 'C:\ProgramData\HomelabRMM-Server\cert-renewal.log'
)
$ErrorActionPreference = 'Stop'

function Say($m) {
    $line = "$(Get-Date -Format s)  $m"
    try { $line | Out-File $LogFile -Append -Encoding utf8 } catch { }
    Write-Host $line
}

try {
    if (-not (Test-Path $Tailscale)) { Say "tailscale.exe not found at $Tailscale"; exit 1 }

    if (-not $Domain) {
        # Self.DNSName comes back with a trailing dot.
        $status = & $Tailscale status --json | ConvertFrom-Json
        $Domain = ($status.Self.DNSName).TrimEnd('.')
        if (-not $Domain) { Say 'cannot determine this machine tailnet name; pass -Domain'; exit 1 }
    }

    New-Item -ItemType Directory -Force $CertDir | Out-Null
    $crt = Join-Path $CertDir "$Domain.crt"
    $key = Join-Path $CertDir "$Domain.key"
    $before = if (Test-Path $crt) { (Get-FileHash $crt -Algorithm SHA256).Hash } else { '' }

    & $Tailscale cert --cert-file $crt --key-file $key $Domain 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Say "tailscale cert failed with exit $LASTEXITCODE (are HTTPS certificates enabled for this tailnet?)"
        exit 1
    }

    $after = (Get-FileHash $crt -Algorithm SHA256).Hash
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($crt)
    $daysLeft = [int]($cert.NotAfter - (Get-Date)).TotalDays

    if ($after -eq $before) {
        Say ("unchanged; expires {0:yyyy-MM-dd} ({1} days left)" -f $cert.NotAfter, $daysLeft)
        exit 0
    }

    # A new key file must not be world-readable: it is the server's identity.
    icacls $key /inheritance:r /grant 'SYSTEM:(F)' /grant 'Administrators:(F)' 2>&1 | Out-Null
    Say ("RENEWED; expires {0:yyyy-MM-dd} ({1} days); sha256 {2}" -f $cert.NotAfter, $daysLeft,
        ([BitConverter]::ToString($cert.GetCertHash('SHA256')) -replace '-', '').ToLower())

    # The server reads its certificate at startup only, so it has to restart to
    # pick the new one up.
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { Say "service $ServiceName not installed; nothing to restart"; exit 0 }
    Restart-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 5
    Say ("service $ServiceName is " + (Get-Service -Name $ServiceName).Status)
}
catch {
    Say ("ERROR: " + $_.Exception.Message)
    exit 1
}
