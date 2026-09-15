<#
.SYNOPSIS
    Builds Homelab RMM on Windows without make. Windows PowerShell 5.1 or PowerShell 7.

.DESCRIPTION
    Same targets as the Makefile:
      web       npm ci + npm run build in web\ (the server embeds web\dist)
      server    rmm-server for windows/amd64, windows/arm64, linux/amd64, linux/arm64
      agents    rmm-agent for those plus linux/arm (GOARM=7)
      all       web, server, agents (default)
      test      go vet, go test, UI type-check + build
      package   dist\homelab-rmm-<os>-<arch>.zip per server platform (+ .tar.gz for linux
                when tar.exe is available) and dist\SHA256SUMS
      clean     remove dist\ and the built UI

    Needs go, node and npm on PATH.

.EXAMPLE
    tools\build.ps1                       # everything
    tools\build.ps1 -Target server,agents # binaries only, reusing the existing web\dist
    tools\build.ps1 -Target package -Version v1.2.3
#>
[CmdletBinding()]
param(
    [ValidateSet('web', 'server', 'agents', 'all', 'test', 'package', 'checksums', 'clean')]
    [string[]]$Target = @('all'),
    [string]$Version = '',
    [string]$Dist = 'dist'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$module = 'github.com/MonsterCouch/homelab-rmm'
$serverPlatforms = @('windows/amd64', 'windows/arm64', 'linux/amd64', 'linux/arm64')
$agentPlatforms = @('windows/amd64', 'windows/arm64', 'linux/amd64', 'linux/arm64', 'linux/arm')

function Get-BuildVersion {
    if ($script:Version) { return $script:Version }
    if ($env:VERSION) { return $env:VERSION }
    # git prints to stderr when there is no tag; under 5.1 with Stop that would throw,
    # so relax the preference just for this call.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $v = (& git describe --tags --always 2>$null | Select-Object -First 1)
        if ($LASTEXITCODE -ne 0 -or -not $v) { $v = 'dev' }
    } catch { $v = 'dev' } finally { $ErrorActionPreference = $prev }
    return [string]$v
}

$Version = Get-BuildVersion
$ldflags = "-s -w -X $module/internal/server.Version=$Version -X $module/internal/agent.Version=$Version"

function Invoke-Native {
    # Runs a native command and turns a non-zero exit into a terminating error.
    param([string]$Exe, [string[]]$Arguments, [string]$WorkDir = '')
    $where = if ($WorkDir) { $WorkDir } else { (Get-Location).Path }
    Push-Location $where
    try {
        & $Exe @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
    } finally { Pop-Location }
}

function Get-BinName([string]$Name, [string]$Os, [string]$Arch) {
    $n = Join-Path $Dist "$Name-$Os-$Arch"
    if ($Os -eq 'windows') { $n += '.exe' }
    return $n
}

function Invoke-GoBuild([string]$Cmd, [string]$Platform) {
    $parts = $Platform.Split('/')
    $os = $parts[0]; $arch = $parts[1]
    $out = Get-BinName $Cmd $os $arch
    New-Item -ItemType Directory -Force -Path $Dist | Out-Null
    Write-Host "  build $out ($Version)"
    $env:CGO_ENABLED = '0'
    $env:GOOS = $os
    $env:GOARCH = $arch
    if ($arch -eq 'arm') { $env:GOARM = '7' } else { Remove-Item Env:\GOARM -ErrorAction SilentlyContinue }
    try {
        Invoke-Native 'go' @('build', '-trimpath', '-ldflags', $ldflags, '-o', $out, "./cmd/$Cmd")
    } finally {
        Remove-Item Env:\CGO_ENABLED, Env:\GOOS, Env:\GOARCH, Env:\GOARM -ErrorAction SilentlyContinue
    }
}

function Build-Web {
    Invoke-Native 'npm' @('ci') 'web'
    Invoke-Native 'npm' @('run', 'build') 'web'
}

function Build-Server { foreach ($p in $serverPlatforms) { Invoke-GoBuild 'rmm-server' $p } }
function Build-Agents { foreach ($p in $agentPlatforms) { Invoke-GoBuild 'rmm-agent' $p } }

function Invoke-Tests {
    Invoke-Native 'go' @('vet', './...')
    Invoke-Native 'go' @('test', './...')
    Invoke-Native 'npm' @('run', 'build') 'web'
}

function New-ZipFromDirectory([string]$Stage, [string]$Zip) {
    # Compress-Archive on Windows PowerShell 5.1 writes backslashes into entry names,
    # which unzip on Linux turns into literal file names. Build the archive by hand
    # with forward slashes, and mark the linux binaries executable where the
    # runtime supports it (.NET Framework ignores the attribute; see the docs).
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Zip) { Remove-Item -LiteralPath $Zip -Force }
    $stageFull = (Resolve-Path -LiteralPath $Stage).Path.TrimEnd('\', '/')
    $fs = [System.IO.File]::Open($Zip, [System.IO.FileMode]::CreateNew)
    $archive = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        Get-ChildItem -LiteralPath $stageFull -Recurse -File | ForEach-Object {
            $rel = $_.FullName.Substring($stageFull.Length).TrimStart('\', '/') -replace '\\', '/'
            $entry = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $_.FullName, $rel, [System.IO.Compression.CompressionLevel]::Optimal)
            if ($rel -eq 'rmm-server' -or $rel -like 'agents/rmm-agent-linux-*') {
                try { $entry.ExternalAttributes = (0x81ED -shl 16) } catch { }   # -rwxr-xr-x
            }
        }
    } finally {
        $archive.Dispose()
        $fs.Dispose()
    }
}

function Write-Checksums {
    $files = Get-ChildItem -Path $Dist -File | Where-Object { $_.Name -match '^(homelab-rmm-.*\.(zip|tar\.gz)|rmm-(server|agent)-.*)$' } | Sort-Object Name
    $lines = foreach ($f in $files) {
        $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
        "$hash  $($f.Name)"
    }
    # sha256sum -c expects LF line endings and no BOM
    [System.IO.File]::WriteAllText((Join-Path (Resolve-Path $Dist).Path 'SHA256SUMS'), (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "  wrote $Dist\SHA256SUMS"
}

function New-Packages {
    New-Item -ItemType Directory -Force -Path $Dist | Out-Null
    Get-ChildItem -Path $Dist -Filter 'homelab-rmm-*' -File -ErrorAction SilentlyContinue | Remove-Item -Force
    $tar = Get-Command tar.exe -ErrorAction SilentlyContinue
    foreach ($p in $serverPlatforms) {
        $parts = $p.Split('/')
        $os = $parts[0]; $arch = $parts[1]
        $name = "homelab-rmm-$os-$arch"
        $stage = Join-Path $Dist (Join-Path 'pkg' $name)
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
        New-Item -ItemType Directory -Force -Path (Join-Path $stage 'agents') | Out-Null
        $srv = Get-BinName 'rmm-server' $os $arch
        if (-not (Test-Path -LiteralPath $srv)) { throw "missing $srv (run: tools\build.ps1 -Target server)" }
        $srvName = if ($os -eq 'windows') { 'rmm-server.exe' } else { 'rmm-server' }
        Copy-Item -LiteralPath $srv -Destination (Join-Path $stage $srvName)
        foreach ($ap in $agentPlatforms) {
            $aparts = $ap.Split('/')
            $a = Get-BinName 'rmm-agent' $aparts[0] $aparts[1]
            if (-not (Test-Path -LiteralPath $a)) { throw "missing $a (run: tools\build.ps1 -Target agents)" }
            Copy-Item -LiteralPath $a -Destination (Join-Path $stage 'agents')
        }
        Copy-Item -LiteralPath 'README.md' -Destination $stage
        if (Test-Path 'CHANGELOG.md') { Copy-Item -LiteralPath 'CHANGELOG.md' -Destination $stage }
        if (Test-Path 'docs') { Copy-Item -LiteralPath 'docs' -Destination (Join-Path $stage 'docs') -Recurse }
        if (Test-Path 'deploy') { Copy-Item -LiteralPath 'deploy' -Destination (Join-Path $stage 'deploy') -Recurse }
        if (Test-Path 'LICENSE') {
            Copy-Item -LiteralPath 'LICENSE' -Destination (Join-Path $stage 'LICENSE')
        } else {
            [System.IO.File]::WriteAllText((Join-Path (Resolve-Path $stage).Path 'LICENSE'), "Homelab RMM $Version`n`nNo LICENSE file is present in this build. See the project repository for licensing terms.`n")
        }
        [System.IO.File]::WriteAllText((Join-Path (Resolve-Path $stage).Path 'VERSION'), "$Version`n")

        $zip = Join-Path (Resolve-Path $Dist).Path "$name.zip"
        New-ZipFromDirectory $stage $zip
        Write-Host "  packaged $Dist\$name.zip"
        if ($os -eq 'linux') {
            if ($tar) {
                $tgz = Join-Path (Resolve-Path $Dist).Path "$name.tar.gz"
                Invoke-Native $tar.Source @('-czf', $tgz, '-C', (Resolve-Path $stage).Path, '.')
                Write-Host "  packaged $Dist\$name.tar.gz"
            } else {
                Write-Warning "tar.exe not found; skipping $name.tar.gz (linux users must chmod +x after unzip)"
            }
        }
    }
    Remove-Item -LiteralPath (Join-Path $Dist 'pkg') -Recurse -Force
    Write-Checksums
}

function Remove-BuildOutput {
    if (Test-Path -LiteralPath $Dist) { Remove-Item -LiteralPath $Dist -Recurse -Force }
    Get-ChildItem -Path 'web\dist' -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '.gitkeep' } | Remove-Item -Recurse -Force
}

foreach ($t in $Target) {
    switch ($t) {
        'web'       { Build-Web }
        'server'    { Build-Server }
        'agents'    { Build-Agents }
        'all'       { Build-Web; Build-Server; Build-Agents }
        'test'      { Invoke-Tests }
        'package'   { New-Packages }
        'checksums' { Write-Checksums }
        'clean'     { Remove-BuildOutput }
    }
}
Write-Host "done ($Version)"
