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
                when tar.exe is available) and dist\SHA256SUMS. It archives what
                server/agents built and does NOT build the UI, and it refuses a
                binary older than the sources or web\dist it was built from.
      clean     remove dist\ and the built UI

    Needs go, node and npm on PATH.

    server and package refuse to run when web\dist\index.html is missing: rmm-server
    embeds web\dist, so such a build would ship with no console. Set the environment
    variable ALLOW_EMPTY_WEB=1 to build one on purpose (for use with --dev-web).

    Environment: VERSION (default: the output of git describe --tags --always),
    ALLOW_EMPTY_WEB, ALLOW_STALE_BUILD (packages a binary older than the sources
    anyway). Same names and meanings as tools/build.sh.

.EXAMPLE
    tools\build.ps1                       # everything
    tools\build.ps1 -Target server,agents # binaries only, reusing the existing web\dist
    tools\build.ps1 -Target package -Version v1.2.3
#>
[CmdletBinding()]
param(
    [ValidateSet('web', 'server', 'agents', 'all', 'test', 'package', 'msi', 'checksums', 'clean')]
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
    $v = 'dev'
    try {
        # Capture git's output whole, then read $LASTEXITCODE before anything else
        # runs. Piping the call into Select-Object -First 1 stops the upstream
        # pipeline as soon as it has its line, which kills the native process and
        # leaves $LASTEXITCODE = -1 under Windows PowerShell 5.1: the describe was
        # then thrown away and every Windows build stamped 'dev'.
        $out = & git describe --tags --always 2>$null
        $code = $LASTEXITCODE
        if ($code -eq 0 -and $out) {
            $first = ([string](@($out)[0])).Trim()
            if ($first) { $v = $first }
        }
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

function Assert-WebBuilt {
    # rmm-server embeds web\dist (web\embed.go, `go:embed all:dist`), and web\dist is
    # gitignored apart from .gitkeep: on a fresh clone the embed quietly succeeds with one
    # empty file, the Go build says nothing, and the archive ships a server whose console
    # is a directory listing. Check before any server binary is built.
    if ($env:ALLOW_EMPTY_WEB) {
        Write-Host '  ALLOW_EMPTY_WEB is set: building rmm-server without a built UI'
        return
    }
    if (-not (Test-Path -LiteralPath 'web\dist\index.html')) {
        throw "web\dist\index.html is missing: run 'tools\build.ps1 -Target web' first. rmm-server embeds web\dist, so this build would ship a server with no console. Set ALLOW_EMPTY_WEB=1 to build one on purpose."
    }
}

function Build-Server { Assert-WebBuilt; foreach ($p in $serverPlatforms) { Invoke-GoBuild 'rmm-server' $p } }
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

# The newest file this build is made from: every *.go, go.mod and go.sum in the
# tree (minus dist\, node_modules\ and .git\) plus everything under web\dist,
# which rmm-server embeds. tools/build.sh walks the tree once per binary with
# find(1); one cached walk gives the same verdict - "some source is newer than
# this binary" and "the newest source is newer than this binary" agree - and
# `package` checks two dozen binaries against it.
$script:newestSource = $null

function Get-NewestSource {
    if ($null -ne $script:newestSource) { return $script:newestSource }
    $newest = @{ Path = ''; Time = [datetime]::MinValue }
    $webDist = Join-Path $root 'web\dist'
    $distFull = ''
    if (Test-Path -LiteralPath $Dist) { $distFull = (Resolve-Path -LiteralPath $Dist).Path.TrimEnd('\') }
    $stack = New-Object System.Collections.Stack
    $stack.Push($root)
    while ($stack.Count -gt 0) {
        $dir = [string]$stack.Pop()
        $inWebDist = ($dir -eq $webDist) -or $dir.StartsWith($webDist + '\', [System.StringComparison]::OrdinalIgnoreCase)
        foreach ($e in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
            if ($e.PSIsContainer) {
                if ($e.Name -eq 'node_modules' -or $e.Name -eq '.git') { continue }
                if ($distFull -and $e.FullName.TrimEnd('\') -eq $distFull) { continue }
                $stack.Push($e.FullName)
                continue
            }
            if (-not ($inWebDist -or $e.Name -like '*.go' -or $e.Name -eq 'go.mod' -or $e.Name -eq 'go.sum')) { continue }
            if ($e.LastWriteTimeUtc -gt $newest.Time) {
                $newest.Time = $e.LastWriteTimeUtc
                $newest.Path = $e.FullName
            }
        }
    }
    $script:newestSource = $newest
    return $newest
}

function Assert-Fresh([string]$Binary, [string]$BuildTarget) {
    # package archives what server and agents left in dist\, so a run that skips
    # them ships whatever was built last time - a server binary that predates the
    # feature, beside the docs that describe it. Nothing about that archive looks
    # wrong until someone runs it, so it is refused here. Same guard, message and
    # escape hatch as fresh() in tools/build.sh.
    if ($env:ALLOW_STALE_BUILD) { return }
    $newest = Get-NewestSource
    if (-not $newest.Path) { return }
    $built = (Get-Item -LiteralPath $Binary).LastWriteTimeUtc
    if ($newest.Time -gt $built) {
        throw "$Binary is older than $($newest.Path): it would ship a binary built from different source than this tree. Run 'tools\build.ps1 -Target $BuildTarget' (or -Target all) first, or set ALLOW_STALE_BUILD=1 to package it anyway."
    }
}

function New-Packages {
    Assert-WebBuilt
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
        Assert-Fresh $srv 'server'
        $srvName = if ($os -eq 'windows') { 'rmm-server.exe' } else { 'rmm-server' }
        Copy-Item -LiteralPath $srv -Destination (Join-Path $stage $srvName)
        foreach ($ap in $agentPlatforms) {
            $aparts = $ap.Split('/')
            $a = Get-BinName 'rmm-agent' $aparts[0] $aparts[1]
            if (-not (Test-Path -LiteralPath $a)) { throw "missing $a (run: tools\build.ps1 -Target agents)" }
            Assert-Fresh $a 'agents'
            Copy-Item -LiteralPath $a -Destination (Join-Path $stage 'agents')
        }
        Copy-Item -LiteralPath 'README.md' -Destination $stage
        if (Test-Path 'CHANGELOG.md') { Copy-Item -LiteralPath 'CHANGELOG.md' -Destination $stage }
        if (Test-Path 'docs') { Copy-Item -LiteralPath 'docs' -Destination (Join-Path $stage 'docs') -Recurse }
        if (Test-Path 'deploy') { Copy-Item -LiteralPath 'deploy' -Destination (Join-Path $stage 'deploy') -Recurse }
        # The attributions the compiled-in components require have to be in
        # the archive, not just in the repository: this archive is a copy of
        # the software and carries their code inside the binaries.
        if (Test-Path 'THIRD-PARTY-NOTICES.md') {
            Copy-Item -LiteralPath 'THIRD-PARTY-NOTICES.md' -Destination (Join-Path $stage 'THIRD-PARTY-NOTICES.md')
        } else {
            throw "THIRD-PARTY-NOTICES.md is missing; the archive must carry the third-party attributions"
        }
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

# New-Msi builds the Windows installers with the WiX Toolset. MSI rather than a
# self-extracting .exe because the agent has to reach a fleet: msiexec takes the
# server URL and enrollment token as properties, and Group Policy, Intune and
# SCCM all deploy an MSI natively.
#
# WiX is not a build dependency for anything else, so this target is deliberately
# not part of -Target all: a machine without it can still build and package.
function New-Msi {
    $wix = Get-Command wix -ErrorAction SilentlyContinue
    if (-not $wix) {
        $candidate = Join-Path $env:ProgramFiles 'WiX Toolset v7.0\bin\wix.exe'
        if (Test-Path $candidate) { $wix = $candidate } else {
            throw "wix.exe not found. Install it with: winget install --id WiXToolset.WiXCLI, then accept the EULA with: wix eula accept wix7"
        }
    } else { $wix = $wix.Source }

    $agentExe  = Join-Path $Dist "rmm-agent-windows-amd64.exe"
    $serverExe = Join-Path $Dist "rmm-server-windows-amd64.exe"
    foreach ($exe in @($agentExe, $serverExe)) {
        if (-not (Test-Path $exe)) { throw "$exe is missing; run -Target all first" }
    }
    Assert-Fresh $agentExe  "agents"
    Assert-Fresh $serverExe "server"

    # An MSI ProductVersion must be numeric (a.b.c.d), so a describe like
    # v0.2.0-43-g1e3fc5d becomes 0.2.0.43. The full version still goes into the
    # binaries themselves via -ldflags.
    $msiVersion = Get-MsiVersion $Version
    $src = Join-Path $Root "installer\windows"
    $icon = Join-Path $src "homelab-rmm.ico"
    if (-not (Test-Path $icon)) { throw "$icon is missing; generate it with installer\windows\make-icon.ps1" }

    # The licence and the third-party attributions are installed beside the
    # executable, not merely kept in the repository: the permissive licences
    # of the compiled-in components require their notices to travel with any
    # copy of the software, and an MSI is a copy of the software.
    $license = Join-Path $Root "LICENSE"
    $notices = Join-Path $Root "THIRD-PARTY-NOTICES.md"
    foreach ($doc in @($license, $notices)) {
        if (-not (Test-Path $doc)) { throw "$doc is missing; the installers must carry it" }
    }
    foreach ($part in @(
        @{ Name = "rmm-agent";  Wxs = "rmm-agent.wxs";  VarName = "AgentExe";  Exe = $agentExe },
        @{ Name = "rmm-server"; Wxs = "rmm-server.wxs"; VarName = "ServerExe"; Exe = $serverExe }
    )) {
        $out = Join-Path $Dist ($part.Name + "-" + $Version + "-x64.msi")
        & $wix build (Join-Path $src $part.Wxs) `
            "-d" "Version=$msiVersion" `
            "-d" ($part.VarName + "=" + $part.Exe) `
            "-d" ("IconFile=" + $icon) `
            "-d" ("LicenseFile=" + $license) `
            "-d" ("NoticesFile=" + $notices) `
            "-ext" "WixToolset.Util.wixext" "-arch" "x64" "-o" $out
        if ($LASTEXITCODE -ne 0) { throw "wix build failed for $($part.Wxs)" }
        Write-Host "  msi $out"
    }
}

# Get-MsiVersion reduces a git describe to the numeric form Windows Installer
# accepts. v0.2.0-43-g1e3fc5d -> 0.2.0.43; a plain tag v0.2.0 -> 0.2.0.
function Get-MsiVersion([string]$v) {
    $m = [regex]::Match($v, "^v?(d+).(d+).(d+)(?:-(d+))?")
    if (-not $m.Success) { return "0.0.0.0" }
    $rev = if ($m.Groups[4].Success) { $m.Groups[4].Value } else { "0" }
    return "$($m.Groups[1].Value).$($m.Groups[2].Value).$($m.Groups[3].Value).$rev"
}

foreach ($t in $Target) {
    switch ($t) {
        'web'       { Build-Web }
        'server'    { Build-Server }
        'agents'    { Build-Agents }
        'all'       { Build-Web; Build-Server; Build-Agents }
        'test'      { Invoke-Tests }
        'package'   { New-Packages }
        'msi'       { New-Msi }
        'checksums' { Write-Checksums }
        'clean'     { Remove-BuildOutput }
    }
}
Write-Host "done ($Version)"
