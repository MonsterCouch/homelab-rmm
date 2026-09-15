package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Agent binaries live in <data>/agents/ (rmm-agent-windows-amd64.exe,
// rmm-agent-linux-amd64, ...). The release archive ships them alongside the
// server; the install script downloads the right one from here.
func (s *Server) agentBinaryPath(osName, arch string) string {
	name := fmt.Sprintf("rmm-agent-%s-%s", osName, arch)
	if osName == "windows" {
		name += ".exe"
	}
	candidates := []string{
		s.cfg.path(filepath.Join("agents", name)),
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "agents", name), filepath.Join(filepath.Dir(exe), name))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

// binHashes caches sha256(file) by path+size+mtime so rendering an install
// script does not re-read a 12 MB binary on every request.
var binHashes sync.Map

// agentBinarySHA256 is the hash of the binary this server would serve for
// os/arch, or "" when it has none.
//
// The install script carries it so the device can check what it downloaded.
// /api/agent-download is unauthenticated by design (the device has no key
// yet) and the bootstrap connection cannot validate a CA chain, so without
// this an on-path attacker could hand the enrolling machine any binary at all
// and get root/SYSTEM on it - on the very box the curl|sudo bash line runs on.
func (s *Server) agentBinarySHA256(osName, arch string) string {
	p := s.agentBinaryPath(osName, arch)
	if p == "" {
		return ""
	}
	st, err := os.Stat(p)
	if err != nil {
		return ""
	}
	key := fmt.Sprintf("%s|%d|%d", p, st.Size(), st.ModTime().UnixNano())
	if v, ok := binHashes.Load(key); ok {
		return v.(string)
	}
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	binHashes.Store(key, sum)
	return sum
}

func (s *Server) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	if strings.ContainsAny(file, `/\`) || !strings.HasPrefix(file, "rmm-agent-") {
		http.NotFound(w, r)
		return
	}
	// downloads are not authenticated: the binary is not secret and the
	// install script runs before the device has a key. Enrolment still needs
	// a valid token, and the script verifies the SHA-256 it was rendered with
	// before running what it got.
	for _, dir := range []string{s.cfg.path("agents")} {
		p := filepath.Join(dir, file)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			http.ServeFile(w, r, p)
			return
		}
	}
	if exe, err := os.Executable(); err == nil {
		for _, p := range []string{filepath.Join(filepath.Dir(exe), "agents", file), filepath.Join(filepath.Dir(exe), file)} {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				http.ServeFile(w, r, p)
				return
			}
		}
	}
	writeErr(w, 404, "agent binary not found on the server; place it in "+s.cfg.path("agents"))
}

var (
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	archRe  = regexp.MustCompile(`^(amd64|arm64|arm|386)$`)
	// linuxArches are the architectures the Linux script's uname -m mapping
	// can produce, and therefore the ones it needs a hash for.
	linuxArches = []string{"amd64", "arm64", "arm"}
)

// handleInstallScript renders the platform install script for a token. The
// script is piped into an elevated shell on the device, so every value that
// lands in it is whitelisted: the token must be a real, unexpired enrolment
// token (404 otherwise, which also stops the endpoint acting as a script
// injection oracle) and the architecture must be one we ship.
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !tokenRe.MatchString(token) || s.db.checkEnrollToken(token) != nil {
		http.NotFound(w, r)
		return
	}
	arch := r.URL.Query().Get("arch")
	if arch == "" {
		arch = "amd64"
	}
	if !archRe.MatchString(arch) {
		writeErr(w, http.StatusBadRequest, "unsupported arch")
		return
	}
	url := s.PublicURL()
	fp := s.fingerprint
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Query().Get("os") {
	case "windows":
		fmt.Fprint(w, render(windowsInstall, map[string]string{
			"SERVER": psQuote(url),
			"TOKEN":  psQuote(token),
			"FP":     psQuote(fp),
			"ARCH":   psQuote(arch),
			"SUM":    psQuote(s.agentBinarySHA256("windows", arch)),
		}))
	default:
		fmt.Fprint(w, render(linuxInstall, map[string]string{
			"SERVER": shQuote(url),
			"TOKEN":  shQuote(token),
			"FP":     shQuote(fp),
			"PIN":    shQuote(s.pubkeyPin),
			"SUMS":   s.linuxSumCases(),
		}))
	}
}

// linuxSumCases renders the `case "$ARCH"` arms that give the Linux script the
// expected hash for whichever architecture uname -m turns out to be.
func (s *Server) linuxSumCases() string {
	arches := append([]string(nil), linuxArches...)
	sort.Strings(arches)
	var b strings.Builder
	for _, a := range arches {
		if sum := s.agentBinarySHA256("linux", a); sum != "" {
			fmt.Fprintf(&b, "    %s) SUM='%s' ;;\n", a, shQuote(sum))
		}
	}
	return b.String()
}

// render substitutes @@NAME@@ placeholders. strings.Replacer walks the
// template once and never rescans what it wrote, so a value that contains a
// placeholder cannot introduce another substitution.
func render(tmpl string, vals map[string]string) string {
	pairs := make([]string, 0, len(vals)*2)
	for k, v := range vals {
		pairs = append(pairs, "@@"+k+"@@", v)
	}
	return strings.NewReplacer(pairs...).Replace(tmpl)
}

// psQuote escapes for a single-quoted PowerShell literal, where a quote is
// written by doubling it (”).
func psQuote(v string) string { return strings.ReplaceAll(v, "'", "''") }

// shQuote escapes for a single-quoted POSIX shell literal, which cannot
// contain a quote at all: close, emit an escaped quote, reopen.
func shQuote(v string) string { return strings.ReplaceAll(v, "'", `'\''`) }

const windowsInstall = `# Homelab RMM agent installer
$ErrorActionPreference = 'Stop'
$server = '@@SERVER@@'
$token = '@@TOKEN@@'
$fp = '@@FP@@'
$arch = '@@ARCH@@'
$sum = '@@SUM@@'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this from an elevated (Administrator) PowerShell.'
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# This device has never seen the server's certificate, so it cannot be checked
# against a CA - but it does not have to be accepted blindly either. Trust
# exactly the certificate whose SHA-256 this script carries, which is the one
# the agent pins for every connection afterwards.
if ('@@FP@@') {
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($sender, $certificate, $chain, $sslErrors)
        if ($sslErrors -eq [Net.Security.SslPolicyErrors]::None) { return $true }
        $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($certificate.GetRawCertData())
        return ([BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant() -eq '@@FP@@')
    }
}
$dir = Join-Path $env:ProgramFiles 'HomelabRMM'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir 'rmm-agent.exe'
Write-Host "Downloading agent from $server ..."
(New-Object Net.WebClient).DownloadFile("$server/api/agent-download/rmm-agent-windows-$arch.exe", "$exe.new")
# The download endpoint is unauthenticated, so what arrived is checked against
# the hash of the file the server rendered this script from.
if (-not $sum) {
    Remove-Item -Force "$exe.new" -ErrorAction SilentlyContinue
    Write-Error "this server has no rmm-agent-windows-$arch.exe to verify the download against; put the agent binaries in its agents\ directory"
}
$stream = [IO.File]::OpenRead("$exe.new")
try {
    $got = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
} finally { $stream.Close() }
if ($got -ne $sum) {
    Remove-Item -Force "$exe.new" -ErrorAction SilentlyContinue
    Write-Error "the downloaded agent does not match the expected SHA-256 (got $got, expected $sum); refusing to install"
}
Write-Host 'Download verified.'
$svc = Get-Service -Name HomelabRMMAgent -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    Write-Host 'Stopping the running agent ...'
    Stop-Service -Name HomelabRMMAgent -Force -ErrorAction SilentlyContinue
    # WaitForStatus is a .NET call and throws TimeoutException, which
    # $ErrorActionPreference = 'Stop' would turn into an abort - killing the
    # process wait and the retry loop below, which are what actually handle a
    # service that is slow to die.
    try { $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)) }
    catch { Write-Host 'The service did not report Stopped within 60s; continuing.' }
}
for ($i = 0; $i -lt 20; $i++) {
    if (-not (Get-Process -Name rmm-agent -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 500
}
$swapped = $false
for ($i = 0; $i -lt 10 -and -not $swapped; $i++) {
    try { Move-Item -Force "$exe.new" $exe; $swapped = $true } catch { Start-Sleep -Seconds 1 }
}
if (-not $swapped) { Write-Error "could not replace $exe (still in use)" }
& $exe install --server $server --token $token --fingerprint $fp
if ($LASTEXITCODE -ne 0) { Write-Error "install failed ($LASTEXITCODE)" }
Write-Host 'Agent installed and started. It should appear in the console within a few seconds.'
`

const linuxInstall = `#!/bin/bash
# Homelab RMM agent installer
set -euo pipefail
SERVER='@@SERVER@@'
TOKEN='@@TOKEN@@'
FP='@@FP@@'
PIN='@@PIN@@'
ARCH=$(uname -m); case "$ARCH" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; armv7l) ARCH=arm;; esac
# SHA-256 of the binary this server would serve, per architecture.
SUM=''
case "$ARCH" in
@@SUMS@@esac
if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)"; exit 1; fi
mkdir -p /opt/homelab-rmm
NEW=/opt/homelab-rmm/rmm-agent.new
echo "Downloading agent from $SERVER ..."
# This device has never seen the server's certificate, so the CA chain cannot
# be checked - but curl can still pin the server's public key, which is the
# same key the agent pins afterwards. -k only skips the chain; --pinnedpubkey
# is enforced regardless. Without pinning support, the SHA-256 check below is
# what stands between an on-path attacker and root on this machine.
CURL=(curl -fsS)
if [ -n "$PIN" ] && curl --help all 2>/dev/null | grep -q -- '--pinnedpubkey'; then
    CURL+=(-k --pinnedpubkey "sha256//$PIN")
elif [ -n "$FP" ]; then
    CURL+=(-k)
fi
"${CURL[@]}" -o "$NEW" "$SERVER/api/agent-download/rmm-agent-linux-$ARCH"
# The download endpoint is unauthenticated, so what arrived is checked against
# the hash of the file the server rendered this script from.
if [ -z "$SUM" ]; then
    rm -f "$NEW"
    echo "this server has no rmm-agent-linux-$ARCH to verify the download against; put the agent binaries in its agents/ directory" >&2
    exit 1
fi
GOT=$(sha256sum "$NEW" 2>/dev/null | awk '{print $1}' || true)
[ -n "$GOT" ] || GOT=$(shasum -a 256 "$NEW" 2>/dev/null | awk '{print $1}' || true)
[ -n "$GOT" ] || GOT=$(openssl dgst -sha256 "$NEW" 2>/dev/null | awk '{print $NF}' || true)
if [ -z "$GOT" ]; then
    rm -f "$NEW"
    echo "no sha256 tool (sha256sum, shasum or openssl) to verify the download" >&2
    exit 1
fi
if [ "$GOT" != "$SUM" ]; then
    rm -f "$NEW"
    echo "the downloaded agent does not match the expected SHA-256 (got $GOT, expected $SUM); refusing to install" >&2
    exit 1
fi
echo "Download verified."
chmod 755 "$NEW"
systemctl stop HomelabRMMAgent 2>/dev/null || true
mv -f "$NEW" /opt/homelab-rmm/rmm-agent
/opt/homelab-rmm/rmm-agent install --server "$SERVER" --token "$TOKEN" --fingerprint "$FP"
echo "Agent installed and started."
`
