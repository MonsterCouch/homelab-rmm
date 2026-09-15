package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

func (s *Server) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	if strings.ContainsAny(file, `/\`) || !strings.HasPrefix(file, "rmm-agent-") {
		http.NotFound(w, r)
		return
	}
	// downloads are not authenticated: the binary is not secret and the
	// install script runs before the device has a key. Enrolment still needs
	// a valid token.
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

// handleInstallScript renders the platform install script for a token. The
// token is validated only at enrolment, so this endpoint leaks nothing beyond
// the server URL an attacker already has.
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	url := s.PublicURL()
	fp := s.fingerprint
	arch := r.URL.Query().Get("arch")
	if arch == "" {
		arch = "amd64"
	}
	switch r.URL.Query().Get("os") {
	case "windows":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, windowsInstall, url, token, fp, arch)
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, linuxInstall, url, token, fp)
	}
}

const windowsInstall = `# Homelab RMM agent installer
$ErrorActionPreference = 'Stop'
$server = '%s'
$token = '%s'
$fp = '%s'
$arch = '%s'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this from an elevated (Administrator) PowerShell.'
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$dir = Join-Path $env:ProgramFiles 'HomelabRMM'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir 'rmm-agent.exe'
Write-Host "Downloading agent from $server ..."
(New-Object Net.WebClient).DownloadFile("$server/api/agent-download/rmm-agent-windows-$arch.exe", "$exe.new")
& sc.exe stop HomelabRMMAgent 2>$null | Out-Null
Start-Sleep -Seconds 1
Move-Item -Force "$exe.new" $exe
& $exe install --server $server --token $token --fingerprint $fp
if ($LASTEXITCODE -ne 0) { Write-Error "install failed ($LASTEXITCODE)" }
Write-Host 'Agent installed and started. It should appear in the console within a few seconds.'
`

const linuxInstall = `#!/bin/bash
# Homelab RMM agent installer
set -euo pipefail
SERVER='%s'
TOKEN='%s'
FP='%s'
ARCH=$(uname -m); case "$ARCH" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; armv7l) ARCH=arm;; esac
if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)"; exit 1; fi
mkdir -p /opt/homelab-rmm
echo "Downloading agent from $SERVER ..."
curl -fsSk -o /opt/homelab-rmm/rmm-agent.new "$SERVER/api/agent-download/rmm-agent-linux-$ARCH"
chmod 755 /opt/homelab-rmm/rmm-agent.new
systemctl stop homelab-rmm-agent 2>/dev/null || true
mv -f /opt/homelab-rmm/rmm-agent.new /opt/homelab-rmm/rmm-agent
/opt/homelab-rmm/rmm-agent install --server "$SERVER" --token "$TOKEN" --fingerprint "$FP"
echo "Agent installed and started."
`
