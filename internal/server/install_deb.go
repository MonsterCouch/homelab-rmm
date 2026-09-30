package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// buildDebPackage creates an authentic Debian/Ubuntu (.deb) package in pure Go
// containing the agent binary, systemd service, and pre-configured agent.json.
func (s *Server) buildDebPackage(token, arch string) ([]byte, error) {
	if arch == "" {
		arch = "amd64"
	}
	agentBinPath := s.agentBinaryPath("linux", arch)
	if agentBinPath == "" {
		return nil, fmt.Errorf("linux agent binary not found on server for arch %s", arch)
	}

	binBytes, err := os.ReadFile(agentBinPath)
	if err != nil || len(binBytes) == 0 {
		return nil, fmt.Errorf("failed to read linux agent binary for arch %s: %w", arch, err)
	}

	// 1. Prepare configuration payload (agent.json)
	fp := strings.ToLower(strings.ReplaceAll(s.PinFingerprint(), ":", ""))
	cfgJSON, _ := json.MarshalIndent(map[string]string{
		"server_url":   s.PublicURL(),
		"enroll_token": token,
		"fingerprint":  fp,
	}, "", "  ")

	// 2. Build data.tar.gz
	var dataBuf bytes.Buffer
	gwData := gzip.NewWriter(&dataBuf)
	twData := tar.NewWriter(gwData)

	now := time.Now()

	// /usr/bin/rmm-agent
	twData.WriteHeader(&tar.Header{
		Name:     "./usr/bin/rmm-agent",
		Mode:     0o755,
		Size:     int64(len(binBytes)),
		ModTime:  now,
		Typeflag: tar.TypeReg,
	})
	twData.Write(binBytes)

	// /etc/homelab-rmm/agent.json
	twData.WriteHeader(&tar.Header{
		Name:     "./etc/homelab-rmm/agent.json",
		Mode:     0o600,
		Size:     int64(len(cfgJSON)),
		ModTime:  now,
		Typeflag: tar.TypeReg,
	})
	twData.Write(cfgJSON)

	// /lib/systemd/system/rmm-agent.service
	serviceContent := `[Unit]
Description=Homelab RMM Agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/rmm-agent run
Restart=always
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`
	twData.WriteHeader(&tar.Header{
		Name:     "./lib/systemd/system/rmm-agent.service",
		Mode:     0o644,
		Size:     int64(len(serviceContent)),
		ModTime:  now,
		Typeflag: tar.TypeReg,
	})
	io.WriteString(twData, serviceContent)

	twData.Close()
	gwData.Close()
	dataTarGz := dataBuf.Bytes()

	// 3. Build control.tar.gz
	controlContent := fmt.Sprintf(`Package: homelab-rmm-agent
Version: %s
Section: admin
Priority: optional
Architecture: %s
Maintainer: Homelab RMM <admin@homelab-rmm>
Description: Homelab RMM endpoint monitoring and management agent
`, Version, arch)

	postinstContent := `#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    systemctl daemon-reload || true
    systemctl enable --now rmm-agent || true
fi
exit 0
`

	prermContent := `#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl stop rmm-agent || true
    systemctl disable rmm-agent || true
fi
exit 0
`

	var ctlBuf bytes.Buffer
	gwCtl := gzip.NewWriter(&ctlBuf)
	twCtl := tar.NewWriter(gwCtl)

	twCtl.WriteHeader(&tar.Header{
		Name:     "./control",
		Mode:     0o644,
		Size:     int64(len(controlContent)),
		ModTime:  now,
		Typeflag: tar.TypeReg,
	})
	io.WriteString(twCtl, controlContent)

	twCtl.WriteHeader(&tar.Header{
		Name:     "./postinst",
		Mode:     0o755,
		Size:     int64(len(postinstContent)),
		ModTime:  now,
		Typeflag: tar.TypeReg,
	})
	io.WriteString(twCtl, postinstContent)

	twCtl.WriteHeader(&tar.Header{
		Name:     "./prerm",
		Mode:     0o755,
		Size:     int64(len(prermContent)),
		ModTime:  now,
		Typeflag: tar.TypeReg,
	})
	io.WriteString(twCtl, prermContent)

	twCtl.Close()
	gwCtl.Close()
	controlTarGz := ctlBuf.Bytes()

	// 4. Assemble the ar archive (.deb format)
	var debBuf bytes.Buffer
	// ar signature
	debBuf.WriteString("!<arch>\n")

	// Member 1: debian-binary
	debBinary := "2.0\n"
	writeArHeader(&debBuf, "debian-binary", int64(len(debBinary)), 0o644)
	debBuf.WriteString(debBinary)

	// Member 2: control.tar.gz
	writeArHeader(&debBuf, "control.tar.gz", int64(len(controlTarGz)), 0o644)
	debBuf.Write(controlTarGz)
	if len(controlTarGz)%2 != 0 {
		debBuf.WriteByte('\n')
	}

	// Member 3: data.tar.gz
	writeArHeader(&debBuf, "data.tar.gz", int64(len(dataTarGz)), 0o644)
	debBuf.Write(dataTarGz)
	if len(dataTarGz)%2 != 0 {
		debBuf.WriteByte('\n')
	}

	return debBuf.Bytes(), nil
}

// writeArHeader writes a standard 60-byte ar file member header.
func writeArHeader(w io.Writer, name string, size int64, mode int) {
	// 16 bytes: filename, padded with spaces (GNU/Debian standard)
	fn := fmt.Sprintf("%-16s", name)
	if len(fn) > 16 {
		fn = fn[:16]
	}
	// 12 bytes: mtime (0 for reproducible build)
	mtime := fmt.Sprintf("%-12d", time.Now().Unix())
	// 6 bytes: uid
	uid := fmt.Sprintf("%-6d", 0)
	// 6 bytes: gid
	gid := fmt.Sprintf("%-6d", 0)
	// 8 bytes: mode in octal
	modeStr := fmt.Sprintf("%-8o", mode)
	// 10 bytes: size in decimal
	sizeStr := fmt.Sprintf("%-10d", size)
	// 2 bytes: magic trailer
	trailer := "`\n"

	header := fn + mtime + uid + gid + modeStr + sizeStr + trailer
	io.WriteString(w, header)
}
