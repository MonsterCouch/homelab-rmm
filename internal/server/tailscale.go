package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Tailscale certificates.
//
// `tailscale cert` gets a real Let's Encrypt certificate for a tailnet name,
// which is worth having for one reason above all: it removes pinning from the
// picture. Agents use the system trust store, browsers stop warning, and the
// Android app does not need the fingerprint path at all.
//
// The catch is that those certificates last 90 days, so minting one at install
// time only moves the outage a quarter into the future. That is why this lives
// in the server rather than in the installer: the process that serves the
// certificate is the one that can renew it and pick the new one up without
// anybody being told to.

const (
	// tailscaleCertTimeout bounds one issuance. The first one talks to Let's
	// Encrypt; a renewal is usually instant because Tailscale caches.
	tailscaleCertTimeout = 90 * time.Second
	// tailscaleRenewEvery is how often the server re-asks. Tailscale only
	// re-issues near expiry, so asking daily is cheap and means a renewal is
	// picked up within a day of happening rather than at the next restart.
	tailscaleRenewEvery = 24 * time.Hour
)

// tailscaleExe finds the CLI. On Windows it is not on PATH for a service.
func tailscaleExe() (string, error) {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p, nil
	}
	candidates := []string{"/usr/bin/tailscale", "/usr/local/bin/tailscale"}
	if runtime.GOOS == "windows" {
		candidates = []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Tailscale", "tailscale.exe"),
			filepath.Join(os.Getenv("ProgramW6432"), "Tailscale", "tailscale.exe"),
			`C:\Program Files\Tailscale\tailscale.exe`,
		}
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", errors.New("the tailscale CLI was not found")
}

// tailscaleDNSName is this machine's own tailnet name, without the trailing
// dot that the status output carries.
func tailscaleDNSName(ctx context.Context, exe string) (string, error) {
	out, err := exec.CommandContext(ctx, exe, "status", "--json").Output()
	if err != nil {
		return "", fmt.Errorf("tailscale status: %w", err)
	}
	var st struct {
		Self struct {
			DNSName string `json:"DNSName"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return "", fmt.Errorf("tailscale status: %w", err)
	}
	name := strings.TrimSuffix(st.Self.DNSName, ".")
	if name == "" {
		return "", errors.New("tailscale reports no name for this machine (is it logged in?)")
	}
	return name, nil
}

// mintTailscaleCert asks Tailscale for a certificate for host, writing the
// pair into dir, and returns the two paths. Asking again for a certificate
// that is still valid is a no-op that rewrites the same bytes, which is what
// makes the renewal loop safe to run on a timer.
func mintTailscaleCert(ctx context.Context, exe, dir, host string) (certFile, keyFile string, err error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", err
	}
	certFile = filepath.Join(dir, host+".crt")
	keyFile = filepath.Join(dir, host+".key")
	cmd := exec.CommandContext(ctx, exe, "cert", "--cert-file", certFile, "--key-file", keyFile, host)
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return "", "", fmt.Errorf("tailscale cert %s: %s", host, msg)
	}
	return certFile, keyFile, nil
}

// tailscaleCertHost is the name to ask for: the public URL's host when it
// looks like a tailnet name, and whatever Tailscale calls this machine
// otherwise. Asking for a name that is not ours fails, so preferring the
// configured host only when it is plausible avoids a confusing error on a
// server whose public URL is a different DNS name entirely.
func (s *Server) tailscaleCertHost(ctx context.Context, exe string) (string, error) {
	if h := hostOf(s.PublicURL()); strings.HasSuffix(h, ".ts.net") {
		return h, nil
	}
	return tailscaleDNSName(ctx, exe)
}

// setupTailscaleCert mints a certificate before the listener starts and points
// the configuration at it. Any failure is a warning, never fatal: a server that
// cannot reach Tailscale must still come up on its self-signed certificate
// rather than refuse to start.
func (s *Server) setupTailscaleCert() {
	exe, err := tailscaleExe()
	if err != nil {
		slog.Warn("tailscale certificate requested but unavailable; falling back to a self-signed one", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), tailscaleCertTimeout)
	defer cancel()

	host, err := s.tailscaleCertHost(ctx, exe)
	if err != nil {
		slog.Warn("tailscale certificate requested but the name is unknown; falling back to a self-signed one", "err", err)
		return
	}
	certFile, keyFile, err := mintTailscaleCert(ctx, exe, s.cfg.path("certs"), host)
	if err != nil {
		slog.Warn("tailscale certificate requested but could not be issued; falling back to a self-signed one",
			"host", host, "err", err,
			"hint", "HTTPS certificates must be enabled for the tailnet in the admin console")
		return
	}
	s.cfg.CertFile, s.cfg.KeyFile = certFile, keyFile
	s.tsCertHost = host
	slog.Info("using a tailscale certificate", "host", host, "cert", certFile)
}

// renewTailscaleCert re-asks for the certificate on a timer and swaps it in
// when the bytes on disk change. The listener reads the certificate through
// GetCertificate, so this takes effect on the next handshake with no restart
// and no dropped connection.
func (s *Server) renewTailscaleCert(ctx context.Context) {
	exe, err := tailscaleExe()
	if err != nil {
		return
	}
	t := time.NewTicker(tailscaleRenewEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		mintCtx, cancel := context.WithTimeout(ctx, tailscaleCertTimeout)
		certFile, keyFile, err := mintTailscaleCert(mintCtx, exe, s.cfg.path("certs"), s.tsCertHost)
		cancel()
		if err != nil {
			slog.Warn("tailscale certificate renewal failed; the current one is still being served", "err", err)
			continue
		}
		cert, fp, err := loadCertPair(certFile, keyFile)
		if err != nil {
			slog.Warn("tailscale certificate renewal produced a pair that will not load", "err", err)
			continue
		}
		if fp == s.Fingerprint() {
			continue // unchanged, which is the usual case
		}
		s.swapCert(cert, fp)
		slog.Info("tailscale certificate renewed", "host", s.tsCertHost, "fingerprint", fp,
			"note", "agents using system trust are unaffected; any agent pinned to the old fingerprint must be re-enrolled")
	}
}

// loadCertPair reads a certificate and key from disk and returns it with its
// fingerprint.
func loadCertPair(certFile, keyFile string) (*tls.Certificate, string, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, "", err
	}
	return &cert, Fingerprint(cert.Certificate[0]), nil
}

// swapCert replaces the certificate the listener serves.
func (s *Server) swapCert(cert *tls.Certificate, fp string) {
	s.certMu.Lock()
	s.cert = cert
	s.fingerprint = fp
	s.pubkeyPin = PublicKeyPin(cert.Certificate[0])
	s.certMu.Unlock()
	s.checkCertHost()
	s.refreshCertTrust()
}

// currentCert is the TLS config's GetCertificate hook. Serving through a hook
// rather than a fixed Certificates slice is what lets a renewal take effect
// without a restart.
func (s *Server) currentCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if s.cert == nil {
		return nil, errors.New("no certificate is loaded")
	}
	return s.cert, nil
}

// Fingerprint is the SHA-256 of the certificate being served, and the empty
// string when there is nothing for an agent to pin.
func (s *Server) Fingerprint() string {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	return s.fingerprint
}

// PinFingerprint is the fingerprint an enrolling agent should pin, which is
// the empty string when the certificate is publicly trusted.
//
// This is the difference between a fleet that keeps working and one that stops
// in 90 days. A pin is a promise about one specific certificate; a publicly
// trusted certificate is designed to be replaced, and a Tailscale or Let's
// Encrypt one is replaced every few months. Handing out a pin for a
// certificate that will certainly be rotated hard-codes an expiry date into
// every agent, so when the chain verifies on its own we hand out nothing and
// the agent uses system trust.
func (s *Server) PinFingerprint() string {
	if s.publiclyTrusted() {
		return ""
	}
	return s.Fingerprint()
}

// publiclyTrusted reports whether the served certificate verifies against the
// host's own trust store for the public URL's host.
func (s *Server) publiclyTrusted() bool {
	s.certMu.Lock()
	trusted := s.certTrusted
	s.certMu.Unlock()
	return trusted
}

// refreshCertTrust recomputes whether the certificate needs pinning. Done once
// per certificate rather than per request: it builds a chain, which is not
// free, and the answer only changes when the certificate does.
func (s *Server) refreshCertTrust() {
	trusted := false
	defer func() {
		s.certMu.Lock()
		s.certTrusted = trusted
		s.certMu.Unlock()
	}()

	s.certMu.Lock()
	cert := s.cert
	s.certMu.Unlock()
	if cert == nil || len(cert.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	host := hostOf(s.PublicURL())
	if host == "" {
		return
	}
	// Intermediates the server serves are part of the chain a client sees.
	inter := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err == nil {
		trusted = true
	}
}
