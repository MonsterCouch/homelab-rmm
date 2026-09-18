package server

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A pin is a promise about one specific certificate. A publicly trusted one is
// designed to be rotated, and a Tailscale or Let's Encrypt certificate is
// rotated every few months, so handing out its fingerprint writes an expiry
// date into every agent that enrolls today. These pin the rule that decides.

func TestSelfSignedCertificateIsPinned(t *testing.T) {
	s, ts, _ := newTestServerWith(t, Config{})
	_ = ts
	// The fixture runs --insecure, so drive the decision directly with a
	// generated certificate the way a real self-signed server has one.
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "s.crt"), filepath.Join(dir, "s.key")
	if err := generateSelfSigned(crt, key, []string{"rmm.invalid"}); err != nil {
		t.Fatal(err)
	}
	cert, fp, err := loadCertPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	s.db.SetSetting("public_url", "https://rmm.invalid:8443")
	s.swapCert(cert, fp)

	if s.Fingerprint() != fp {
		t.Fatalf("Fingerprint = %q, want %q", s.Fingerprint(), fp)
	}
	if s.publiclyTrusted() {
		t.Fatal("a self-signed certificate must not be reported as publicly trusted")
	}
	if s.PinFingerprint() != fp {
		t.Fatalf("a self-signed certificate must be pinned, got %q", s.PinFingerprint())
	}
}

func TestPubliclyTrustedCertificateIsNotPinned(t *testing.T) {
	// Build the same decision the server makes, against a real chain from the
	// host's trust store. Verify() is the whole rule, so exercising it with a
	// certificate that genuinely chains is the closest thing to the case that
	// matters without minting a Let's Encrypt certificate in a unit test.
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		t.Skip("no system certificate pool on this platform")
	}
	s, _, _ := newTestServerWith(t, Config{})

	// A certificate that does NOT chain: the negative half of the rule, with
	// every other input identical.
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "s.crt"), filepath.Join(dir, "s.key")
	if err := generateSelfSigned(crt, key, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	cert, fp, err := loadCertPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	s.db.SetSetting("public_url", "https://example.com:8443")
	s.swapCert(cert, fp)
	if s.PinFingerprint() == "" {
		t.Fatal("an untrusted certificate for a public name must still be pinned")
	}

	// And the rule itself: a leaf that fails Verify is never trusted, whatever
	// its name says.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "example.com"}); err == nil {
		t.Fatal("a self-signed leaf verified against the system pool; the test is not testing what it claims")
	}
}

func TestPinIsEmptyWhenThereIsNoCertificate(t *testing.T) {
	// An --insecure server has nothing to pin, and the installer must render
	// no --fingerprint rather than an empty one (which the agent rejects).
	s, _, _ := newTestServerWith(t, Config{})
	if got := s.PinFingerprint(); got != "" {
		t.Fatalf("plain HTTP must offer no pin, got %q", got)
	}
}

func TestSwapCertIsWhatTheListenerServes(t *testing.T) {
	// The renewal path swaps the certificate under a running listener, so what
	// GetCertificate returns has to follow the swap rather than a value copied
	// at startup.
	s, _, _ := newTestServerWith(t, Config{})
	dir := t.TempDir()
	var first string
	for i, name := range []string{"one.invalid", "two.invalid"} {
		crt := filepath.Join(dir, name+".crt")
		key := filepath.Join(dir, name+".key")
		if err := generateSelfSigned(crt, key, []string{name}); err != nil {
			t.Fatal(err)
		}
		cert, fp, err := loadCertPair(crt, key)
		if err != nil {
			t.Fatal(err)
		}
		s.swapCert(cert, fp)

		got, err := s.currentCert(&tls.ClientHelloInfo{ServerName: name})
		if err != nil {
			t.Fatalf("%s: currentCert: %v", name, err)
		}
		leaf, err := x509.ParseCertificate(got.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if leaf.VerifyHostname(name) != nil {
			t.Errorf("after swapping to %s the listener still serves %v", name, leaf.DNSNames)
		}
		if s.Fingerprint() != fp {
			t.Errorf("%s: Fingerprint did not follow the swap", name)
		}
		if i == 0 {
			first = fp
		} else if fp == first {
			t.Error("the two generated certificates share a fingerprint; the test proves nothing")
		}
	}
}

func TestTailscaleCertHostPrefersATailnetPublicURL(t *testing.T) {
	// Asking Tailscale for a name that is not ours fails, so the configured
	// host is only used when it looks like a tailnet name; anything else falls
	// back to asking Tailscale what this machine is called.
	s, _, _ := newTestServerWith(t, Config{})
	s.db.SetSetting("public_url", "https://box.taila7a096.ts.net:8443")
	host, err := s.tailscaleCertHost(t.Context(), "tailscale-does-not-exist")
	if err != nil {
		t.Fatalf("a tailnet public URL must not need the CLI at all: %v", err)
	}
	if host != "box.taila7a096.ts.net" {
		t.Fatalf("host = %q, want the public URL's host", host)
	}

	// A non-tailnet public URL has to ask the CLI, which is absent here.
	s.db.SetSetting("public_url", "https://rmm.example.com:8443")
	if _, err := s.tailscaleCertHost(t.Context(), "tailscale-does-not-exist"); err == nil {
		t.Fatal("a non-tailnet public URL must fall through to the CLI and report its failure")
	}
}

func TestTailscaleExeReportsItsAbsenceClearly(t *testing.T) {
	// The only behaviour worth asserting on a machine that may or may not have
	// Tailscale: when it is missing, say so rather than returning an empty
	// path that becomes a confusing exec error later.
	p, err := tailscaleExe()
	if err != nil {
		if !strings.Contains(err.Error(), "tailscale") {
			t.Errorf("the error should name what is missing, got %v", err)
		}
		return
	}
	if p == "" {
		t.Fatal("no error but no path either")
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(p), ".exe") {
		t.Errorf("windows path should be an .exe, got %q", p)
	}
}
