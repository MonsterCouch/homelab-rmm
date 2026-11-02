// Package cache is the agent's side of the local subnet cache (docs/plans/
// 2026-10-24-phase4b-mesh-cache.md): a content-addressable store, the leader
// server that fronts it over HTTPS and HTTP/3, and the client a member uses to
// fetch an artifact from its leader with an origin fallback.
package cache

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	certFile = "cache.crt"
	keyFile  = "cache.key"
)

// LoadOrCreateCert returns the leader certificate kept in dir, generating a
// self-signed one on first use, together with the SHA-256 fingerprint of its
// leaf in hex. The certificate is persisted so the fingerprint the device
// reported in its hello survives a restart: members pin it, and a new one on
// every start would strand them until the next config push. A pair that is
// unreadable, expired or inconsistent is replaced rather than failing, because
// the cache is optional and must never keep the agent from starting.
func LoadOrCreateCert(dir string) (tls.Certificate, string, error) {
	crtPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	if c, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil && len(c.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil && time.Now().Before(leaf.NotAfter.Add(-24*time.Hour)) {
			return c, Fingerprint(c.Certificate[0]), nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create the cache directory %s: %w", dir, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate the cache certificate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate the cache certificate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "homelab-rmm subnet cache"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create the cache certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("encode the cache certificate key: %w", err)
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("write the cache certificate key: %w", err)
	}
	if err := os.WriteFile(crtPath, crtPEM, 0o600); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("write the cache certificate: %w", err)
	}
	c, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("load the new cache certificate: %w", err)
	}
	return c, Fingerprint(der), nil
}

// Fingerprint is the SHA-256 of a DER certificate in lower-case hex, the form
// the server's AgentConfig carries and the agent pins.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// PinnedTLS is a client TLS configuration that trusts exactly the certificate
// with the given fingerprint and nothing else: the leader's certificate is
// self-signed and carries no usable name, so the pin is the whole identity.
func PinnedTLS(fingerprint string) *tls.Config {
	fp := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // verified against the pin just below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if fp == "" {
				return errors.New("the cache leader has no certificate fingerprint to pin")
			}
			if len(raw) == 0 {
				return errors.New("the cache leader presented no certificate")
			}
			if got := Fingerprint(raw[0]); got != fp {
				return fmt.Errorf("the cache leader certificate fingerprint does not match the pinned one: got %s", got)
			}
			return nil
		},
	}
}
