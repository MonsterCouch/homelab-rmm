package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// loadOrCreateCert returns the server certificate. If the operator supplied
// one it is used as is; otherwise a self-signed ECDSA certificate is written
// to the data directory on first run and reused thereafter. Agents pin its
// SHA-256 fingerprint at enrolment, so a self-signed certificate is as safe
// as a public one for the agent channel; browsers will warn once until the
// operator imports it or supplies their own.
func loadOrCreateCert(cfg Config, hosts []string) (tls.Certificate, string, error) {
	certFile, keyFile := cfg.CertFile, cfg.KeyFile
	if certFile == "" || keyFile == "" {
		certFile, keyFile = cfg.path("server.crt"), cfg.path("server.key")
		if _, err := os.Stat(certFile); err != nil {
			if err := generateSelfSigned(certFile, keyFile, hosts); err != nil {
				return tls.Certificate{}, "", err
			}
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("load certificate: %w", err)
	}
	return cert, Fingerprint(cert.Certificate[0]), nil
}

// Fingerprint is the SHA-256 of the DER certificate, lower-case hex, no colons.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// PublicKeyPin is base64(sha256(SubjectPublicKeyInfo)) - the shape curl's
// --pinnedpubkey wants, so the install script can pin the download connection
// to the same key the agent pins for every connection afterwards. It survives
// a certificate renewal that keeps the key, unlike the fingerprint.
func PublicKeyPin(der []byte) string {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func generateSelfSigned(certFile, keyFile string, hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Homelab RMM", Organization: []string{"Homelab RMM"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
}

// localHostnames lists names the self-signed certificate should cover so the
// operator's first browser visit on the LAN matches at least one SAN.
func localHostnames() []string {
	out := []string{"localhost", "127.0.0.1"}
	if h, err := os.Hostname(); err == nil {
		out = append(out, h)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
				out = append(out, ipn.IP.String())
			}
		}
	}
	return out
}
