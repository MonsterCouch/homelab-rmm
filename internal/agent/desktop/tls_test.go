package desktop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func TestWSURL(t *testing.T) {
	cases := map[string]string{
		"https://rmm.lan:8443":  "wss://rmm.lan:8443/ws/desktop-agent?token=x",
		"https://rmm.lan:8443/": "wss://rmm.lan:8443/ws/desktop-agent?token=x",
		"http://127.0.0.1:8080": "ws://127.0.0.1:8080/ws/desktop-agent?token=x",
		"rmm.lan":               "wss://rmm.lan/ws/desktop-agent?token=x",
		"wss://rmm.lan":         "wss://rmm.lan/ws/desktop-agent?token=x",
	}
	for in, want := range cases {
		if got := wsURL(in, "/ws/desktop-agent?token=x"); got != want {
			t.Errorf("wsURL(%q) = %q want %q", in, got, want)
		}
	}
}

func TestTLSConfigPins(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	fp := hex.EncodeToString(sum[:])

	cfg := tlsConfig(strings.ToUpper(strings.Join(splitPairs(fp), ":")))
	if !cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate == nil {
		t.Fatal("pinned config must verify itself")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{der}, nil); err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{append([]byte{1}, der...)}, nil); err == nil {
		t.Fatal("wrong certificate accepted")
	}
	if err := cfg.VerifyPeerCertificate(nil, nil); err == nil {
		t.Fatal("empty chain accepted")
	}
	if plain := tlsConfig(""); plain.InsecureSkipVerify || plain.VerifyPeerCertificate != nil {
		t.Fatal("no pin must use the system trust store")
	}
}

func splitPairs(s string) []string {
	var out []string
	for i := 0; i+2 <= len(s); i += 2 {
		out = append(out, s[i:i+2])
	}
	return out
}
