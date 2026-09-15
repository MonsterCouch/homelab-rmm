package desktop

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// tlsConfig pins the server certificate by SHA-256 fingerprint when one is
// configured, otherwise trusts the system store. This duplicates
// agent.TLSConfig on purpose: the agent package imports this one, so the
// helper cannot import it back without a cycle.
func tlsConfig(fingerprint string) *tls.Config {
	fp := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fingerprint), ":", ""))
	if fp == "" {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // verified below against the pin instead
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no server certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if got := hex.EncodeToString(sum[:]); got != fp {
				return fmt.Errorf("server certificate fingerprint mismatch: got %s", got)
			}
			return nil
		},
	}
}

// wsURL turns the configured server URL (https://host:port) into the
// WebSocket URL of one path, mirroring agent.Config.WSURL.
func wsURL(serverURL, path string) string {
	u := strings.TrimRight(strings.TrimSpace(serverURL), "/")
	switch {
	case strings.HasPrefix(u, "https://"):
		u = "wss://" + strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "http://"):
		u = "ws://" + strings.TrimPrefix(u, "http://")
	case strings.HasPrefix(u, "wss://"), strings.HasPrefix(u, "ws://"):
	default:
		u = "wss://" + u
	}
	return u + path
}

// dial opens the helper's WebSocket. The token travels in the query string
// because that is the contract with relay.go; TLS protects it in transit.
func dial(ctx context.Context, url, fingerprint string) (*websocket.Conn, error) {
	d := websocket.Dialer{
		TLSClientConfig:  tlsConfig(fingerprint),
		HandshakeTimeout: 20 * time.Second,
		ReadBufferSize:   64 << 10,
		WriteBufferSize:  256 << 10,
	}
	ws, resp, err := d.DialContext(ctx, url, http.Header{"User-Agent": {"homelab-rmm-desktop-helper"}})
	if err != nil {
		// Never echo the query string: it carries the session token.
		shown, _, _ := strings.Cut(url, "?")
		if resp != nil {
			return nil, fmt.Errorf("dial %s: %w (HTTP %d)", shown, err, resp.StatusCode)
		}
		return nil, fmt.Errorf("dial %s: %w", shown, err)
	}
	return ws, nil
}
