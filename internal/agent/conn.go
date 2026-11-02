package agent

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
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// TLSConfig pins the server certificate by SHA-256 fingerprint when one is
// configured, otherwise falls back to the system trust store. Pinning is what
// makes a self-signed server certificate safe for the agent channel.
func TLSConfig(fingerprint string) *tls.Config {
	fp := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	if fp == "" {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // we verify ourselves below, against the pin
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no server certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) != fp {
				return fmt.Errorf("server certificate fingerprint mismatch: got %s", hex.EncodeToString(sum[:]))
			}
			return nil
		},
	}
}

// Dial opens a WebSocket to the server with the given headers.
func Dial(ctx context.Context, url, fingerprint string, hdr http.Header) (*websocket.Conn, *http.Response, error) {
	d := websocket.Dialer{
		TLSClientConfig:  TLSConfig(fingerprint),
		HandshakeTimeout: 20 * time.Second,
		ReadBufferSize:   64 << 10,
		WriteBufferSize:  64 << 10,
	}
	return d.DialContext(ctx, url, hdr)
}

// conn is one live connection to the server with a serialised writer. It is
// either a WebSocket (ws) or a QUIC connection (q); exactly one is set, and
// everything above send neither knows nor cares which.
type conn struct {
	ws *websocket.Conn
	q  *quicLink
	mu sync.Mutex
	// logSize, when set, reports the size of the transparency log head the
	// device holds; every frame carries it (a script or shell session can run
	// for hours without replying) so the hub can send consistency proofs from
	// the right place.
	logSize func() int64
}

func (c *conn) send(env protocol.Envelope) error {
	if c.q != nil {
		// QUIC writes are serialised per stream inside the link, not here: one
		// lock around every write would let a stalled shell stream hold up a
		// reply on another, which is what the transport exists to prevent.
		if env.Log == 0 && c.logSize != nil {
			env.Log = c.logSize()
		}
		return c.q.send(env)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if env.Log == 0 && c.logSize != nil {
		env.Log = c.logSize()
	}
	c.ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return c.ws.WriteJSON(env)
}

func (c *conn) reply(id string, v any) error {
	var d []byte
	if v != nil {
		d = protocol.Must(v)
	}
	return c.send(protocol.Envelope{T: protocol.TypeReply, ID: id, D: d})
}

func (c *conn) replyErr(id string, err error) error {
	return c.send(protocol.Envelope{T: protocol.TypeReply, ID: id, Err: err.Error()})
}

func (c *conn) stream(id string, v any) error {
	return c.send(protocol.Envelope{T: protocol.TypeStream, ID: id, D: protocol.Must(v)})
}

func (c *conn) event(kind, msg string, fields map[string]string) error {
	return c.send(protocol.Envelope{T: protocol.TypeEvent, D: protocol.Must(protocol.Event{Kind: kind, Message: msg, Fields: fields, TS: time.Now().Unix()})})
}
