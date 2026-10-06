package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Config is everything the server needs to start. Every field has a default
// that works on a bare Windows box: data under ProgramData, HTTPS on :8443
// with a self-signed certificate generated on first run.
type Config struct {
	DataDir  string // database, certificate, uploads
	Listen   string // address:port for HTTPS
	CertFile string // optional operator-supplied certificate
	KeyFile  string
	// TailscaleCert makes the server get its certificate from
	// `tailscale cert` and keep it renewed. Ignored when CertFile is set.
	TailscaleCert bool
	PublicURL     string // what agents and links use to reach the server, e.g. https://rmm.lan:8443
	DevWebDir     string // serve UI from this directory instead of the embedded build (development)
	LogLevel      string
	Insecure      bool // plain HTTP (behind a reverse proxy that terminates TLS)
	SkipSeed      bool // do not create the starter scripts/rules on first run (tests)
	// TrustedProxies lists CIDRs whose X-Forwarded-For header is believed
	// (the reverse proxy in front of --insecure). Empty = never trust it.
	TrustedProxies []string
	// ICEServers are the STUN/TURN servers handed to the remote-desktop
	// viewer for WebRTC. Each entry is a server URL, optionally with
	// credentials as "url|username|credential" (for TURN). Empty falls back
	// to a public STUN server so direct P2P still works on most networks; a
	// LAN-only or NAT-restricted deployment should set its own TURN here.
	ICEServers []string
}

// defaultICEServers is used when none are configured: a public STUN server is
// enough for hole-punching on the common NAT types and leaks nothing but the
// client's reflexive address to Google, the same as any WebRTC site.
var defaultICEServers = []string{"stun:stun.l.google.com:19302"}

// iceServersJSON renders the configured (or default) ICE servers as the JSON
// array the browser's RTCConfiguration.iceServers expects.
func (c Config) iceServersJSON() json.RawMessage {
	src := c.ICEServers
	if len(src) == 0 {
		src = defaultICEServers
	}
	type iceServer struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username,omitempty"`
		Credential string   `json:"credential,omitempty"`
	}
	out := make([]iceServer, 0, len(src))
	for _, s := range src {
		parts := strings.SplitN(s, "|", 3)
		srv := iceServer{URLs: []string{strings.TrimSpace(parts[0])}}
		if len(parts) >= 2 {
			srv.Username = parts[1]
		}
		if len(parts) >= 3 {
			srv.Credential = parts[2]
		}
		if srv.URLs[0] != "" {
			out = append(out, srv)
		}
	}
	b, _ := json.Marshal(out)
	return b
}

// DefaultDataDir is %ProgramData%\HomelabRMM on Windows and /var/lib/homelab-rmm
// elsewhere, falling back to ./data when neither is writable.
func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "HomelabRMM")
		}
		return `C:\HomelabRMM`
	}
	if os.Geteuid() == 0 {
		return "/var/lib/homelab-rmm"
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return "./data"
	}
	return filepath.Join(home, ".homelab-rmm")
}

// FromEnv applies RMM_* environment variables on top of c and returns it.
func (c Config) FromEnv() Config {
	if v := os.Getenv("RMM_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("RMM_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("RMM_CERT_FILE"); v != "" {
		c.CertFile = v
	}
	if v := os.Getenv("RMM_KEY_FILE"); v != "" {
		c.KeyFile = v
	}
	if v := os.Getenv("RMM_PUBLIC_URL"); v != "" {
		c.PublicURL = v
	}
	if v := os.Getenv("RMM_DEV_WEB_DIR"); v != "" {
		c.DevWebDir = v
	}
	if v := os.Getenv("RMM_INSECURE"); v != "" {
		c.Insecure, _ = strconv.ParseBool(v)
	}
	if v := os.Getenv("RMM_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = strings.Split(v, ",")
	}
	if v := os.Getenv("RMM_ICE_SERVERS"); v != "" {
		c.ICEServers = nil
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				c.ICEServers = append(c.ICEServers, s)
			}
		}
	}
	return c
}

func (c Config) path(name string) string { return filepath.Join(c.DataDir, name) }
