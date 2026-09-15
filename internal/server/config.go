package server

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// Config is everything the server needs to start. Every field has a default
// that works on a bare Windows box: data under ProgramData, HTTPS on :8443
// with a self-signed certificate generated on first run.
type Config struct {
	DataDir   string // database, certificate, uploads
	Listen    string // address:port for HTTPS
	CertFile  string // optional operator-supplied certificate
	KeyFile   string
	PublicURL string // what agents and links use to reach the server, e.g. https://rmm.lan:8443
	DevWebDir string // serve UI from this directory instead of the embedded build (development)
	LogLevel  string
	Insecure  bool // plain HTTP (behind a reverse proxy that terminates TLS)
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
	return c
}

func (c Config) path(name string) string { return filepath.Join(c.DataDir, name) }
