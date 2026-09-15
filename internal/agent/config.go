package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config is persisted at ConfigPath() with mode 0600. The key is issued at
// enrolment and never shown again; losing it means re-enrolling.
type Config struct {
	ServerURL   string `json:"server_url"`
	AgentID     string `json:"agent_id,omitempty"`
	Key         string `json:"key,omitempty"`
	EnrollToken string `json:"enroll_token,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"` // sha256 hex of the server certificate; "" = system trust
	LogFile     string `json:"log_file,omitempty"`
}

// Version is stamped by the build.
var Version = "dev"

// ServiceName is the Windows service / systemd unit name.
const ServiceName = "HomelabRMMAgent"

func ConfigDir() string {
	if v := os.Getenv("RMM_AGENT_DIR"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "HomelabRMM")
	}
	return "/etc/homelab-rmm"
}

func ConfigPath() string { return filepath.Join(ConfigDir(), "agent.json") }

func LoadConfig() (*Config, error) {
	b, err := os.ReadFile(ConfigPath())
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.ServerURL == "" {
		return nil, errors.New("config has no server_url")
	}
	c.ServerURL = strings.TrimRight(c.ServerURL, "/")
	return &c, nil
}

func (c *Config) Save() error {
	if err := os.MkdirAll(ConfigDir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := ConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ConfigPath())
}

// WSURL converts https://host:port into wss://host:port/<path>.
func (c *Config) WSURL(path string) string {
	u := c.ServerURL
	switch {
	case strings.HasPrefix(u, "https://"):
		u = "wss://" + strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "http://"):
		u = "ws://" + strings.TrimPrefix(u, "http://")
	default:
		u = "wss://" + u
	}
	return u + path
}
