package agent

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config is persisted at ConfigPath() with mode 0600 - on Windows the mode is
// ignored entirely and the protected DACL EnsureConfigDir puts on the
// directory is what keeps other accounts out. The key is issued at enrollment
// and never shown again; losing it means re-enrolling.
//
// EnrollToken stays in the file after enrollment on purpose: it is how a device
// whose key the server revoked re-enrolls without anyone visiting it (the 401
// path in Agent.session). That makes agent.json a fleet credential and not
// only a device one, for as long as the token has uses and has not expired -
// "The token stays on the device" in docs/SECURITY.md says what that costs.
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

// EnvConfigDir names the environment variable that moves the configuration
// directory. It is exported because it is also the channel the directory
// travels down: SetConfigDir writes it, and the processes the agent starts
// (the desktop helper) inherit it.
const EnvConfigDir = "RMM_AGENT_DIR"

// ConfigDir is the directory holding agent.json and agent.log: EnvConfigDir
// when it is set, the platform default otherwise.
func ConfigDir() string {
	if v := os.Getenv(EnvConfigDir); v != "" {
		return v
	}
	return DefaultConfigDir()
}

// DefaultConfigDir is the built-in location, ignoring EnvConfigDir entirely.
// The service installer compares ConfigDir against it to decide whether the
// directory has to be pinned into the service definition: a service is started
// by the service manager with none of the environment the install ran with -
// and sudo's env_reset drops RMM_AGENT_DIR before the documented install
// one-liner even starts - so a non-default directory that is not written into
// the unit (or the Windows ImagePath) is silently lost, and the service loads
// the default path's config, which is another install's or nothing at all.
func DefaultConfigDir() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "HomelabRMM")
	}
	return "/etc/homelab-rmm"
}

// SetConfigDir pins dir as the configuration directory for this process and
// everything it starts, and reports the absolute path it settled on. dir is
// resolved against the working directory first: the service manager starts the
// agent from / (or C:\Windows\system32), so a relative path baked into a
// service definition would point at a different place than it did when the
// operator typed it.
//
// It sets the environment variable rather than a package variable on purpose.
// That is the same channel the desktop helper is handed (helperEnv copies
// RMM_AGENT_DIR into the helper's environment), so an agent started with
// --config-dir gives its helper the same directory without a second mechanism.
// Call it once, during start-up, before anything reads a path from it.
func SetConfigDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if err := os.Setenv(EnvConfigDir, abs); err != nil {
		return "", err
	}
	return abs, nil
}

func ConfigPath() string { return filepath.Join(ConfigDir(), "agent.json") }

// LogPath is the service's own log file, inside the directory EnsureConfigDir
// locks down. Only the service writes it: it is the one log that is rotated,
// and a second process renaming it would pull the file out from under the
// running service.
func LogPath() string { return filepath.Join(ConfigDir(), "agent.log") }

// HelperLogPaths lists, most preferred first, the files the desktop helper may
// log to. The helper is not the service: on Windows it runs under the
// logged-in user's token, which the protected DACL keeps out of ConfigDir
// entirely, and on Linux it runs as the desktop user against a root-owned
// /etc/homelab-rmm. With nowhere to write, its diagnostics used to vanish -
// its console is hidden - so it falls back to a directory it certainly owns.
//
// ConfigDir comes first for the cases where the helper does run with the
// service's rights (a locked or logged-out Windows console session, where the
// helper gets the SYSTEM token, and the developer in-process path): the
// operator then finds helper.log beside agent.log. The user cache directory
// (%LocalAppData%, $XDG_CACHE_HOME, ~/Library/Caches) comes before the temp
// directory because it belongs to one user; /tmp is shared, and a local
// attacker who pre-creates a symlink there would otherwise aim the helper's
// writes at a file of the victim's choosing.
func HelperLogPaths() []string {
	paths := []string{filepath.Join(ConfigDir(), "helper.log")}
	if cache, err := os.UserCacheDir(); err == nil && cache != "" {
		paths = append(paths, filepath.Join(cache, "homelab-rmm-helper.log"))
	}
	return append(paths, filepath.Join(os.TempDir(), "rmm-desktop-helper.log"))
}

// EnsureConfigDir creates ConfigDir() and restricts it to the agent's own
// account: mode 0700 on Unix, a protected SYSTEM+Administrators DACL on
// Windows, where the mode is ignored and the inherited ACL would otherwise
// let every local user read the device key. A directory that cannot be
// secured (an agent installed by a non-admin, an exotic filesystem) is a
// warning, not a failure: the agent still has to run.
func EnsureConfigDir() error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := secureDir(dir); err != nil {
		slog.Warn("cannot restrict permissions on the agent directory", "dir", dir, "err", err)
	}
	return nil
}

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
	if err := EnsureConfigDir(); err != nil {
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
	if err := os.Rename(tmp, ConfigPath()); err != nil {
		return err
	}
	saveRegistryClientInfo(c.ServerURL, c.AgentID)
	return nil
}

// Plaintext reports whether the agent will reach the server over an
// unencrypted socket. It asks WSURL rather than re-testing the scheme so the
// two cannot drift: whatever WSURL turns ServerURL into is what the agent
// actually dials, and a ws:// dial never consults TLSConfig - not the system
// trust store, and not the pinned fingerprint either.
func (c *Config) Plaintext() bool { return strings.HasPrefix(c.WSURL(""), "ws://") }

// PlaintextWarning is the warning `install` prints and the agent logs at every
// start when the configured server URL gives the connection no protection at
// all, or "" when it does. docs/SECURITY.md promises the operator that agents
// pin the server certificate; a server_url of http:// silently opts out of
// that, and nothing said so before.
func (c *Config) PlaintextWarning() string {
	if !c.Plaintext() {
		return ""
	}
	msg := "WARNING: server_url is " + c.ServerURL + ", so this agent talks to the server in\n" +
		"         clear text: the device key, script bodies, shell traffic and file\n" +
		"         transfers can be read and rewritten by anyone on the network path.\n" +
		"         Use an https:// URL unless the server is on this machine."
	if c.Fingerprint != "" {
		msg += "\n         The configured fingerprint pins nothing over http://."
	}
	return msg
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
