package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigDirPrefersTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)
	if got := ConfigDir(); got != dir {
		t.Fatalf("ConfigDir() = %q, want %q", got, dir)
	}
	if got, want := ConfigPath(), filepath.Join(dir, "agent.json"); got != want {
		t.Fatalf("ConfigPath() = %q, want %q", got, want)
	}
	if got, want := LogPath(), filepath.Join(dir, "agent.log"); got != want {
		t.Fatalf("LogPath() = %q, want %q", got, want)
	}
}

func TestConfigDirFallsBackToTheDefault(t *testing.T) {
	t.Setenv(EnvConfigDir, "")
	if got, want := ConfigDir(), DefaultConfigDir(); got != want {
		t.Fatalf("ConfigDir() = %q, want the default %q", got, want)
	}
	if !filepath.IsAbs(DefaultConfigDir()) {
		t.Fatalf("DefaultConfigDir() = %q, which is not absolute", DefaultConfigDir())
	}
}

func TestDefaultConfigDirIgnoresTheEnvironment(t *testing.T) {
	// The installer compares the two to decide whether the directory has to
	// be pinned into the service definition, so the default must not move
	// when RMM_AGENT_DIR does.
	def := DefaultConfigDir()
	t.Setenv(EnvConfigDir, t.TempDir())
	if got := DefaultConfigDir(); got != def {
		t.Fatalf("DefaultConfigDir() = %q, want %q", got, def)
	}
}

func TestSetConfigDirResolvesAndExportsTheDirectory(t *testing.T) {
	t.Setenv(EnvConfigDir, "")
	rel := filepath.Join("tmp", "agent-"+t.Name())
	got, err := SetConfigDir(rel)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("SetConfigDir returned %q, which is not absolute", got)
	}
	if ConfigDir() != got {
		t.Fatalf("ConfigDir() = %q, want %q", ConfigDir(), got)
	}
	// Exported, not merely remembered: the desktop helper is handed this
	// variable, and it is what a child process reads.
	if os.Getenv(EnvConfigDir) != got {
		t.Fatalf("%s = %q, want %q", EnvConfigDir, os.Getenv(EnvConfigDir), got)
	}
}

func TestSetConfigDirLeavesAnAbsolutePathAlone(t *testing.T) {
	t.Setenv(EnvConfigDir, "")
	dir := t.TempDir()
	got, err := SetConfigDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("SetConfigDir(%q) = %q", dir, got)
	}
}

func TestSaveAndLoadRoundTripInTheConfiguredDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)
	c := &Config{ServerURL: "https://rmm.lan:8443/", AgentID: "a1", Key: "k1", Fingerprint: "ab12"}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.json")); err != nil {
		t.Fatalf("agent.json was not written to the configured directory: %v", err)
	}
	got, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerURL != "https://rmm.lan:8443" || got.AgentID != "a1" || got.Key != "k1" {
		t.Fatalf("loaded %+v", got)
	}
}

// ---- is the connection to the server protected at all? ----

// docs/SECURITY.md promises the operator that agents pin the server
// certificate. A server_url of http:// opts out of TLS entirely - WSURL turns
// it into ws://, which never consults TLSConfig - and nothing said so.
func TestPlaintextIsRecognisedFromTheURLTheAgentWillDial(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:18080", true},
		{"http://rmm.lan:8080", true},
		{"https://rmm.lan:8443", false},
		{"rmm.lan:8443", false}, // no scheme: WSURL dials wss://
	}
	for _, tc := range cases {
		c := &Config{ServerURL: tc.url}
		if got := c.Plaintext(); got != tc.want {
			t.Errorf("Config{%q}.Plaintext() = %v, want %v", tc.url, got, tc.want)
		}
		// The two must not drift: what WSURL builds is what is dialled.
		if got := strings.HasPrefix(c.WSURL("/ws/agent"), "ws://"); got != c.Plaintext() {
			t.Errorf("%q: WSURL says plaintext=%v, Plaintext() says %v", tc.url, got, c.Plaintext())
		}
	}
}

func TestPlaintextWarningNamesTheURLAndTheIgnoredPin(t *testing.T) {
	if got := (&Config{ServerURL: "https://rmm.lan:8443"}).PlaintextWarning(); got != "" {
		t.Fatalf("PlaintextWarning on an https:// URL = %q, want nothing", got)
	}
	got := (&Config{ServerURL: "http://rmm.lan:8080"}).PlaintextWarning()
	if !strings.HasPrefix(got, "WARNING") || !strings.Contains(got, "http://rmm.lan:8080") {
		t.Fatalf("PlaintextWarning = %q", got)
	}
	// A fingerprint on an http:// URL pins nothing at all, which is worse than
	// having none: the operator thinks the connection is protected.
	pinned := (&Config{ServerURL: "http://rmm.lan:8080", Fingerprint: "ab12"}).PlaintextWarning()
	if !strings.Contains(pinned, "fingerprint") {
		t.Fatalf("PlaintextWarning with a fingerprint = %q, want it to say the pin is ignored", pinned)
	}
}
