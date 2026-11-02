//go:build linux

package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDisplayKey(t *testing.T) {
	for in, want := range map[string]string{":0": ":0", ":0.0": ":0", ":1.2": ":1", "host:0": "host:0", "host:0.0": "host:0", "host.lan:2": "host.lan:2", "host.lan:2.1": "host.lan:2"} {
		if got := displayKey(in); got != want {
			t.Errorf("displayKey(%q) = %q want %q", in, got, want)
		}
	}
}

func TestParseKeyValues(t *testing.T) {
	props := parseKeyValues("Type=x11\nDisplay=:0\nName=alice\nActive=yes\nState=active\nClass=user\nUser=1000\n\n")
	if props["Type"] != "x11" || props["Display"] != ":0" || props["User"] != "1000" || props["Name"] != "alice" || props["Class"] != "user" {
		t.Fatalf("props = %v", props)
	}
	if _, ok := props[""]; ok {
		t.Fatal("blank line produced a key")
	}
}

func TestSessionFromPropsRejectsUnknownUser(t *testing.T) {
	// uid 4294967 does not exist on any sane box; the launcher must refuse
	// rather than spawn the helper with gid 0.
	if _, err := sessionFromProps("9", map[string]string{"User": "4294967", "Type": "x11"}); err == nil {
		t.Fatal("unknown uid accepted")
	}
	if _, err := sessionFromProps("9", map[string]string{"User": "alice", "Type": "x11"}); err == nil {
		t.Fatal("non-numeric uid accepted")
	}
	// root always resolves; its groups list must start with its primary gid
	// so setgroups() is always called.
	s, err := sessionFromProps("1", map[string]string{"User": "0", "Name": "root", "Display": ":0", "Class": "user"})
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if len(s.groups) == 0 || s.groups[0] != uint32(s.gid) {
		t.Fatalf("groups %v gid %d", s.groups, s.gid)
	}
	if s.home == "" || s.display != ":0" || s.class != "user" {
		t.Fatalf("session = %+v", s)
	}
}

func TestHelperEnvIsMinimalAndCarriesTheToken(t *testing.T) {
	t.Setenv("RMM_DEBUG", "1")
	t.Setenv("SUPERSECRET", "x")
	env := helperEnv(&x11Session{user: "alice", uid: 1000, home: "/home/alice", display: ":1", xauth: "/run/user/1000/gdm/Xauthority"}, "s3cret")
	joined := strings.Join(env, "\n")
	for _, want := range []string{"DISPLAY=:1", "XAUTHORITY=/run/user/1000/gdm/Xauthority", "HOME=/home/alice", "USER=alice", "XDG_RUNTIME_DIR=/run/user/1000", "RMM_DEBUG=1", TokenEnv + "=s3cret"} {
		if !strings.Contains(joined, want) {
			t.Errorf("env lacks %s: %v", want, env)
		}
	}
	if strings.Contains(joined, "SUPERSECRET") {
		t.Error("the service environment leaked into the helper")
	}
}

// The token must never be an argument: /proc/<pid>/cmdline is world
// readable, so an argument would hand the bridge token to every local user.
func TestHelperArgsCarryNoToken(t *testing.T) {
	args := strings.Join(helperArgs(Config{ServerURL: "https://rmm.example:8443", Fingerprint: "abcd", Quality: 60}), " ")
	if strings.Contains(args, "--token") || strings.Contains(args, "s3cret") {
		t.Fatalf("token on the command line: %s", args)
	}
	for _, want := range []string{"desktop-helper", "--server", "--fingerprint", "--quality"} {
		if !strings.Contains(args, want) {
			t.Errorf("args lack %s: %s", want, args)
		}
	}
}

func writeAgentConfig(t *testing.T, cfg map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RMM_AGENT_DIR", dir)
	return dir
}

func TestReadDesktopConfig(t *testing.T) {
	dir := writeAgentConfig(t, map[string]any{
		"server_url":         "https://rmm.example:8443",
		"key":                "device-key",
		"desktop_display":    ":3",
		"desktop_user":       "root",
		"desktop_xauthority": "/tmp/xauth",
	})
	if got := agentConfigPath(); got != filepath.Join(dir, "agent.json") {
		t.Fatalf("agentConfigPath = %s", got)
	}
	c := readDesktopConfig()
	if c.Display != ":3" || c.User != "root" || c.XAuthority != "/tmp/xauth" || !c.set() {
		t.Fatalf("config = %+v", c)
	}

	// A config without the keys, and a missing file, are both "no override".
	writeAgentConfig(t, map[string]any{"server_url": "https://rmm.example:8443"})
	if c := readDesktopConfig(); c.set() {
		t.Fatalf("plain config produced an override: %+v", c)
	}
	t.Setenv("RMM_AGENT_DIR", t.TempDir())
	if c := readDesktopConfig(); c.set() {
		t.Fatalf("missing file produced an override: %+v", c)
	}
	// Broken JSON must not take the launcher down with it.
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "agent.json"), []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RMM_AGENT_DIR", broken)
	if c := readDesktopConfig(); c.set() {
		t.Fatalf("broken JSON produced an override: %+v", c)
	}
}

func TestSessionFromConfig(t *testing.T) {
	xauth := filepath.Join(t.TempDir(), "Xauthority")
	if err := os.WriteFile(xauth, []byte("cookie"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := sessionFromConfig(desktopConfig{Display: ":7", User: "root", XAuthority: xauth})
	if err != nil {
		t.Fatalf("sessionFromConfig: %v", err)
	}
	if s.display != ":7" || s.uid != 0 || s.xauth != xauth || !s.configured {
		t.Fatalf("session = %+v", s)
	}
	if len(s.groups) == 0 || s.groups[0] != uint32(s.gid) || s.home == "" {
		t.Fatalf("credentials not filled in: %+v", s)
	}
	// A numeric uid is accepted too, and the display defaults when only the
	// user is named.
	if s, err := sessionFromConfig(desktopConfig{User: "0"}); err != nil || s.uid != 0 || s.display == "" {
		t.Fatalf("numeric uid: %+v %v", s, err)
	}
	// An unusable override is an error, so findSession can fall back to
	// logind instead of spawning the helper with the wrong credentials.
	if _, err := sessionFromConfig(desktopConfig{Display: ":7", User: "no-such-account-here"}); err == nil {
		t.Fatal("unknown desktop_user accepted")
	}
	if _, err := sessionFromConfig(desktopConfig{Display: ":7", XAuthority: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing desktop_xauthority accepted")
	}
}

func TestFindSessionPrefersTheConfig(t *testing.T) {
	writeAgentConfig(t, map[string]any{"server_url": "https://x", "desktop_display": ":8", "desktop_user": "root"})
	s, err := findSession()
	if err != nil {
		t.Fatalf("findSession: %v", err)
	}
	if s.display != ":8" || s.uid != 0 || !s.configured {
		t.Fatalf("session = %+v", s)
	}
}

// Without logind and without the keys the operator must be told what to set,
// not handed a raw loginctl error.
func TestLaunchWithoutASessionNamesTheConfigKeys(t *testing.T) {
	t.Setenv("RMM_AGENT_DIR", t.TempDir())
	t.Setenv("DISPLAY", "")
	t.Setenv("XDG_SESSION_TYPE", "") // a test run from a desktop terminal must not take the in-process path
	if s, err := findSession(); err == nil {
		t.Skipf("this machine has a usable graphical session (%s); nothing to assert", s.display)
	} else if errors.Is(err, errWayland) && !errors.Is(err, errWaylandGreeter) {
		// launch serves a user's Wayland session through launchWayland, so
		// there is no "no session" error to assert on this machine.
		t.Skipf("this machine has a user Wayland session (%v); nothing to assert", err)
	}
	_, err := launch("/nonexistent/rmm-agent", Config{ServerURL: "https://rmm.example:8443", Token: "tok", Fingerprint: "fp", Quality: 60})
	if err == nil {
		t.Fatal("launch succeeded without a session")
	}
	for _, want := range []string{"cannot find the graphical session", "set desktop_display and desktop_user in agent.json"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q lacks %q", err, want)
		}
	}
}

func TestSelectSession(t *testing.T) {
	show := func(props map[string]map[string]string) func(string) (map[string]string, error) {
		return func(id string) (map[string]string, error) { return props[id], nil }
	}
	// A greeter is used only when there is no user session, whatever the
	// order logind lists them in.
	props := map[string]map[string]string{
		"c1": {"Type": "x11", "Active": "yes", "Class": greeterClass, "User": "0", "Name": "gdm", "Display": ":0"},
		"c2": {"Type": "x11", "Active": "yes", "Class": "user", "User": "0", "Name": "root", "Display": ":1"},
	}
	s, err := selectSession("c1 0 gdm seat0\nc2 0 root seat0\n", show(props))
	if err != nil || s.id != "c2" || s.class != "user" {
		t.Fatalf("user session not preferred: %+v %v", s, err)
	}
	s, err = selectSession("c1 0 gdm seat0\n", show(props))
	if err != nil || s.id != "c1" || s.class != greeterClass {
		t.Fatalf("greeter not used as the fallback: %+v %v", s, err)
	}
	// Wayland: a greeter means "no user is logged in", a user session is
	// handed to launchWayland; both stay recognisable as errWayland.
	wl := map[string]map[string]string{
		"w1": {"Type": "wayland", "Active": "yes", "Class": greeterClass, "User": "0"},
		"w2": {"Type": "wayland", "Active": "yes", "Class": "user", "User": "0"},
	}
	_, err = selectSession("w1 0 gdm seat0\n", show(wl))
	if err == nil || !strings.Contains(err.Error(), "no user is logged in") {
		t.Fatalf("wayland greeter: %v", err)
	}
	_, err = selectSession("w2 0 alice seat0\n", show(wl))
	if err == nil || strings.Contains(err.Error(), "no user is logged in") {
		t.Fatalf("wayland user session: %v", err)
	}
	// Inactive sessions are reported as such rather than as "none found".
	_, err = selectSession("i1 0 alice seat0\n", show(map[string]map[string]string{
		"i1": {"Type": "x11", "Active": "no", "State": "closing", "User": "0"},
	}))
	if err == nil || !strings.Contains(err.Error(), "inactive") {
		t.Fatalf("inactive session: %v", err)
	}
	if _, err := selectSession("", show(nil)); err == nil {
		t.Fatal("empty list accepted")
	}
}

// The operator's desktop_display must survive the whole way: config ->
// session -> the helper's environment -> a capture that really works. This
// is the no-logind host the keys exist for (this container is one), with
// Xvfb standing in for its X server.
func TestConfiguredDisplayIsCapturable(t *testing.T) {
	if _, err := exec.LookPath("Xvfb"); err != nil {
		t.Skip("Xvfb not installed; skipping the X11 integration test")
	}
	os.Unsetenv("XAUTHORITY")
	os.Unsetenv("XDG_SESSION_TYPE")
	display, stop, err := startXvfb(t, 640, 480)
	if err != nil {
		t.Skipf("could not start a usable Xvfb: %v", err)
	}
	defer stop()
	t.Setenv("DISPLAY", display) // record for restore; startXvfb already set it

	writeAgentConfig(t, map[string]any{"server_url": "https://rmm.example:8443", "desktop_display": display})
	s, err := findSession()
	if err != nil {
		t.Fatalf("findSession with desktop_display=%s: %v", display, err)
	}
	if s.display != display || s.uid != os.Geteuid() || !s.configured {
		t.Fatalf("session = %+v", s)
	}

	// Put this process in the environment the helper would be spawned with
	// and capture through it.
	for _, kv := range helperEnv(s, "tok") {
		switch k, v, _ := strings.Cut(kv, "="); k {
		case "DISPLAY", "XAUTHORITY", "XDG_SESSION_TYPE":
			t.Setenv(k, v)
		}
	}
	if err := platformInit(); err != nil {
		t.Fatalf("platformInit on the configured display: %v", err)
	}
	var mons []monitor
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if mons, err = (screenCapturer{}).monitors(); err == nil && len(mons) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || len(mons) == 0 {
		t.Fatalf("no monitor on the configured display: %v", err)
	}
	if got := mons[0].Bounds; got.Dx() != 640 || got.Dy() != 480 {
		t.Fatalf("captured %v, want the 640x480 Xvfb screen", got)
	}
}
