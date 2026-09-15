//go:build linux

package desktop

import (
	"strings"
	"testing"
)

func TestDisplayKey(t *testing.T) {
	for in, want := range map[string]string{":0": ":0", ":0.0": ":0", ":1.2": ":1", "host:0": "host:0", "host:0.0": "host:0", "host.lan:2": "host.lan:2", "host.lan:2.1": "host.lan:2"} {
		if got := displayKey(in); got != want {
			t.Errorf("displayKey(%q) = %q want %q", in, got, want)
		}
	}
}

func TestParseKeyValues(t *testing.T) {
	props := parseKeyValues("Type=x11\nDisplay=:0\nName=alice\nActive=yes\nState=active\nUser=1000\n\n")
	if props["Type"] != "x11" || props["Display"] != ":0" || props["User"] != "1000" || props["Name"] != "alice" {
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
	s, err := sessionFromProps("1", map[string]string{"User": "0", "Name": "root", "Display": ":0"})
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if len(s.groups) == 0 || s.groups[0] != uint32(s.gid) {
		t.Fatalf("groups %v gid %d", s.groups, s.gid)
	}
	if s.home == "" || s.display != ":0" {
		t.Fatalf("session = %+v", s)
	}
}

func TestHelperEnvIsMinimal(t *testing.T) {
	t.Setenv("RMM_DEBUG", "1")
	t.Setenv("SUPERSECRET", "x")
	env := helperEnv(&x11Session{user: "alice", uid: 1000, home: "/home/alice", display: ":1", xauth: "/run/user/1000/gdm/Xauthority"})
	joined := strings.Join(env, "\n")
	for _, want := range []string{"DISPLAY=:1", "XAUTHORITY=/run/user/1000/gdm/Xauthority", "HOME=/home/alice", "USER=alice", "XDG_RUNTIME_DIR=/run/user/1000", "RMM_DEBUG=1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("env lacks %s: %v", want, env)
		}
	}
	if strings.Contains(joined, "SUPERSECRET") {
		t.Error("the service environment leaked into the helper")
	}
}
