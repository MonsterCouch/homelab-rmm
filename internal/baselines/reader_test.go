package baselines

import (
	"encoding/json"
	"strings"
	"testing"
)

// The writer and the reader share every rule but one: a key this build has
// never heard of is a 400 when a console writes it and a shrug when a device
// reads it. Without that split an agent one release behind the server reports
// `error` for a params field a newer console added, which is a drift alert on
// every matched device - the fleet-wide false alarm A42 exists to prevent.
func TestStrictAndLenientDifferOnlyOnUnknownKeys(t *testing.T) {
	cases := []struct {
		kind   string
		params string
	}{
		{"service", `{"name":"Spooler","state":"running","start_type":"manual","restart_on_fail":true}`},
		{"file", `{"path":"/etc/motd","state":"present","content":"hi","selinux":"etc_t"}`},
		{"disk_free", `{"mount":"/","min_free_pct":10,"min_free_inodes_pct":5}`},
		{"firewall", `{"enabled":true,"profiles":["domain"]}`},
		{"group_members", `{"group":"sudo","allowed":["root"],"mode":"subset","notify":false}`},
	}
	for _, c := range cases {
		if err := ValidateCheck(c.kind, json.RawMessage(c.params)); err == nil {
			t.Errorf("%s: a writer must be refused an unknown key: %s", c.kind, c.params)
		}
		if err := ValidateCheckLenient(c.kind, json.RawMessage(c.params)); err != nil {
			t.Errorf("%s: a reader must ignore the unknown key, got %v", c.kind, err)
		}
	}
}

func TestLenientStillEnforcesEveryRealRule(t *testing.T) {
	bad := []struct {
		kind, params, want string
	}{
		{"service", `{"name":"Spooler","state":"paused"}`, "state"},
		{"file", `{"path":"relative/path","state":"present"}`, "path"},
		{"file", `{"path":"/etc/x","state":"present","mode":"4755"}`, "mode"},
		{"disk_free", `{"mount":"/","min_free_pct":0}`, "min_free_pct"},
		{"registry", `{"path":"HKLM\\SAM\\x","name":"v","type":"dword","value":1}`, "SAM"},
		{"sysctl", `{"key":"NET.ipv4","value":"0"}`, "key"},
		{"command", `{"language":"bash","fix":"true"}`, "check"},
		{"reboot_pending", `{"max_hours":0}`, "max_hours"},
	}
	for _, c := range bad {
		err := ValidateCheckLenient(c.kind, json.RawMessage(c.params))
		if err == nil {
			t.Errorf("%s: %s must be refused by the reader too", c.kind, c.params)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error must name %q, got %v", c.kind, c.want, err)
		}
	}
}

// A34 puts the agent's own directory on the deny list "on BOTH sides". The
// device refuses its real ConfigDir() (which RMM_AGENT_DIR can move and only
// the device knows); a writer is refused the default location, so a baseline
// that rewrites agent.json - the server URL of the whole fleet - cannot be
// saved in the first place.
func TestFileCheckRefusesTheAgentsOwnDirectory(t *testing.T) {
	for _, p := range []string{
		"/etc/homelab-rmm",
		"/etc/homelab-rmm/agent.json",
		"/etc/homelab-rmm/baselines.json",
		`C:\ProgramData\HomelabRMM\agent.json`,
		`c:\programdata\homelabrmm\baselines.json`,
	} {
		if err := CheckFilePath(p, "present", "{}"); err == nil {
			t.Errorf("%s must not be manageable by a baseline", p)
		}
	}
	for _, p := range []string{"/etc/homelab-rmm-notes.txt", "/etc/motd", `C:\ProgramData\app\x.conf`} {
		if err := CheckFilePath(p, "present", "x"); err != nil {
			t.Errorf("%s is a legitimate target: %v", p, err)
		}
	}
}
