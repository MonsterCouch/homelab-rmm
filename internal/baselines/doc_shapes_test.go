package baselines

import (
	"encoding/json"
	"testing"
)

// docShapes is one fixture per kind, copied verbatim from the parameter table
// in docs/BASELINES.md and from the worked example in README.md. It is the
// contract between three builders: the console's typed forms emit these
// shapes, the server validates a write with ValidateCheck, and the agent
// re-reads them with ValidateCheckLenient. A doc example the validator
// refuses is a bug in one of the three, so pin them here rather than trust
// three separate readings of the same table.
var docShapes = []struct {
	name   string
	kind   string
	params string
}{
	{"service", "service", `{"name":"Spooler","state":"running","start_type":"auto"}`},
	{"service on linux (README example)", "service", `{"name":"ssh","state":"running","start_type":"auto"}`},
	{"package", "package", `{"name":"unattended-upgrades","state":"present","min_version":"2.9","allow_winget":false}`},
	{"registry", "registry", `{"path":"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters","name":"SMB1","type":"dword","value":0}`},
	{"file", "file", `{"path":"/etc/ssh/sshd_config.d/99-rmm.conf","state":"present","content":"PermitRootLogin no\n","sha256":"","contains":"PermitRootLogin no","mode":"0644","owner":"root:root"}`},
	{"file (README example)", "file", `{"path":"/etc/ssh/sshd_config.d/99-rmm.conf","state":"present","content":"PermitRootLogin no\nPasswordAuthentication no\n","mode":"0644","owner":"root:root"}`},
	{"command", "command", `{"language":"bash","check":"test -f /etc/foo","fix":"touch /etc/foo","expected":"present"}`},
	{"group_members", "group_members", `{"group":"Administrators","allowed":["Administrator","rmm-admin"],"mode":"exact","allow_domain":false}`},
	{"group_members (README example)", "group_members", `{"group":"sudo","allowed":["ansible","admin"],"mode":"subset"}`},
	{"firewall", "firewall", `{"enabled":true}`},
	{"time_sync", "time_sync", `{"enabled":true}`},
	{"sysctl", "sysctl", `{"key":"net.ipv4.ip_forward","value":"0"}`},
	{"windows_feature", "windows_feature", `{"name":"SMB1Protocol","state":"disabled"}`},
	{"reboot_pending", "reboot_pending", `{"max_hours":72,"allow_reboot":false}`},
	{"disk_free", "disk_free", `{"mount":"C:","min_free_pct":10}`},
}

func TestDocumentedShapesValidate(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range docShapes {
		seen[c.kind] = true
		if err := ValidateCheck(c.kind, json.RawMessage(c.params)); err != nil {
			t.Errorf("%s: the documented shape is refused by the server validator: %v", c.name, err)
		}
		// The agent reads the same JSON with the lenient decoder; every rule
		// but "unknown keys" must still hold.
		if err := ValidateCheckLenient(c.kind, json.RawMessage(c.params)); err != nil {
			t.Errorf("%s: the documented shape is refused by the agent validator: %v", c.name, err)
		}
	}
	for _, k := range Kinds() {
		if !seen[k] {
			t.Errorf("kind %q has no documented example: add one to docs/BASELINES.md and to docShapes", k)
		}
	}
}

// The seeds are what an operator meets on first run, so they have to satisfy
// the same validator every other write does.
func TestSeededShapesValidate(t *testing.T) {
	seeds := []struct {
		kind   string
		params string
	}{
		{"firewall", `{"enabled":true}`},
		{"time_sync", `{"enabled":true}`},
		{"registry", `{"path":"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters","name":"SMB1","type":"dword","value":0}`},
		{"service", `{"name":"Spooler","state":"stopped","start_type":"manual"}`},
		{"group_members", `{"group":"Administrators","allowed":["Administrator"],"mode":"subset"}`},
		{"reboot_pending", `{"max_hours":72,"allow_reboot":false}`},
		{"disk_free", `{"mount":"C:","min_free_pct":10}`},
		{"service", `{"name":"ssh","state":"running","start_type":"auto"}`},
		{"service", `{"name":"sshd","state":"running","start_type":"auto"}`},
		{"sysctl", `{"key":"net.ipv4.ip_forward","value":"0"}`},
		{"package", `{"name":"unattended-upgrades","state":"present"}`},
		{"disk_free", `{"mount":"/","min_free_pct":10}`},
		{"group_members", `{"group":"sudo","allowed":[],"mode":"subset"}`},
		{"group_members", `{"group":"wheel","allowed":[],"mode":"subset"}`},
	}
	for _, s := range seeds {
		if err := ValidateCheck(s.kind, json.RawMessage(s.params)); err != nil {
			t.Errorf("seeded %s check is refused: %v (%s)", s.kind, err, s.params)
		}
	}
}
