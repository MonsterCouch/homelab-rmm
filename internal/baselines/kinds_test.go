package baselines

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateCheckTable(t *testing.T) {
	cases := []struct {
		name   string
		kind   string
		params string
		bad    string // substring of the expected error; "" = must be accepted
	}{
		// service
		{"service ok", "service", `{"name":"Spooler","state":"running","start_type":"auto"}`, ""},
		{"service installed", "service", `{"name":"Spooler","state":"installed"}`, ""},
		{"service not installed", "service", `{"name":"Telnet","state":"not_installed"}`, ""},
		{"service default start type", "service", `{"name":"sshd","state":"running"}`, ""},
		{"service bad state", "service", `{"name":"Spooler","state":"paused"}`, "state"},
		{"service no name", "service", `{"state":"running"}`, "name"},
		{"service option injection", "service", `{"name":"-rf","state":"running"}`, "name"},
		{"service slash", "service", `{"name":"a/b","state":"running"}`, "name"},
		{"service unknown key", "service", `{"name":"a","state":"running","enable":true}`, "enable"},
		// package
		{"package ok", "package", `{"name":"unattended-upgrades","state":"present"}`, ""},
		{"package installed", "package", `{"name":"7-Zip","state":"installed"}`, ""},
		{"package not installed", "package", `{"name":"utorrent","state":"not_installed"}`, ""},
		{"package version exact", "package", `{"name":"curl","state":"installed","version":"8.5.0","version_op":"=="}`, ""},
		{"package version op bad", "package", `{"name":"curl","state":"installed","version":"8.5.0","version_op":"~="}`, "version_op"},
		{"package version on not installed", "package", `{"name":"curl","state":"not_installed","version":"8.5.0"}`, "version"},
		{"package min version", "package", `{"name":"curl","state":"present","min_version":"8.5.0"}`, ""},
		{"package min version on absent", "package", `{"name":"curl","state":"absent","min_version":"8"}`, "min_version"},
		{"package unparsable min version", "package", `{"name":"curl","state":"present","min_version":"latest"}`, "min_version"},
		{"package trailing dash", "package", `{"name":"curl-","state":"present"}`, "name"},
		// package: a Windows program is named the way the Uninstall keys
		// spell it, which is where the spaces and parentheses come from.
		{"package windows display name", "package", `{"name":"7-Zip 26.03 (x64)","state":"present"}`, ""},
		{"package windows two words", "package", `{"name":"GitHub CLI","state":"present"}`, ""},
		{"package windows punctuation", "package", `{"name":"Microsoft Visual C++ v14 Redistributable (x64) - 14.51.36247","state":"present"}`, ""},
		{"package windows non-ascii", "package", `{"name":"Intel® Chipset Device Software","state":"present"}`, ""},
		{"package option injection", "package", `{"name":"-x --force","state":"present"}`, "name"},
		{"package leading space", "package", `{"name":" Git","state":"present"}`, "name"},
		{"package newline", "package", `{"name":"Git\nrm -rf","state":"present"}`, "name"},
		// registry
		{"registry guid key", "registry", `{"path":"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}","name":"Class","type":"string","value":"Net"}`, ""},
		{"registry punctuation key", "registry", `{"path":"HKLM\\SOFTWARE\\Classes\\CLSID\\{00021401-0000-0000-C000-000000000046}\\InProcServer32 (x86)","name":"","type":"string","value":"a"}`, ""},
		{"registry wildcard", "registry", `{"path":"HKLM\\SOFTWARE\\Micro*","name":"S","type":"string","value":"a"}`, "wildcard"},
		{"registry doubled backslash", "registry", `{"path":"HKLM\\SOFTWARE\\\\X","name":"S","type":"string","value":"a"}`, "empty"},
		{"registry trailing backslash", "registry", `{"path":"HKLM\\SOFTWARE\\X\\","name":"S","type":"string","value":"a"}`, "empty"},
		{"registry dword", "registry", `{"path":"HKLM\\SOFTWARE\\X","name":"SMB1","type":"dword","value":0}`, ""},
		{"registry multi", "registry", `{"path":"HKLM\\SOFTWARE\\X","name":"L","type":"multi_string","value":["a","b"]}`, ""},
		{"registry wrong value type", "registry", `{"path":"HKLM\\SOFTWARE\\X","name":"S","type":"dword","value":"0"}`, "whole number"},
		{"registry dword overflow", "registry", `{"path":"HKLM\\SOFTWARE\\X","name":"S","type":"dword","value":4294967296}`, "dword"},
		{"registry bad root", "registry", `{"path":"HKU\\X","name":"S","type":"string","value":"a"}`, "path"},
		{"registry SAM denied", "registry", `{"path":"HKLM\\SAM\\Domains","name":"S","type":"string","value":"a"}`, "SAM"},
		{"registry agent service denied", "registry", `{"path":"HKLM\\SYSTEM\\CurrentControlSet\\Services\\HomelabRMMAgent","name":"Start","type":"dword","value":4}`, "not writable"},
		// file
		{"file ok", "file", `{"path":"/etc/ssh/sshd_config.d/99-rmm.conf","state":"present","content":"x","mode":"0644","owner":"root:root"}`, ""},
		{"file relative", "file", `{"path":"etc/x","state":"present"}`, "absolute"},
		{"file dotdot", "file", `{"path":"/etc/../root/.ssh/authorized_keys","state":"present"}`, ".."},
		{"file shadow", "file", `{"path":"/etc/shadow","state":"present","content":"x"}`, "root"},
		{"file proc", "file", `{"path":"/proc/sys/x","state":"absent"}`, "/proc"},
		{"file sudoers.d absent", "file", `{"path":"/etc/sudoers.d/10-x","state":"absent"}`, "sudoers.d"},
		{"file sudoers.d with content", "file", `{"path":"/etc/sudoers.d/10-x","state":"present","content":"x"}`, ""},
		{"file setuid mode", "file", `{"path":"/etc/x","state":"present","content":"y","mode":"4755"}`, "mode"},
		{"file absent with content", "file", `{"path":"/etc/x","state":"absent","content":"y"}`, "absent"},
		{"file windows config hive", "file", `{"path":"C:\\Windows\\System32\\config\\SAM","state":"absent"}`, "not manageable"},
		{"file windows ok", "file", `{"path":"C:\\ProgramData\\x\\y.txt","state":"present","content":"a"}`, ""},
		{"file bad sha", "file", `{"path":"/etc/x","state":"present","sha256":"zz"}`, "sha256"},
		// command
		{"command ok", "command", `{"language":"bash","check":"exit 0"}`, ""},
		{"command fix without check", "command", `{"language":"bash","fix":"echo hi"}`, "check"},
		{"command bad language", "command", `{"language":"perl","check":"x"}`, "language"},
		// group_members
		{"group ok", "group_members", `{"group":"sudo","allowed":["alice"],"mode":"subset"}`, ""},
		{"group empty allowed", "group_members", `{"group":"wheel","allowed":[]}`, ""},
		{"group bad mode", "group_members", `{"group":"sudo","mode":"loose"}`, "mode"},
		{"group bad name", "group_members", `{"group":"-x"}`, "group"},
		{"group bad member", "group_members", `{"group":"sudo","allowed":["a;rm -rf /"]}`, "allowed[0]"},
		// toggles
		{"firewall ok", "firewall", `{"enabled":true}`, ""},
		{"firewall default", "firewall", `{}`, ""},
		{"firewall typo", "firewall", `{"enable":true}`, "enable"},
		{"time_sync ok", "time_sync", `{"enabled":true}`, ""},
		// sysctl
		{"sysctl ok", "sysctl", `{"key":"net.ipv4.ip_forward","value":"0"}`, ""},
		{"sysctl bad key", "sysctl", `{"key":"Net.IPv4","value":"0"}`, "key"},
		{"sysctl numeric value", "sysctl", `{"key":"net.ipv4.ip_forward","value":0}`, "params"},
		{"sysctl no value", "sysctl", `{"key":"net.ipv4.ip_forward","value":"  "}`, "value"},
		// windows_feature
		{"feature ok", "windows_feature", `{"name":"SMB1Protocol","state":"disabled"}`, ""},
		{"feature bad name", "windows_feature", `{"name":"SMB1 Protocol","state":"disabled"}`, "name"},
		// reboot_pending
		{"reboot ok", "reboot_pending", `{"max_hours":72,"allow_reboot":false}`, ""},
		{"reboot zero", "reboot_pending", `{"max_hours":0}`, "max_hours"},
		// disk_free
		{"disk ok", "disk_free", `{"mount":"C:","min_free_pct":10}`, ""},
		{"disk 100", "disk_free", `{"mount":"/","min_free_pct":100}`, "min_free_pct"},
		{"disk zero", "disk_free", `{"mount":"/","min_free_pct":0}`, "min_free_pct"},
		{"disk no mount", "disk_free", `{"min_free_pct":10}`, "mount"},
		// unknown kind
		{"unknown kind", "quantum", `{}`, "unknown check kind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCheck(tc.kind, json.RawMessage(tc.params))
			switch {
			case tc.bad == "" && err != nil:
				t.Fatalf("expected %s %s to be accepted, got %v", tc.kind, tc.params, err)
			case tc.bad != "" && err == nil:
				t.Fatalf("expected %s %s to be refused for %q", tc.kind, tc.params, tc.bad)
			case tc.bad != "" && !strings.Contains(err.Error(), tc.bad):
				t.Fatalf("error %q does not name %q", err, tc.bad)
			}
		})
	}
}

func TestValidateCheckRejectsOversizeParams(t *testing.T) {
	big := `{"key":"net.ipv4.ip_forward","value":"` + strings.Repeat("x", MaxParamsBytes+10) + `"}`
	if err := ValidateCheck("sysctl", json.RawMessage(big)); err == nil || !strings.Contains(err.Error(), "params") {
		t.Fatalf("expected an oversize params refusal, got %v", err)
	}
	if MaxParamsBytesFor("command") <= MaxCommandBodyBytes || MaxParamsBytesFor("file") <= MaxFileContentBytes {
		t.Fatal("the two kinds that carry a payload need a params envelope larger than the payload")
	}
	body := strings.Repeat("y", MaxCommandBodyBytes+1)
	b, _ := json.Marshal(map[string]string{"language": "bash", "check": body})
	if err := ValidateCheck("command", b); err == nil || !strings.Contains(err.Error(), "check") {
		t.Fatalf("expected an oversize check-body refusal, got %v", err)
	}
}

func TestValidateCheckRequiresAnObject(t *testing.T) {
	for _, raw := range []string{`[]`, `"x"`, `3`} {
		if err := ValidateCheck("firewall", json.RawMessage(raw)); err == nil {
			t.Fatalf("expected %s to be refused", raw)
		}
	}
	if err := ValidateCheck("firewall", nil); err != nil {
		t.Fatalf("absent params must read as an empty object: %v", err)
	}
}

func TestKindOSAndRunsOn(t *testing.T) {
	if !KindRunsOn("sysctl", "linux") || KindRunsOn("sysctl", "windows") {
		t.Fatal("sysctl is a linux kind")
	}
	if !KindRunsOn("registry", "windows") || KindRunsOn("registry", "linux") {
		t.Fatal("registry is a windows kind")
	}
	if KindKnown("quantum") || !KindKnown("file") {
		t.Fatal("KindKnown is wrong")
	}
	if len(Kinds()) != 12 {
		t.Fatalf("the contract names 12 kinds, the table has %d: %v", len(Kinds()), Kinds())
	}
	for _, k := range Kinds() {
		if len(KindOS(k)) == 0 {
			t.Fatalf("kind %s claims no platform", k)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		err  bool
	}{
		{"8.5.0", "8.5.0", 0, false},
		{"8.5.1", "8.5.0", 1, false},
		{"8.5", "8.5.0", 0, false},
		{"2.9", "2.10", -1, false},
		{"1:2.9.1-1ubuntu2", "2.9", 1, false},
		{"2.9.1-1ubuntu2", "2.9.1", 0, false},
		{"5.15.0~rc1", "5.15", 0, false},
		{"126.0.6478.126", "120", 1, false},
		{"latest", "1.0", 0, true},
		{"1.0", "stable", 0, true},
		{"", "1.0", 0, true},
	}
	for _, tc := range cases {
		got, err := CompareVersions(tc.a, tc.b)
		if tc.err {
			if err == nil {
				t.Fatalf("CompareVersions(%q,%q) should refuse to guess", tc.a, tc.b)
			}
			if !strings.Contains(err.Error(), "cannot compare versions") {
				t.Fatalf("unexpected error text %q", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("CompareVersions(%q,%q): %v", tc.a, tc.b, err)
		}
		if (got > 0) != (tc.want > 0) || (got < 0) != (tc.want < 0) {
			t.Fatalf("CompareVersions(%q,%q) = %d, want sign %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestClampsAndTruncate(t *testing.T) {
	if ClampInterval(0) != DefaultIntervalSec || ClampInterval(5) != MinIntervalSec || ClampInterval(999999) != MaxIntervalSec {
		t.Fatal("interval clamp is wrong")
	}
	if ClampTimeout(0) != DefaultTimeoutSec || ClampTimeout(1) != MinTimeoutSec || ClampTimeout(9999) != MaxTimeoutSec {
		t.Fatal("timeout clamp is wrong")
	}
	if got := Truncate("hello", 10); got != "hello" {
		t.Fatalf("short strings are untouched, got %q", got)
	}
	got := Truncate(strings.Repeat("a", 300), MaxObservedBytes)
	if len(got) > MaxObservedBytes || !strings.HasSuffix(got, "\u2026") {
		t.Fatalf("truncation is wrong: %d bytes, %q", len(got), got[len(got)-4:])
	}
	// A cut inside a multi-byte rune must not produce invalid UTF-8.
	wide := strings.Repeat("\u00e9", 200)
	cut := Truncate(wide, 50)
	if len(cut) > 50 {
		t.Fatalf("truncate overshot: %d", len(cut))
	}
	for i, r := range cut {
		if r == '\uFFFD' {
			t.Fatalf("truncation broke a rune at %d: %q", i, cut)
		}
	}
}

func TestRequiresAdminAndReboot(t *testing.T) {
	if ok, _ := RequiresAdmin("command", json.RawMessage(`{"language":"bash","check":"x"}`)); !ok {
		t.Fatal("a command check must need admin")
	}
	if ok, _ := RequiresAdmin("file", json.RawMessage(`{"path":"/etc/x","state":"present","content":"a"}`)); ok {
		t.Fatal("/etc is the ordinary case and must not need admin")
	}
	if ok, _ := RequiresAdmin("file", json.RawMessage(`{"path":"/usr/local/bin/x","state":"present","content":"a"}`)); !ok {
		t.Fatal("a write outside /etc must need admin")
	}
	if ok, _ := RequiresAdmin("reboot_pending", json.RawMessage(`{"max_hours":72}`)); ok {
		t.Fatal("a check-only reboot_pending must not need admin")
	}
	if ok, _ := RequiresAdmin("reboot_pending", json.RawMessage(`{"max_hours":72,"allow_reboot":true}`)); !ok {
		t.Fatal("allow_reboot must need admin")
	}
	if !AllowsReboot("reboot_pending", json.RawMessage(`{"max_hours":1,"allow_reboot":true}`)) {
		t.Fatal("AllowsReboot is wrong")
	}
	if AllowsReboot("file", json.RawMessage(`{}`)) {
		t.Fatal("only reboot_pending can reboot")
	}
}

func TestFileAuditAndPathStyle(t *testing.T) {
	if PathStyle("/etc/hosts") != "unix" || PathStyle(`C:\Windows`) != "windows" || PathStyle("etc") != "" {
		t.Fatal("PathStyle is wrong")
	}
	if !FileIsAudited(`C:\Windows\System32\drivers\etc\hosts`) {
		t.Fatal("the hosts file is allowed but audited")
	}
	if err := CheckFilePath(`C:\Windows\System32\drivers\etc\hosts`, "present", "x"); err != nil {
		t.Fatalf("the hosts file must be allowed: %v", err)
	}
}

func TestSeverityTriggerState(t *testing.T) {
	for _, s := range []string{"info", "warning", "critical"} {
		if !ValidSeverity(s) {
			t.Fatalf("%s is a severity", s)
		}
	}
	if ValidSeverity("drift") || ValidSeverity("") {
		t.Fatal("severity is validated against exactly three values")
	}
	for _, tr := range []string{"schedule", "startup", "config", "manual", "remediate", "preview"} {
		if !ValidTrigger(tr) {
			t.Fatalf("%s is a trigger", tr)
		}
	}
	if ValidTrigger("cron") {
		t.Fatal("unknown triggers are refused")
	}
	if !ValidState("fixed") || ValidState("drifted") {
		t.Fatal("state vocabulary is wrong")
	}
}

// A Windows program is named by its Uninstall DisplayName, which is ordinary
// text; a Linux package is named by its manager's id. Both spellings have to
// be writable, and neither may start with something a command line would read
// as an option.
func TestPackageNameAcceptsBothSpellings(t *testing.T) {
	for _, ok := range []string{
		"unattended-upgrades", "curl", "Git.Git", "Microsoft.VisualStudioCode",
		"7-Zip 26.03 (x64)", "GitHub CLI", "Node.js", "Google Drive",
		"NVIDIA App 11.0.8.299", "Intel® Chipset Device Software",
		"AMD Software: Adrenalin Edition", "Bitdefender Total Security",
	} {
		if !packageNameOK(ok) {
			t.Errorf("%q is a package a device can hold", ok)
		}
	}
	for _, bad := range []string{
		"", "-x", " leading", "trailing ", "two\nlines", "bell\aname",
		strings.Repeat("x", 257),
	} {
		if packageNameOK(bad) {
			t.Errorf("%q must not be accepted as a package name", bad)
		}
	}
}

// The registry path rule has to allow the keys Windows actually has - GUID
// braces above all - while still refusing a wildcard, an empty component and
// anything but the two roots, and while SAYING which of those it was.
func TestRegistryPathCharactersAndReasons(t *testing.T) {
	for _, ok := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		`HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`,
		`HKLM\SOFTWARE\Classes\CLSID\{00021401-0000-0000-C000-000000000046}\InProcServer32`,
		`HKCU\SOFTWARE\Policies\Microsoft\Office (16.0)\common`,
		`HKLM\SOFTWARE\Vendor+Co, Ltd.'s app#2`,
	} {
		if err := CheckRegistryPath(ok); err != nil {
			t.Errorf("%s is an ordinary registry key: %v", ok, err)
		}
	}
	for _, tc := range []struct{ path, reason string }{
		{`HKLM\SOFTWARE\Micro*`, "wildcard"},
		{`HKCU\SOFTWARE\?`, "wildcard"},
		{`HKLM\SOFTWARE\\X`, "empty"},
		{`HKLM\SOFTWARE\X\`, "empty"},
		{"HKLM\\SOFTWARE\\X\x01", "control character"},
		{`HKU\SOFTWARE\X`, "only HKLM and HKCU"},
		{`HKLM`, "at least one key name"},
	} {
		if err := CheckRegistryPath(tc.path); err == nil {
			t.Errorf("%s must be refused", tc.path)
			continue
		}
		why := regPathReason(tc.path)
		if why == nil || !strings.Contains(why.Error(), tc.reason) {
			t.Errorf("%s: the refusal must name %q, got %v", tc.path, tc.reason, why)
		}
	}
	// A path the deny list refuses is syntactically fine, so the explainer
	// must stay quiet and let the deny message through.
	if regPathReason(`HKLM\SAM\Domains`) != nil {
		t.Fatal(`the deny list, not the syntax, refuses HKLM\SAM`)
	}
	if err := CheckRegistryPath(`HKLM\SAM\Domains`); err == nil || !strings.Contains(err.Error(), "SAM") {
		t.Fatalf(`HKLM\SAM stays denied: %v`, err)
	}
}

func TestCheckVersion(t *testing.T) {
	cases := []struct {
		got, want, op string
		expected      bool
	}{
		{"1.2.3", "1.2.3", "==", true},
		{"1.2.4", "1.2.3", "==", false},
		{"1.2.4", "1.2.3", ">=", true},
		{"1.2.3", "1.2.3", ">=", true},
		{"1.2.2", "1.2.3", ">=", false},
		{"1.2.2", "1.2.3", "<=", true},
		{"1.2.3", "1.2.3", "<=", true},
		{"1.2.4", "1.2.3", "<=", false},
		{"2.0.0", "1.9.9", ">", true},
		{"1.9.9", "2.0.0", "<", true},
		{"1.2.3", "1.2.4", "!=", true},
	}
	for _, tc := range cases {
		ok, err := CheckVersion(tc.got, tc.want, tc.op)
		if err != nil {
			t.Fatalf("CheckVersion(%q, %q, %q): %v", tc.got, tc.want, tc.op, err)
		}
		if ok != tc.expected {
			t.Errorf("CheckVersion(%q, %q, %q) = %v, want %v", tc.got, tc.want, tc.op, ok, tc.expected)
		}
	}
}

