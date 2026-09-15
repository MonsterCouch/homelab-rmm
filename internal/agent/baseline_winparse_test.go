package agent

import (
	"strings"
	"testing"
)

func TestBlWinFirewallProfiles(t *testing.T) {
	out := `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound

Ok.
`
	p, complete := blWinFirewallProfiles(out)
	if !complete {
		t.Fatalf("all three profiles are present: %+v", p)
	}
	if !p["domain"] || !p["private"] || p["public"] {
		t.Fatalf("states wrong: %+v", p)
	}
	if got := blWinFirewallLabel(p); got != "domain/private/public: on/on/off" {
		t.Fatalf("label wrong: %q", got)
	}
	if _, complete := blWinFirewallProfiles("garbage"); complete {
		t.Fatal("unparsable output must not read as complete")
	}
	if got := blWinFirewallLabel(map[string]bool{"domain": true}); !strings.Contains(got, "unknown") {
		t.Fatalf("a missing profile must read as unknown: %q", got)
	}
}

func TestBlWinTimeSource(t *testing.T) {
	synced := "Leap Indicator: 0(no warning)\nStratum: 3\nSource: time.windows.com,0x9\nPoll Interval: 10\n"
	src, ok := blWinTimeSource(synced)
	if !ok || src != "time.windows.com,0x9" {
		t.Fatalf("a real source must read as synced: %q %v", src, ok)
	}
	for _, free := range []string{"Source: Local CMOS Clock\n", "Source: Free-running System Clock\n"} {
		if _, ok := blWinTimeSource(free); ok {
			t.Fatalf("%q is not time synchronisation", free)
		}
	}
	if _, ok := blWinTimeSource("The service has not been started."); ok {
		t.Fatal("no Source line means not synced")
	}
}

func TestBlWinFeatureState(t *testing.T) {
	state, ok := blWinFeatureState(`{"name":"SMB1Protocol","state":"Disabled"}`)
	if !ok || state != "Disabled" || blWinFeatureEnabled(state) {
		t.Fatalf("wrong: %q %v", state, ok)
	}
	state, ok = blWinFeatureState("WARNING: something\r\n{\"name\":\"X\",\"state\":\"Enabled\"}\r\n")
	if !ok || !blWinFeatureEnabled(state) {
		t.Fatalf("a banner before the JSON must not break the parse: %q %v", state, ok)
	}
	if _, ok := blWinFeatureState("Get-WindowsOptionalFeature: not found"); ok {
		t.Fatal("no JSON means no answer")
	}
	if blWinFeatureEnabled("EnablePending") {
		t.Fatal("a pending enable is not enabled yet")
	}
}

func TestBlWinWingetList(t *testing.T) {
	out := "Name                Id                     Version    Available Source\n" +
		"-------------------------------------------------------------------------\n" +
		"Visual Studio Code  Microsoft.VisualStudioCode 1.92.0  1.93.0    winget\n"
	found, version := blWinWingetList(out, "Microsoft.VisualStudioCode")
	if !found || version != "1.92.0" {
		t.Fatalf("wrong: %v %q", found, version)
	}
	if found, _ := blWinWingetList(out, "Other.Package"); found {
		t.Fatal("a different id must not match")
	}
	if found, _ := blWinWingetList("No installed package found matching input criteria.", "X"); found {
		t.Fatal("the empty answer is not an error")
	}
}

func TestParseNetLocalGroup(t *testing.T) {
	out := "Alias name     Administrators\r\n" +
		"Comment        Administrators have complete and unrestricted access\r\n" +
		"\r\n" +
		"Members\r\n" +
		"\r\n" +
		"-------------------------------------------------------------------------------\r\n" +
		"Administrator\r\n" +
		"CORP\\Domain Admins\r\n" +
		"rmm-admin\r\n" +
		"The command completed successfully.\r\n"
	got := parseNetLocalGroup(out)
	want := []string{"Administrator", `CORP\Domain Admins`, "rmm-admin"}
	if len(got) != len(want) {
		t.Fatalf("got %d members %v, want %v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("member %d is %q, want %q", i, got[i], want[i])
		}
	}
	if len(parseNetLocalGroup("The specified local group does not exist.")) != 0 {
		t.Fatal("an error message is not a member list")
	}
}

func TestParseGroupAndPasswd(t *testing.T) {
	n, gid, members, ok := parseGroupLine("sudo:x:27:alice,bob")
	if !ok || n != "sudo" || gid != "27" || len(members) != 2 || members[1] != "bob" {
		t.Fatalf("wrong: %q %q %v %v", n, gid, members, ok)
	}
	if _, _, members, _ := parseGroupLine("root:x:0:"); len(members) != 0 {
		t.Fatalf("an empty member list is empty, got %v", members)
	}
	if _, _, _, ok := parseGroupLine("# a comment"); ok {
		t.Fatal("comments are not entries")
	}
	primary := parsePasswdPrimary("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\n", "0")
	if len(primary) != 1 || primary[0] != "root" {
		t.Fatalf("primary members wrong: %v", primary)
	}
}
