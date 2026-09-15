package agent

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseOSRelease(t *testing.T) {
	m := parseOSRelease(`PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
# a comment
VERSION_CODENAME='noble'
WEIRD="quoted \"inner\""
NOVALUE
`)
	if m["PRETTY_NAME"] != "Ubuntu 24.04.4 LTS" || m["ID"] != "ubuntu" || m["VERSION_CODENAME"] != "noble" {
		t.Fatalf("bad parse: %#v", m)
	}
	if m["WEIRD"] != `quoted "inner"` {
		t.Fatalf("escaped quote: %q", m["WEIRD"])
	}
	if _, ok := m["NOVALUE"]; ok {
		t.Fatal("line without = must be ignored")
	}
}

func TestParseListUnits(t *testing.T) {
	text := `cron.service                 loaded    active   running Regular background program processing daemon
dbus.service                 loaded    active   running D-Bus System Message Bus
● networkd-dispatcher.service loaded    failed   failed  Dispatcher daemon for systemd-networkd
snapd.service                not-found inactive dead    snapd.service
apt-daily.service            loaded    inactive dead    Daily apt download activities
ssh.service                  loaded    activating start   OpenBSD Secure Shell server
junk line
`
	rows := parseListUnits(text)
	if len(rows) != 6 {
		t.Fatalf("want 6 rows, got %d: %#v", len(rows), rows)
	}
	if rows[0].Unit != "cron.service" || rows[0].Description != "Regular background program processing daemon" {
		t.Fatalf("row 0: %#v", rows[0])
	}
	if rows[2].Unit != "networkd-dispatcher.service" || rows[2].Active != "failed" {
		t.Fatalf("bullet row: %#v", rows[2])
	}
	if unitState(rows[0].Active, rows[0].Sub) != "running" || unitState(rows[2].Active, rows[2].Sub) != "failed" ||
		unitState(rows[4].Active, rows[4].Sub) != "stopped" || unitState(rows[5].Active, rows[5].Sub) != "start_pending" {
		t.Fatal("state mapping")
	}
	if unitState("deactivating", "stop") != "stop_pending" || unitState("", "") != "unknown" {
		t.Fatal("state mapping edge cases")
	}
}

func TestParseListUnitFiles(t *testing.T) {
	text := `apt-daily-upgrade.service                    static   -
console-getty.service                        disabled disabled
cron.service                                 enabled  enabled
autovt@.service                              alias    -
docker.service                               masked
getty@.service                               enabled  enabled
systemd-networkd.service                     indirect enabled
`
	m := parseListUnitFiles(text)
	if len(m) != 7 || m["cron.service"] != "enabled" || m["docker.service"] != "masked" {
		t.Fatalf("bad parse: %#v", m)
	}
	cases := map[string]string{
		"enabled": "auto", "enabled-runtime": "auto", "disabled": "disabled", "masked": "disabled",
		"static": "manual", "indirect": "manual", "generated": "manual", "transient": "manual", "": "manual", "weird": "manual",
	}
	for in, want := range cases {
		if got := unitStartType(in); got != want {
			t.Errorf("unitStartType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseShowBlocks(t *testing.T) {
	text := `Id=cron.service
MainPID=812
Description=Regular background program processing daemon
ActiveState=active
SubState=running
UnitFileState=enabled
LoadState=loaded

Id=docker.service
MainPID=0
Description=docker.service
ActiveState=inactive
SubState=dead
UnitFileState=
LoadState=masked
`
	blocks := parseShowBlocks(text)
	if len(blocks) != 2 {
		t.Fatalf("want 2 blocks, got %d", len(blocks))
	}
	s := serviceFromShow(blocks[0])
	if s.Name != "cron.service" || s.PID != 812 || s.State != "running" || s.StartType != "auto" || s.DisplayName != "Regular background program processing daemon" {
		t.Fatalf("service 0: %#v", s)
	}
	s = serviceFromShow(blocks[1])
	if s.PID != 0 || s.State != "stopped" || s.StartType != "disabled" {
		t.Fatalf("masked service: %#v", s)
	}
}

func TestIsActiveState(t *testing.T) {
	for in, want := range map[string]string{"active\n": "running", "inactive": "stopped", "failed": "failed", "activating": "start_pending", "unknown": "unknown", "": "unknown"} {
		if got := isActiveState(in); got != want {
			t.Errorf("isActiveState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidUnitName(t *testing.T) {
	good := []string{"ssh", "ssh.service", "getty@tty1.service", "dbus-org.freedesktop.login1.service", "systemd-fsck@dev-disk-by\\x2duuid-abc.service", "a:b"}
	bad := []string{"", "-rf", "--now", "a b", "a;b", "a$(x)", "a|b", "a\nb", "../etc", "a'b", strings.Repeat("a", 300)}
	for _, n := range good {
		if !validUnitName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range bad {
		if validUnitName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}

func TestParseJournalMatches(t *testing.T) {
	got := journalMatchesFor("sshd")
	want := []string{"_SYSTEMD_UNIT=sshd.service", "+", "UNIT=sshd.service", "_PID=1", "+", "SYSLOG_IDENTIFIER=sshd", "+", "_COMM=sshd"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plain name: %#v", got)
	}
	got = journalMatchesFor("cron.service")
	if got[0] != "_SYSTEMD_UNIT=cron.service" || got[5] != "SYSLOG_IDENTIFIER=cron" {
		t.Fatalf("service suffix: %#v", got)
	}
	got = journalMatchesFor("apt-daily.timer")
	if got[0] != "_SYSTEMD_UNIT=apt-daily.timer" || got[5] != "SYSLOG_IDENTIFIER=apt-daily.timer" {
		t.Fatalf("timer suffix must be kept: %#v", got)
	}
	for _, m := range got {
		if strings.HasPrefix(m, "-") {
			t.Fatalf("a match must never look like an option: %q", m)
		}
	}
	if hasUnitSuffix("foo.socket") != true || hasUnitSuffix("foo.services") || hasUnitSuffix("sshd") {
		t.Fatal("hasUnitSuffix")
	}
}

func TestValidPkgID(t *testing.T) {
	good := []string{"coreutils", "libstdc++6", "g++", "python3.12", "kernel-core.x86_64", "libc6:amd64", "Foo_Bar", "gcc-13-base"}
	bad := []string{"", "-y", "--reinstall", "pkg-", "pkg/", "pkg=1.0", "pkg:", "a b", "a;b", "$(x)", "../x", "pkg*", "pkg?", strings.Repeat("a", 300)}
	for _, n := range good {
		if !validPkgID(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range bad {
		if validPkgID(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}

func TestParseJournalJSON(t *testing.T) {
	text := `{"__REALTIME_TIMESTAMP":"1757908800123456","PRIORITY":"3","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root","_PID":"4242"}
{"__REALTIME_TIMESTAMP":"1757908700000000","PRIORITY":"4","_COMM":"kernel","_TRANSPORT":"kernel","MESSAGE":[72,105,32,255,33]}
{"__REALTIME_TIMESTAMP":"1757908600000000","PRIORITY":"6","_TRANSPORT":"kernel","MESSAGE":["one","two"]}
{"__REALTIME_TIMESTAMP":"1757908500000000","PRIORITY":"7","_SYSTEMD_UNIT":"cron.service","MESSAGE":null}
not json
{"truncated":
`
	es := parseJournalJSON(text)
	if len(es) != 4 {
		t.Fatalf("want 4 entries, got %d: %#v", len(es), es)
	}
	if es[0].TS != 1757908800 || es[0].Level != "error" || es[0].Source != "sshd" || es[0].Message != "Failed password for root" || es[0].EventID != 4242 {
		t.Fatalf("entry 0: %#v", es[0])
	}
	if es[1].Level != "warning" || es[1].Source != "kernel" || !strings.HasPrefix(es[1].Message, "Hi ") || !strings.HasSuffix(es[1].Message, "!") {
		t.Fatalf("byte-array message: %#v", es[1])
	}
	if es[2].Message != "one\ntwo" || es[2].Source != "kernel" || es[2].Level != "info" {
		t.Fatalf("multi-value message: %#v", es[2])
	}
	if es[3].Message != "" || es[3].Source != "cron.service" {
		t.Fatalf("null message: %#v", es[3])
	}
	if journalLevel("0") != "error" || journalLevel("4") != "warning" || journalLevel("5") != "info" || journalLevel("x") != "info" {
		t.Fatal("journalLevel mapping")
	}
}

func TestParseSyslogLines(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	lines := []string{
		"Sep 15 03:56:01 host CRON[1234]: (root) CMD (run-parts /etc/cron.hourly)",
		"Sep 15 03:57:02 host kernel: [12345.678] usb 1-1: device descriptor read/64, error -71",
		"2026-09-15T03:58:03.123456+00:00 host sshd[99]: Connection refused by policy",
		"garbage without structure",
		"Dec 31 23:59:59 host prog: from last year",
	}
	es := parseSyslogLines(lines, now)
	if len(es) != 4 {
		t.Fatalf("want 4 entries, got %d: %#v", len(es), es)
	}
	// newest first
	if es[0].Source != "sshd" || es[0].EventID != 99 || es[0].Level != "warning" {
		t.Fatalf("rfc3339 entry: %#v", es[0])
	}
	if es[1].Source != "kernel" || es[1].Level != "error" {
		t.Fatalf("kernel entry: %#v", es[1])
	}
	if es[2].Source != "CRON" || es[2].Level != "info" || es[2].EventID != 1234 {
		t.Fatalf("cron entry: %#v", es[2])
	}
	if y := time.Unix(es[3].TS, 0).Year(); y != 2025 {
		t.Fatalf("December line read in September must be last year, got %d", y)
	}
	if !logLevelAllowed("error", "error") || logLevelAllowed("error", "warning") || !logLevelAllowed("warning", "error") || !logLevelAllowed("", "info") || logLevelAllowed("warning", "info") {
		t.Fatal("logLevelAllowed")
	}
}

func TestParseAptSimulate(t *testing.T) {
	text := `NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Building dependency tree...
Calculating upgrade...
The following packages will be upgraded:
  coreutils libssl3t64 openssl
3 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Inst coreutils [9.4-3ubuntu6.1] (9.4-3ubuntu6.2 Ubuntu:24.04/noble-updates [amd64])
Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64]) []
Inst newdep (1.0-1 Debian:12.7/stable [all])
Conf coreutils (9.4-3ubuntu6.2 Ubuntu:24.04/noble-updates [amd64])
Remv oldthing [1.0]
`
	ups := parseAptSimulate(text)
	if len(ups) != 4 {
		t.Fatalf("want 4 updates, got %d: %#v", len(ups), ups)
	}
	if ups[0].ID != "coreutils" || ups[0].Version != "9.4-3ubuntu6.2" || ups[0].Severity != "" || ups[0].Source != "apt" || ups[0].Title != "coreutils 9.4-3ubuntu6.1 → 9.4-3ubuntu6.2" {
		t.Fatalf("coreutils: %#v", ups[0])
	}
	if ups[1].Severity != "security" || len(ups[1].Categories) != 1 || ups[1].Categories[0] != "Security" {
		t.Fatalf("security flag: %#v", ups[1])
	}
	if ups[3].ID != "newdep" || ups[3].Version != "1.0-1" || ups[3].Title != "newdep → 1.0-1" {
		t.Fatalf("new package: %#v", ups[3])
	}
	if len(parseAptSimulate("Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")) != 0 {
		t.Fatal("no updates must parse to none")
	}
}

func TestParseAptListUpgradable(t *testing.T) {
	text := `
WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Listing...
coreutils/noble-updates 9.4-3ubuntu6.2 amd64 [upgradable from: 9.4-3ubuntu6.1]
libssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]
`
	ups := parseAptListUpgradable(text)
	if len(ups) != 2 || ups[0].ID != "coreutils" || ups[0].Version != "9.4-3ubuntu6.2" || ups[0].Title != "coreutils 9.4-3ubuntu6.1 → 9.4-3ubuntu6.2" {
		t.Fatalf("bad parse: %#v", ups)
	}
	if ups[1].Severity != "security" {
		t.Fatalf("security from repo list: %#v", ups[1])
	}
}

func TestParseDnfCheckUpdate(t *testing.T) {
	text := `
kernel-core.x86_64                    6.10.3-200.fc40            updates
openssl-libs.x86_64                   1:3.2.1-3.fc40             updates
some-very-long-package-name-that-wraps.noarch
                                      2.0-1.fc40                 fedora
curl.x86_64                           8.6.0-9.fc40               updates-security

Obsoleting Packages
newname.x86_64                        1.0-1.fc40                 updates
    oldname.x86_64                    0.9-1.fc40                 @System
`
	ups := parseDnfCheckUpdate(text)
	if len(ups) != 4 {
		t.Fatalf("want 4 updates, got %d: %#v", len(ups), ups)
	}
	if ups[0].ID != "kernel-core.x86_64" || ups[0].Version != "6.10.3-200.fc40" || ups[0].Source != "dnf" {
		t.Fatalf("kernel: %#v", ups[0])
	}
	if ups[2].ID != "some-very-long-package-name-that-wraps.noarch" || ups[2].Version != "2.0-1.fc40" {
		t.Fatalf("wrapped line: %#v", ups[2])
	}
	if ups[3].Severity != "security" {
		t.Fatalf("security repo: %#v", ups[3])
	}
	sec := parseDnfSecurity(`FEDORA-2024-1a2b3c Important/Sec. openssl-libs-1:3.2.1-3.fc40.x86_64
FEDORA-2024-4d5e6f Moderate/Sec.  curl-8.6.0-9.fc40.x86_64
FEDORA-2024-7g8h9i bugfix         nothing-1.0-1.fc40.noarch
`)
	if sec["openssl-libs"] != "Important" || sec["openssl-libs.x86_64"] != "Important" || sec["curl"] != "Moderate" {
		t.Fatalf("security map: %#v", sec)
	}
	if n, a := rpmNameFromNEVRA("kernel-core-6.10.3-200.fc40.x86_64"); n != "kernel-core" || a != "x86_64" {
		t.Fatalf("nevra split: %q %q", n, a)
	}
	if n, a := rpmSplitArch("python3.12.x86_64"); n != "python3.12" || a != "x86_64" {
		t.Fatalf("rpmSplitArch: %q %q", n, a)
	}
}

func TestParsePacman(t *testing.T) {
	ups := parsePacmanQu("linux 6.10.2.arch1-1 -> 6.10.3.arch1-1\nfirefox 129.0-1 -> 129.0.1-1 [ignored]\nbroken line\n")
	if len(ups) != 2 || ups[0].ID != "linux" || ups[0].Version != "6.10.3.arch1-1" || ups[0].Title != "linux 6.10.2.arch1-1 → 6.10.3.arch1-1" {
		t.Fatalf("pacman -Qu: %#v", ups)
	}
	if ups[1].Description == "" {
		t.Fatal("ignored flag lost")
	}
	sw := parsePacmanQ("bash 5.2.026-2\nzlib 1:1.3.1-2\n")
	if len(sw) != 2 || sw[1].Name != "zlib" || sw[1].Version != "1:1.3.1-2" {
		t.Fatalf("pacman -Q: %#v", sw)
	}
	if up, ok := archKernelUpToDate("6.10.3-arch1-1", "linux 6.10.3.arch1-1"); !ok || !up {
		t.Fatal("same kernel must compare equal")
	}
	if up, ok := archKernelUpToDate("6.10.2-arch1-1", "linux 6.10.3.arch1-1"); !ok || up {
		t.Fatal("older running kernel must compare unequal")
	}
	if _, ok := archKernelUpToDate("", "linux 6.10.3.arch1-1"); ok {
		t.Fatal("empty uname is not comparable")
	}
	if archKernelPackage("6.6.44-1-lts") != "linux-lts" || archKernelPackage("6.10.3-zen1-1-zen") != "linux-zen" || archKernelPackage("6.10.3-arch1-1") != "linux" {
		t.Fatal("kernel flavour")
	}
}

func TestParseZypperLu(t *testing.T) {
	text := `Loading repository data...
Reading installed packages...
S | Repository            | Name         | Current Version | Available Version | Arch
--+-----------------------+--------------+-----------------+-------------------+-------
v | Main Update Repo      | curl         | 8.0.1-150600.1  | 8.0.1-150600.4.3  | x86_64
v | SLE-Security-Updates  | libopenssl3  | 3.1.4-150600.1  | 3.1.4-150600.5.1  | x86_64
`
	ups := parseZypperLu(text)
	if len(ups) != 2 || ups[0].ID != "curl" || ups[0].Version != "8.0.1-150600.4.3" || ups[0].Source != "zypper" {
		t.Fatalf("zypper lu: %#v", ups)
	}
	if ups[1].Severity != "security" {
		t.Fatalf("security repo: %#v", ups[1])
	}
}

func TestParseSoftwareLists(t *testing.T) {
	sw := parseTabbedSoftware("bash\t5.2.21-2ubuntu4\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\ncoreutils\t9.4-3ubuntu6.1\tMichael Stone <mstone@debian.org>\nnovendor\t1.0\t(none)\n\nbroken\n")
	if len(sw) != 3 || sw[0].Publisher != "Ubuntu Developers" || sw[1].Publisher != "Michael Stone" || sw[2].Publisher != "" {
		t.Fatalf("dpkg: %#v", sw)
	}
	// dpkg keeps removed packages with leftover conffiles in its database;
	// only "installed" rows are software the device actually has.
	sw = parseTabbedSoftware("bash\t5.2\tX\tinstalled\nremoved\t1.0\tX\tconfig-files\nhalf\t1.0\tX\thalf-installed\nolddpkg\t1.0\tX\t\nrpm\t1.0\tX\n")
	if len(sw) != 3 || sw[0].Name != "bash" || sw[1].Name != "olddpkg" || sw[2].Name != "rpm" {
		t.Fatalf("status filter: %#v", sw)
	}
	snaps := parseSnapList("Name    Version   Rev    Tracking       Publisher   Notes\ncore22  20240408  1380   latest/stable  canonical✓  base\nfirefox 129.0-1   4793   latest/stable  mozilla✓    -\n")
	if len(snaps) != 2 || snaps[0].Name != "core22" || snaps[0].Version != "20240408" || snaps[0].Publisher != "canonical" {
		t.Fatalf("snap: %#v", snaps)
	}
	fp := parseFlatpakList("org.gimp.GIMP\t2.10.38\ncom.spotify.Client\t1.2.40\n\n")
	if len(fp) != 2 || fp[0].Name != "org.gimp.GIMP" || fp[0].Version != "2.10.38" {
		t.Fatalf("flatpak: %#v", fp)
	}
}

func TestParseLspci(t *testing.T) {
	text := `00:00.0 Host bridge: Intel Corporation 8th Gen Core Processor Host Bridge/DRAM Registers (rev 07)
00:02.0 VGA compatible controller: Intel Corporation CoffeeLake-S GT2 [UHD Graphics 630] (rev 02)
01:00.0 3D controller: NVIDIA Corporation GP107M [GeForce GTX 1050 Mobile] (rev a1)
02:00.0 Display controller: Advanced Micro Devices, Inc. [AMD/ATI] Navi 23 (rev c1)
03:00.0 Ethernet controller: Intel Corporation Ethernet Connection I219-V
`
	gpus := parseLspci(text)
	want := []string{"Intel Corporation CoffeeLake-S GT2 [UHD Graphics 630]", "NVIDIA Corporation GP107M [GeForce GTX 1050 Mobile]", "Advanced Micro Devices, Inc. [AMD/ATI] Navi 23"}
	if !reflect.DeepEqual(gpus, want) {
		t.Fatalf("lspci: %#v", gpus)
	}
	if pciVendorName("0x10de") != "NVIDIA" || pciVendorName("8086") != "Intel" || pciVendorName("ffff") != "" {
		t.Fatal("vendor lookup")
	}
}

func TestDmiCleanAndResolv(t *testing.T) {
	for _, s := range []string{"To Be Filled By O.E.M.", "System Product Name", "Default string", "", "  ", "None", "Not Specified"} {
		if dmiClean(s) != "" {
			t.Errorf("dmiClean(%q) should be empty", s)
		}
	}
	if dmiClean("  Dell Inc. ") != "Dell Inc." {
		t.Fatal("dmiClean must trim")
	}
	if d := parseResolvConfDomain("# comment\nnameserver 1.1.1.1\nsearch home.lan example.com\n"); d != "home.lan" {
		t.Fatalf("search: %q", d)
	}
	if d := parseResolvConfDomain("domain corp.example.\nsearch other.lan\n"); d != "corp.example" {
		t.Fatalf("domain: %q", d)
	}
	if d := parseResolvConfDomain("nameserver 8.8.8.8\noptions timeout:2\n"); d != "" {
		t.Fatalf("no domain: %q", d)
	}
}

func TestParseLoginctlAndLast(t *testing.T) {
	text := `      1 1000 alice seat0 tty2
      3    0 root  -     pts/0
      c1  120 gdm   seat0 tty1
`
	if ids := parseLoginctlSessions(text); !reflect.DeepEqual(ids, []string{"1", "3", "c1"}) {
		t.Fatalf("sessions: %#v", ids)
	}
	if users := parseLoginctlUsers(text); !reflect.DeepEqual(users, []string{"alice", "root", "gdm"}) {
		t.Fatalf("users: %#v", users)
	}
	last := `reboot   system boot  6.8.0-45-generic Mon Sep 15 03:00   still running
alice    tty2         :0               Mon Sep 15 03:05   still logged in
wtmp begins Mon Sep  1 00:00:00 2026
`
	if u := parseLastUser(last); u != "alice" {
		t.Fatalf("last user: %q", u)
	}
	if uniq := uniqNonEmpty([]string{"b", "", "a", "b"}); !reflect.DeepEqual(uniq, []string{"b", "a"}) {
		t.Fatalf("uniqNonEmpty: %#v", uniq)
	}
}
