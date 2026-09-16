package agent

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func TestWinLabel(t *testing.T) {
	cases := []struct {
		product, display, build, ubr, fallback, want string
	}{
		{"Windows 10 Pro", "23H2", "22631", "4037", "", "Windows 11 Pro 23H2 (build 22631.4037)"},
		{"Windows 10 Pro", "22H2", "19045", "4780", "", "Windows 10 Pro 22H2 (build 19045.4780)"},
		{"Windows Server 2022 Datacenter", "21H2", "20348", "", "", "Windows Server 2022 Datacenter 21H2 (build 20348)"},
		{"", "", "", "", "Microsoft Windows 11 Home", "Windows 11 Home"},
		{"", "", "", "", "", "Windows"},
		{"Microsoft Windows 10 Enterprise", "", "19044", "", "", "Windows 10 Enterprise (build 19044)"},
	}
	for _, c := range cases {
		if got := winLabel(c.product, c.display, c.build, c.ubr, c.fallback); got != c.want {
			t.Errorf("winLabel(%q,%q,%q,%q,%q) = %q, want %q", c.product, c.display, c.build, c.ubr, c.fallback, got, c.want)
		}
	}
}

func TestWinUsers(t *testing.T) {
	if got := winCleanUser(`  .\bob `); got != "bob" {
		t.Errorf("winCleanUser local = %q", got)
	}
	if got := winCleanUser(`CORP\alice`); got != `CORP\alice` {
		t.Errorf("winCleanUser domain = %q", got)
	}
	if got := winSessionUser("PC1", "bob", "pc1"); got != "bob" {
		t.Errorf("local session user = %q", got)
	}
	if got := winSessionUser("CORP", "alice", "pc1"); got != `CORP\alice` {
		t.Errorf("domain session user = %q", got)
	}
	if got := winSessionUser("CORP", "", "pc1"); got != "" {
		t.Errorf("empty user = %q", got)
	}
}

func TestWinParseQueryUser(t *testing.T) {
	out := " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\r\n" +
		">administrator         console             1  Active      none   9/14/2026 8:00 AM\r\n" +
		" bob                                       2  Disc         1:23   9/14/2026 7:00 AM\r\n" +
		" carol                 rdp-tcp#3           3  Active         .   9/15/2026 1:00 AM\r\n" +
		" administrator         rdp-tcp#4           4  Active         .   9/15/2026 2:00 AM\r\n"
	got := winParseQueryUser(out)
	want := []string{"administrator", "carol"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := winParseQueryUser("No User exists for *\r\n"); len(got) != 0 {
		t.Fatalf("expected no users, got %v", got)
	}
}

func TestWinSoftwareFromUninstall(t *testing.T) {
	ok := winUninstallEntry{Name: " 7-Zip 23.01 (x64) ", Version: "23.01", Publisher: "Igor Pavlov", InstallDate: "20240115"}
	s, keep := winSoftwareFromUninstall(ok)
	if !keep || s.Name != "7-Zip 23.01 (x64)" || s.Installed != "2024-01-15" || s.Publisher != "Igor Pavlov" {
		t.Fatalf("good entry rejected or mangled: %+v %v", s, keep)
	}
	skip := []winUninstallEntry{
		{Name: ""},
		{Name: "Hidden thing", SystemComponent: 1},
		{Name: "Security Update for Microsoft Office", ReleaseType: "Security Update"},
		{Name: "Update for Office 2016 (KB1234567)"},
		{Name: "KB5031354", Version: "1"},
		{Name: "Office patch", ParentKeyName: "Office16"},
	}
	for _, e := range skip {
		if _, keep := winSoftwareFromUninstall(e); keep {
			t.Errorf("entry %+v should be skipped", e)
		}
	}
	// "KB" as the start of a real product name is not a hotfix.
	if _, keep := winSoftwareFromUninstall(winUninstallEntry{Name: "KBar Tools"}); !keep {
		t.Error("KBar Tools should be kept")
	}
}

func TestWinDedupeSoftware(t *testing.T) {
	in := []protocol.Software{
		{Name: "App", Version: "1.0"},
		{Name: "app", Version: "1.0", Publisher: "Vendor", Installed: "2024-01-01"},
		{Name: "App", Version: "2.0"},
		{Name: "   ", Version: "1"},
	}
	got := winDedupeSoftware(in)
	if len(got) != 2 {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	if got[0].Publisher != "Vendor" || got[0].Installed != "2024-01-01" {
		t.Fatalf("duplicate should have filled the gaps: %+v", got[0])
	}
}

// The Uninstall hives are writable by every user without elevation, so
// neither a field's length nor the number of entries may be theirs to choose:
// the inventory travels over one WebSocket frame the server caps at 16 MiB.
func TestWinSoftwareIsBounded(t *testing.T) {
	blob := strings.Repeat("A", 60000)
	s, keep := winSoftwareFromUninstall(winUninstallEntry{Name: blob, Version: blob, Publisher: blob, InstallDate: "20240115"})
	if !keep {
		t.Fatal("a long name is still an entry")
	}
	for name, field := range map[string]string{"name": s.Name, "version": s.Version, "publisher": s.Publisher} {
		if n := len([]rune(field)); n > winMaxSoftwareField+1 { // +1 for the ellipsis
			t.Errorf("%s kept %d runes, cap is %d", name, n, winMaxSoftwareField)
		}
	}
	var list []protocol.Software
	for i := winMaxSoftware + 9; i >= 0; i-- {
		list = append(list, protocol.Software{Name: fmt.Sprintf("app-%06d", i)})
	}
	got := winCapSoftware(list)
	if len(got) != winMaxSoftware {
		t.Fatalf("capped list has %d entries, want %d", len(got), winMaxSoftware)
	}
	if got[0].Name != "app-000000" {
		t.Errorf("the cap should keep a sorted prefix, first entry is %q", got[0].Name)
	}
	if short := winCapSoftware(list[:3]); len(short) != 3 {
		t.Errorf("a short list must survive whole, got %d", len(short))
	}
}

// Per-user installs live in the loaded HKEY_USERS hives. Entra ID accounts
// key theirs by an S-1-12-1 SID, which a hard-coded S-1-5-21 prefix skipped.
func TestWinIsUserHive(t *testing.T) {
	for _, n := range []string{
		"S-1-5-21-4285530640-3368155222-4143832586-1001",
		"S-1-12-1-1234567890-1234567890-1234567890-1234567890",
	} {
		if !winIsUserHive(n) {
			t.Errorf("%s is an interactive user hive", n)
		}
	}
	for _, n := range []string{
		".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20",
		"S-1-5-21-4285530640-3368155222-4143832586-1001_Classes",
		"S-1-12-1-1234567890-1234567890-1234567890-1234567890_Classes",
	} {
		if winIsUserHive(n) {
			t.Errorf("%s must not be enumerated", n)
		}
	}
}

// Win32_Processor is the physical-core source; gopsutil reports the logical
// count on Windows, which made cpu_cores equal cpu_threads on every device.
func TestWinCPUCounts(t *testing.T) {
	cores, threads := winCPUCounts([]winProcessor{{NumberOfCores: 14, NumberOfLogicalProcessors: 20}})
	if cores != 14 || threads != 20 {
		t.Errorf("one socket = %dc/%dt, want 14c/20t", cores, threads)
	}
	cores, threads = winCPUCounts([]winProcessor{
		{NumberOfCores: 8, NumberOfLogicalProcessors: 16},
		{NumberOfCores: 8, NumberOfLogicalProcessors: 16},
	})
	if cores != 16 || threads != 32 {
		t.Errorf("two sockets = %dc/%dt, want 16c/32t", cores, threads)
	}
	if cores, threads = winCPUCounts(nil); cores != 0 || threads != 0 {
		t.Errorf("no rows = %dc/%dt, want zeros so the caller keeps its own", cores, threads)
	}
}

func TestWinDates(t *testing.T) {
	// `installed` is an ISO date or nothing: the console renders and sorts
	// it, so an installer's free text must never travel in it.
	for in, want := range map[string]string{
		"20240115":     "2024-01-15", // MSI
		" 20240115 ":   "2024-01-15",
		"1/15/2024":    "2024-01-15", // en-US short date
		"15/01/2024":   "2024-01-15", // a first component over 12 is the day
		"15.01.2024":   "2024-01-15",
		"2024-01-15":   "2024-01-15",
		"2024/1/5":     "2024-01-05",
		"not-a-date":   "",
		"":             "",
		"2024":         "",
		"1/15/24":      "",
		"20241301":     "", // month 13
		"20240230":     "", // 30 February
		"99999999":     "",
		"soon/ish/yyy": "",
	} {
		if got := winInstallDate(in); got != want {
			t.Errorf("winInstallDate(%q) = %q want %q", in, got, want)
		}
	}
	if got := winCIMDate("20230512000000.000000+000"); got != "2023-05-12" {
		t.Errorf("winCIMDate = %q", got)
	}
	if got := winCIMDate("garbage"); got != "" {
		t.Errorf("winCIMDate garbage = %q", got)
	}
}

func TestWinPendingRenames(t *testing.T) {
	if winPendingRenames(nil) || winPendingRenames([]string{"", "  "}) {
		t.Error("empty lists must not count as pending")
	}
	if !winPendingRenames([]string{`\??\C:\Temp\a.tmp`, ""}) {
		t.Error("real entry must count")
	}
}

func TestWinServiceNames(t *testing.T) {
	states := map[uint32]string{1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running", 5: "continue_pending", 6: "pause_pending", 7: "paused", 99: "unknown"}
	for k, v := range states {
		if got := winServiceStateName(k); got != v {
			t.Errorf("state %d = %q want %q", k, got, v)
		}
	}
	if winServiceStartTypeName(2, false) != "auto" || winServiceStartTypeName(2, true) != "auto_delayed" ||
		winServiceStartTypeName(3, false) != "manual" || winServiceStartTypeName(4, true) != "disabled" ||
		winServiceStartTypeName(0, false) != "boot" || winServiceStartTypeName(1, false) != "system" || winServiceStartTypeName(9, false) != "unknown" {
		t.Error("start type mapping wrong")
	}
	if winCleanServiceDescription(`@%SystemRoot%\system32\foo.dll,-101`) != "" {
		t.Error("MUI reference should be blanked")
	}
	if winCleanServiceDescription(" Real description ") != "Real description" {
		t.Error("real description should be kept")
	}
}

func TestWinEventLogXPath(t *testing.T) {
	if got := winEventLogXPath("all", 0); got != "" {
		t.Errorf("all/0 = %q", got)
	}
	if got := winEventLogXPath("error", 0); got != "*[System[(Level=1 or Level=2)]]" {
		t.Errorf("error = %q", got)
	}
	if got := winEventLogXPath("warning", 1_700_000_000); got != "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[@SystemTime>='2023-11-14T22:13:20.000Z']]]" {
		t.Errorf("warning+since = %q", got)
	}
	// milliseconds are tolerated
	if got := winEventLogXPath("info", 1_700_000_000_000); got != "*[System[TimeCreated[@SystemTime>='2023-11-14T22:13:20.000Z']]]" {
		t.Errorf("info+since ms = %q", got)
	}
	for _, ok := range []string{"System", "Application", "Microsoft-Windows-TaskScheduler/Operational", "Windows PowerShell"} {
		if !winValidEventLogName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	// a leading "/" or "-" would read as a wevtutil option even as its own argument
	for _, bad := range []string{"", "System /q:*", "Sys\"tem", "/c:1", "/rd", "-f", " System", strings.Repeat("a", 201)} {
		if winValidEventLogName(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

const wevtSample = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Kernel-General' Guid='{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}'/><EventID>12</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-09-15T03:34:12.1234567Z'/><EventRecordID>1234</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/><Channel>System</Channel><Computer>PC1</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='MajorVersion'>10</Data></EventData><RenderingInfo Culture='en-US'><Message>The operating system started at system time 2026-09-15T03:34:12.</Message><Level>Information</Level><Task></Task><Opcode>Info</Opcode><Channel>System</Channel><Provider>Microsoft-Windows-Kernel-General</Provider></RenderingInfo></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/><EventID Qualifiers='49152'>7000</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='2026-09-15T03:30:00.000Z'/><EventRecordID>1233</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>System</Channel><Computer>PC1</Computer><Security/></System><EventData><Data Name='param1'>Foo Service</Data><Data Name='param2'>%%1053</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Legacy'/><EventID>1</EventID><Level></Level><TimeCreated SystemTime='not a time'/><Channel>Application</Channel></System><UserData><Custom><Field>hello</Field><Other>world</Other></Custom></UserData></Event>`

func TestWinParseWevtutilXML(t *testing.T) {
	entries, err := winParseWevtutilXML([]byte(wevtSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries", len(entries))
	}
	e := entries[0]
	if e.TS != 1789443252 || e.Level != "info" || e.Source != "Microsoft-Windows-Kernel-General" || e.EventID != 12 || !strings.HasPrefix(e.Message, "The operating system started") {
		t.Errorf("entry 0 wrong: %+v", e)
	}
	e = entries[1]
	if e.Level != "error" || e.EventID != 7000 || e.Source != "Service Control Manager" || e.Message != "param1=Foo Service | param2=%%1053" {
		t.Errorf("entry 1 wrong: %+v", e)
	}
	e = entries[2]
	if e.TS != 0 || e.Level != "info" || e.EventID != 1 || e.Message != "hello world" {
		t.Errorf("entry 2 wrong: %+v", e)
	}
	// empty output is an empty page, not an error
	if es, err := winParseWevtutilXML(nil); err != nil || len(es) != 0 {
		t.Errorf("empty: %v %v", es, err)
	}
	// garbage with no events is an error
	if _, err := winParseWevtutilXML([]byte("<Event><System>")); err == nil {
		t.Error("truncated garbage should error")
	}
	// one broken event does not lose the others
	broken := wevtSample + "\n<Event><System><Level>oops</Lev"
	if es, err := winParseWevtutilXML([]byte(broken)); err != nil || len(es) != 3 {
		t.Errorf("broken tail should keep the 3 good events: len=%d err=%v", len(es), err)
	}
}

// utf16BOM is the byte-order mark wevtutil puts at the head of a /uni:true
// capture (written as a rune, because Go source may not carry a literal one
// anywhere but the first byte of a file).
var utf16BOM = string(rune(0xFEFF))

// utf16Bytes encodes s the way a tool asked for Unicode output writes it.
func utf16Bytes(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

// evt-01: wevtutil writes the console code page unless it is told otherwise,
// which folds every character the code page cannot hold into "?" - Ω, 日本語,
// Привет, ✓ - before the agent reads a byte. /uni:true makes it write
// UTF-16LE instead, and this is the decoder for that stream.
func TestWinDecodeUTF16LE(t *testing.T) {
	const text = "<Event>ünïcödé-Ω-日本語-Привет-✓-🙂</Event>"
	if got := winDecodeUTF16LE(utf16Bytes(utf16BOM + text)); got != text {
		t.Errorf("with BOM = %q", got)
	}
	// stderr comes back without a BOM
	if got := winDecodeUTF16LE(utf16Bytes(text)); got != text {
		t.Errorf("without BOM = %q", got)
	}
	// a capture cut in half by the output cap loses the half code unit, not
	// the characters before it
	odd := append(utf16Bytes(utf16BOM+"abc"), 0x41)
	if got := winDecodeUTF16LE(odd); got != "abc" {
		t.Errorf("odd trailing byte = %q", got)
	}
	for _, empty := range [][]byte{nil, {}, {0x41}} {
		if got := winDecodeUTF16LE(empty); got != "" {
			t.Errorf("%v decoded to %q", empty, got)
		}
	}
	// the exact failure the live run caught: the same text decoded as a
	// single-byte code page would already be "?" by now
	if !strings.Contains(winDecodeUTF16LE(utf16Bytes("日本語")), "日本語") {
		t.Error("CJK did not survive the decode")
	}
}

// evt-02: wevtutil's RenderedXml format omits any record whose provider
// message cannot be resolved - it warns on stderr and still exits 0 - so the
// raw XML pass is merged back in and those records keep their provider, id,
// level and time.
func TestWinMergeRenderedEventsKeepsUnrenderableRecords(t *testing.T) {
	raw, err := winParseWevtutilRecords([]byte(wevtSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 3 || raw[0].RecordID != "1234" || raw[1].RecordID != "1233" || raw[2].RecordID != "" {
		t.Fatalf("record ids = %+v", raw)
	}
	// The rendered pass dropped everything but the first record.
	rendered, err := winParseWevtutilRecords([]byte(strings.Split(wevtSample, "\n")[0]))
	if err != nil {
		t.Fatal(err)
	}
	got := winMergeRenderedEvents(raw, rendered)
	if len(got) != 3 {
		t.Fatalf("merge lost a record: %d entries", len(got))
	}
	if !strings.HasPrefix(got[0].Message, "The operating system started") {
		t.Errorf("the rendered message was not kept: %q", got[0].Message)
	}
	if got[1].EventID != 7000 || got[1].Level != "error" || got[1].Source != "Service Control Manager" || got[1].TS == 0 {
		t.Errorf("the unrenderable record lost its identity: %+v", got[1])
	}
	// A record the rendered pass saw but the (later) raw pass no longer
	// covers is kept rather than dropped.
	got = winMergeRenderedEvents(raw[1:], rendered)
	if len(got) != 3 || !strings.HasPrefix(got[2].Message, "The operating system started") {
		t.Errorf("a record that slid out of the second window was lost: %+v", got)
	}
}

// evt-04: the 8000-character cap is a display cap. Applying it before the
// search made anything past character 8000 of a long message - a 9 KB
// command line, a policy dump - unfindable as well as unreadable.
func TestEventMessageTruncationIsADisplayCap(t *testing.T) {
	long := strings.Repeat("x", wevtMaxMessage+400) + "-winval-long-end"
	sample := `<Event><System><Provider Name='PS'/><EventID>403</EventID><Level>4</Level><TimeCreated SystemTime='2026-09-15T03:34:12.0000000Z'/><EventRecordID>9</EventRecordID><Channel>Windows PowerShell</Channel></System><EventData><Data Name='Host'>` + long + `</Data></EventData></Event>`
	entries, err := winParseWevtutilXML([]byte(sample))
	if err != nil || len(entries) != 1 {
		t.Fatalf("parse: %d %v", len(entries), err)
	}
	if !strings.HasSuffix(entries[0].Message, "-winval-long-end") {
		t.Fatal("the parser must keep the whole message for the search")
	}
	if got := winFilterEventLog(entries, "winval-long-end"); len(got) != 1 {
		t.Fatal("a search past the display cap found nothing")
	}
	out := winTruncateEventMessages(entries)
	if r := []rune(out[0].Message); len(r) != wevtMaxMessage+1 || r[wevtMaxMessage] != '…' {
		t.Errorf("message went out at %d runes", len(r))
	}
	// a short message is untouched
	short := []protocol.EventLogEntry{{Message: "fine"}}
	if got := winTruncateEventMessages(short); got[0].Message != "fine" {
		t.Errorf("short message = %q", got[0].Message)
	}
}

func TestWinFilterEventLog(t *testing.T) {
	in := []protocol.EventLogEntry{
		{Source: "Kernel", Message: "Disk error on \\Device\\Harddisk0"},
		{Source: "DCOM", Message: "The server did not register"},
	}
	if got := winFilterEventLog(in, ""); len(got) != 2 {
		t.Fatalf("empty search should keep all, got %d", len(got))
	}
	if got := winFilterEventLog(in, "DISK"); len(got) != 1 || got[0].Source != "Kernel" {
		t.Fatalf("substring on message failed: %+v", got)
	}
	if got := winFilterEventLog(in, "dcom"); len(got) != 1 || got[0].Source != "DCOM" {
		t.Fatalf("substring on source failed: %+v", got)
	}
}

func TestWinAVAndLicense(t *testing.T) {
	if got := winAVState(0x11000); got != "enabled, up to date" {
		t.Errorf("enabled up-to-date = %q", got)
	}
	if got := winAVState(0x11010); got != "enabled, definitions out of date" {
		t.Errorf("enabled stale = %q", got)
	}
	if got := winAVState(0x60100); got != "disabled, up to date" {
		t.Errorf("disabled = %q", got)
	}
	// The `antivirus` field is one line and the console shows nothing else:
	// the product actually protecting the machine leads, and every name says
	// whether it is running. SecurityCenter2's own order puts a switched-off
	// Defender first.
	got := winAntivirusSummary([]winAVProduct{
		{Name: "Windows Defender", State: 0x060100},
		{Name: " Bitdefender Antivirus ", State: 0x041000},
		{Name: "   "},
	})
	if want := "Bitdefender Antivirus (active); Windows Defender (disabled)"; got != want {
		t.Errorf("winAntivirusSummary = %q want %q", got, want)
	}
	if got := winAntivirusSummary(nil); got != "" {
		t.Errorf("no products = %q, want empty", got)
	}
	if winLicenseStatus(1) != "licensed" || winLicenseStatus(0) != "unlicensed" || !strings.HasPrefix(winLicenseStatus(42), "unknown") {
		t.Error("license status mapping wrong")
	}
	if winDomainRole(1) != "member workstation" || winDomainRole(5) != "primary domain controller" || winDomainRole(99) != "" {
		t.Error("domain role mapping wrong")
	}
}

func TestWinSplitWUAOutput(t *testing.T) {
	stdout := "PROGRESS Searching\r\nWARNING: a host warning\r\nPROGRESS Installing 2 update(s)\r\nRESULT {\"reboot_required\":true}\r\n"
	progress, other, result := winSplitWUAOutput(stdout)
	if !reflect.DeepEqual(progress, []string{"Searching", "Installing 2 update(s)"}) {
		t.Errorf("progress = %v", progress)
	}
	if result != `{"reboot_required":true}` {
		t.Errorf("result = %q", result)
	}
	if len(other) != 1 || !strings.Contains(other[0], "host warning") {
		t.Errorf("other = %v", other)
	}
}

func TestWinParseWUAScan(t *testing.T) {
	// "updates" is a single object (PowerShell collapses one-element arrays);
	// the parser must still yield one update.
	scan := `{"updates":{"id":"11111111-1111-1111-1111-111111111111","revision":200,"title":"2024-09 Cumulative Update","kb":["5043064"],"severity":"Important","categories":["Security Updates","Windows 11"],"size":734003200,"downloaded":false,"reboot_behavior":1,"description":"A security update.","mandatory":false},"reboot_pending":true,"error":"","error_hresult":""}`
	res, err := winParseWUAScan(scan)
	if err != nil {
		t.Fatal(err)
	}
	if !res.RebootPending || len(res.Updates) != 1 {
		t.Fatalf("scan header wrong: %+v", res)
	}
	u := res.Updates[0]
	if u.ID != "11111111-1111-1111-1111-111111111111" || u.KB != "KB5043064" || u.Severity != "Important" ||
		u.SizeBytes != 734003200 || !u.RebootReq || u.Source != "wua" || len(u.Categories) != 2 {
		t.Fatalf("update decoded wrong: %+v", u)
	}
	// an empty update array is a clean, empty scan
	if r, err := winParseWUAScan(`{"updates":[],"reboot_pending":false}`); err != nil || len(r.Updates) != 0 {
		t.Fatalf("empty scan: %+v %v", r, err)
	}
	// a WUA-level failure is carried in Error, not returned as a Go error
	if r, err := winParseWUAScan(`{"updates":[],"error":"search failed","error_hresult":"0x8024402C"}`); err != nil || !strings.Contains(r.Error, "0x8024402C") {
		t.Fatalf("error scan: %+v %v", r, err)
	}
	if _, err := winParseWUAScan("   "); err == nil {
		t.Error("empty RESULT should error")
	}
}

func TestWinParseWUAInstall(t *testing.T) {
	// result 2 = succeeded, 4 = failed with a known HRESULT (0x80240017,
	// which PowerShell emits as the signed int32 -2145124329).
	install := fmt.Sprintf(`{"results":[{"id":"aaaaaaaa-1111-1111-1111-111111111111","title":"X","result":2,"hresult":0,"reboot":false,"error":""},{"id":"bbbbbbbb-2222-2222-2222-222222222222","title":"Y","result":4,"hresult":%d,"reboot":false,"error":""}],"reboot_required":true,"error":""}`, -2145124329)
	res, err := winParseWUAInstall(install)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Installed) != 1 || res.Installed[0] != "aaaaaaaa-1111-1111-1111-111111111111" {
		t.Fatalf("installed wrong: %+v", res.Installed)
	}
	if !res.RebootReq {
		t.Error("reboot_required should propagate")
	}
	msg, ok := res.Failed["bbbbbbbb-2222-2222-2222-222222222222"]
	if !ok || !strings.Contains(msg, "failed") || !strings.Contains(msg, "0x80240017") || !strings.Contains(msg, "not applicable") {
		t.Fatalf("failure message wrong: %q", msg)
	}
	// a top-level error with no per-update results is a Go error
	if _, err := winParseWUAInstall(`{"results":[],"error":"none of the requested updates are applicable"}`); err == nil {
		t.Error("empty-with-error install should error")
	}
	if _, err := winParseWUAInstall(""); err == nil {
		t.Error("empty RESULT should error")
	}
}

func TestWinWUAResultText(t *testing.T) {
	if winWUAResultText(2, 0, "") != "succeeded" {
		t.Error("2 should be succeeded")
	}
	if got := winWUAResultText(3, 0, ""); got != "succeeded with errors" {
		t.Errorf("3 = %q", got)
	}
	if got := winWUAResultText(5, 0, "user aborted"); got != "aborted: user aborted" {
		t.Errorf("5 with detail = %q", got)
	}
	if got := winWUAResultText(4, 0x80070422, ""); !strings.Contains(got, "Windows Update service is disabled") {
		t.Errorf("known hresult = %q", got)
	}
}

func TestWinIsUpdateID(t *testing.T) {
	if !winIsUpdateID("11111111-2222-3333-4444-555555555555") {
		t.Error("valid GUID rejected")
	}
	for _, bad := range []string{"", "not-a-guid", "11111111-2222-3333-4444-55555555555", "winget:Git.Git", "11111111222233334444555555555555"} {
		if winIsUpdateID(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestWinParseWingetUpgrade(t *testing.T) {
	// Fixed-width columns so header offsets equal cell offsets, exactly as
	// winget aligns its own table.
	row := func(name, id, ver, avail, src string) string {
		return fmt.Sprintf("%-16s%-16s%-10s%-12s%s", name, id, ver, avail, src)
	}
	var b strings.Builder
	// leading spinner animation on its own lines (carriage returns)
	b.WriteString("  -\r  \\\r  |\rResolving\n")
	b.WriteString(row("Name", "Id", "Version", "Available", "Source") + "\n")
	b.WriteString(strings.Repeat("-", 60) + "\n")
	b.WriteString(row("Mozilla Firefox", "Mozilla.Firefox", "128.0", "129.0", "winget") + "\n")
	b.WriteString(row("Git", "Git.Git", "2.45.0", "2.46.0", "winget") + "\n")
	b.WriteString("\n2 upgrades available.\n")

	ups := winParseWingetUpgrade(b.String())
	if len(ups) != 2 {
		t.Fatalf("got %d upgrades: %+v", len(ups), ups)
	}
	if ups[0].ID != "winget:Mozilla.Firefox" || ups[0].Title != "Mozilla Firefox" || ups[0].Version != "129.0" || ups[0].Source != "winget" {
		t.Fatalf("firefox row wrong: %+v", ups[0])
	}
	if !strings.Contains(ups[0].Description, "installed 128.0") || !strings.Contains(ups[0].Description, "available 129.0") {
		t.Fatalf("description wrong: %q", ups[0].Description)
	}
	if ups[1].ID != "winget:Git.Git" || ups[1].Version != "2.46.0" {
		t.Fatalf("git row wrong: %+v", ups[1])
	}
	// no table at all yields nothing, not a panic
	if got := winParseWingetUpgrade("No installed package found matching input criteria.\n"); len(got) != 0 {
		t.Errorf("no-table = %v", got)
	}
}

func TestWinShutdownArgs(t *testing.T) {
	got := winShutdownArgs("reboot", 60, "Patch now")
	want := []string{"/r", "/f", "/t", "60", "/d", "p:0:0", "/c", "Patch now"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reboot args = %v", got)
	}
	got = winShutdownArgs("shutdown", -5, "")
	want = []string{"/s", "/f", "/t", "0", "/d", "p:0:0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shutdown args = %v", got)
	}
	// a control-laden message is flattened, not passed raw onto the command line
	got = winShutdownArgs("reboot", 0, "line1\r\nline2\ttab")
	if got[len(got)-2] != "/c" || got[len(got)-1] != "line1 line2 tab" {
		t.Fatalf("message not cleaned: %v", got)
	}
}

func TestWinCleanMessage(t *testing.T) {
	if got := winCleanMessage("a\r\nb\tc", 100); got != "a b c" {
		t.Errorf("clean = %q", got)
	}
	if got := winCleanMessage(strings.Repeat("x", 50), 10); len(got) != 10 {
		t.Errorf("truncate = %q (len %d)", got, len(got))
	}
}

func TestWinLineSplitter(t *testing.T) {
	var got []string
	var sink strings.Builder
	w := &winLineSplitter{sink: &sink, onLine: func(s string) { got = append(got, s) }}
	// lines arrive split across writes and with CRLF
	io.WriteString(w, "PROGRESS one\r\nPROG")
	io.WriteString(w, "RESS two\nRESULT {}")
	if want := []string{"PROGRESS one", "PROGRESS two"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("before flush got %v want %v", got, want)
	}
	w.flush()
	if len(got) != 3 || got[2] != "RESULT {}" {
		t.Fatalf("after flush got %v", got)
	}
	w.flush() // idempotent
	if len(got) != 3 {
		t.Fatalf("second flush emitted again: %v", got)
	}
	if sink.String() != "PROGRESS one\r\nPROGRESS two\nRESULT {}" {
		t.Fatalf("sink = %q", sink.String())
	}
	// an endless line is delivered in bounded pieces, not buffered for ever
	got = nil
	w = &winLineSplitter{onLine: func(s string) { got = append(got, s) }}
	w.Write(bytes.Repeat([]byte("x"), winMaxLine+10))
	if len(got) != 1 || len(got[0]) != winMaxLine+10 || w.buf != nil {
		t.Fatalf("long line: %d pieces, buffered %d", len(got), len(w.buf))
	}
	// the decode hook sees the raw bytes of each line
	got = nil
	w = &winLineSplitter{decode: func(b []byte) string { return strings.ToUpper(string(b)) }, onLine: func(s string) { got = append(got, s) }}
	io.WriteString(w, "abc\n")
	if !reflect.DeepEqual(got, []string{"ABC"}) {
		t.Fatalf("decode hook: %v", got)
	}
	// a nil callback and nil sink are fine
	w = &winLineSplitter{}
	if n, err := io.WriteString(w, "x\ny"); n != 3 || err != nil {
		t.Fatalf("bare splitter: %d %v", n, err)
	}
	w.flush()
}

func TestWinMarkUnreported(t *testing.T) {
	res := &protocol.UpdatesInstallResult{Installed: []string{"AAAAAAAA-1111-1111-1111-111111111111"}, Failed: map[string]string{"bbbbbbbb-2222-2222-2222-222222222222": "failed"}}
	winMarkUnreported(res, []string{"aaaaaaaa-1111-1111-1111-111111111111", "BBBBBBBB-2222-2222-2222-222222222222", "cccccccc-3333-3333-3333-333333333333", "cccccccc-3333-3333-3333-333333333333"})
	if len(res.Failed) != 2 {
		t.Fatalf("failed = %v", res.Failed)
	}
	if msg := res.Failed["cccccccc-3333-3333-3333-333333333333"]; !strings.Contains(msg, "not offered") {
		t.Fatalf("unreported id message = %q", msg)
	}
	if res.Failed["bbbbbbbb-2222-2222-2222-222222222222"] != "failed" {
		t.Fatal("existing failure overwritten")
	}
	// "install everything" has nothing to mark, and a nil map is created on demand
	res = &protocol.UpdatesInstallResult{}
	winMarkUnreported(res, nil)
	if res.Failed != nil {
		t.Fatal("nothing requested should change nothing")
	}
	winMarkUnreported(res, []string{"dddddddd-4444-4444-4444-444444444444"})
	if len(res.Failed) != 1 {
		t.Fatalf("nil map not created: %v", res.Failed)
	}
}

func TestWinParseWUAInstallErrorHResult(t *testing.T) {
	// a COM failure before any result carries its HRESULT into the error
	_, err := winParseWUAInstall(`{"results":[],"reboot_required":false,"error":"Exception calling \"Search\"","error_hresult":"0x8024402C"}`)
	if err == nil || !strings.Contains(err.Error(), "0x8024402C") {
		t.Fatalf("hresult missing from error: %v", err)
	}
	// with partial results the failure is a log line and the results survive
	res, err := winParseWUAInstall(`{"results":[{"id":"aaaaaaaa-1111-1111-1111-111111111111","title":"X","result":4,"hresult":0,"reboot":false,"error":"download failed"}],"error":"no updates could be downloaded","error_hresult":""}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Log, "no updates could be downloaded") || !strings.Contains(res.Failed["aaaaaaaa-1111-1111-1111-111111111111"], "download failed") {
		t.Fatalf("partial result lost: %+v", res)
	}
}

// TestWinWUAScriptShape checks the embedded PowerShell for the mistakes
// that cannot be caught without a Windows box: the RESULT/PROGRESS contract
// the Go side keys on, and appending to a fixed-size @() array, which
// throws "Collection was of a fixed size" at runtime.
func TestWinWUAScriptShape(t *testing.T) {
	fixed := regexp.MustCompile(`\$(\w+)\s*=\s*@\(\)`)
	for name, script := range map[string]string{"scan": wuaScanScript, "install": wuaInstallScript} {
		if !strings.Contains(script, `"RESULT " + ($out | ConvertTo-Json -Depth 6 -Compress)`) {
			t.Errorf("%s: RESULT line missing or reshaped", name)
		}
		for _, m := range fixed.FindAllStringSubmatch(script, -1) {
			if strings.Contains(script, "$"+m[1]+".Add(") {
				t.Errorf("%s: $%s is a fixed-size @() array but is .Add()ed to", name, m[1])
			}
		}
		for _, pair := range [][2]string{{"{", "}"}, {"(", ")"}, {"[", "]"}} {
			if a, b := strings.Count(script, pair[0]), strings.Count(script, pair[1]); a != b {
				t.Errorf("%s: %d %q vs %d %q", name, a, pair[0], b, pair[1])
			}
		}
		if strings.Contains(script, "ErrorActionPreference = 'Stop'") == false {
			t.Errorf("%s: COM errors must be terminating", name)
		}
	}
	// the Go side classifies these exact prefixes
	if kind, text := winWUALine("PROGRESS Installing 2 update(s)"); kind != wuaLineProgress || text != "Installing 2 update(s)" {
		t.Errorf("PROGRESS classification: %v %q", kind, text)
	}
	if !strings.Contains(wuaInstallScript, `Write-Output ("PROGRESS " + $m)`) {
		t.Error("install script's Progress helper does not emit the PROGRESS prefix")
	}
	// the install script's argument guard admits exactly what winIsUpdateID sends
	if !strings.Contains(wuaInstallScript, `-match '^[0-9A-Fa-f-]{36}$'`) {
		t.Error("install script's GUID guard changed; keep it in step with winIsUpdateID")
	}
}
