package agent

// Pure parsers for the text the Linux platform files get back from
// systemctl, journalctl, apt, dnf, pacman, zypper, dpkg, rpm and friends.
// Nothing here touches the OS, so the file builds and is tested everywhere;
// the *_linux.go files are the thin layer that runs the commands.

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- names that reach a command line ----

// unitNameRE is what a systemd unit may be called. Anything else is refused
// before it gets near exec, and a leading "-" is excluded so a name can never
// be read as an option (we also pass "--", belt and braces).
var unitNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9@._\-\\:]*$`)

func validUnitName(name string) bool {
	return len(name) > 0 && len(name) <= 256 && unitNameRE.MatchString(name)
}

// unitSuffixes are systemd's unit types; a name without one is a service.
var unitSuffixes = []string{".service", ".socket", ".target", ".device", ".mount", ".automount", ".swap", ".timer", ".path", ".slice", ".scope"}

func hasUnitSuffix(name string) bool {
	for _, s := range unitSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// journalMatchesFor builds journalctl match arguments that select entries
// from a unit OR from a syslog identifier / process of that name. "+"
// separates OR groups; terms inside a group are ANDed.
func journalMatchesFor(name string) []string {
	unit := name
	if !hasUnitSuffix(unit) {
		unit += ".service"
	}
	ident := strings.TrimSuffix(name, ".service")
	return []string{
		"_SYSTEMD_UNIT=" + unit,
		"+", "UNIT=" + unit, "_PID=1",
		"+", "SYSLOG_IDENTIFIER=" + ident,
		"+", "_COMM=" + ident,
	}
}

// pkgIDRE is the widest package name any supported manager produces
// (Debian: lowercase, "+", ".", "-"; RPM: mixed case, "_", "+"; Arch: same;
// arch qualifiers "name:amd64" / "name.x86_64"). A leading letter or digit
// keeps "-y" and friends out; a trailing "-", "/", "=" or ":" is refused
// because apt reads "pkg-" as "remove pkg" and "pkg/suite", "pkg=ver" as
// selectors. A trailing "+" stays legal: "g++" is a package, and install
// only ever passes ids that the scan itself produced.
var pkgIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:@-]*$`)

func validPkgID(id string) bool {
	if id == "" || len(id) > 256 || !pkgIDRE.MatchString(id) {
		return false
	}
	switch id[len(id)-1] {
	case '-', '/', '=', ':':
		return false
	}
	return true
}

// ---- os-release ----

// parseOSRelease reads KEY=VALUE lines with optional single/double quotes,
// as /etc/os-release is specified.
func parseOSRelease(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		v = strings.ReplaceAll(v, `\"`, `"`)
		out[strings.TrimSpace(k)] = v
	}
	return out
}

// ---- systemd ----

// unitRow is one line of "systemctl list-units --plain --no-legend".
type unitRow struct {
	Unit, Load, Active, Sub, Description string
}

// parseListUnits handles both the modern output (UNIT LOAD ACTIVE SUB
// DESCRIPTION) and the older one that prefixes a bullet column.
func parseListUnits(text string) []unitRow {
	var out []unitRow
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && (f[0] == "●" || f[0] == "*") {
			f = f[1:]
		}
		if len(f) < 4 || !strings.Contains(f[0], ".") {
			continue
		}
		r := unitRow{Unit: f[0], Load: f[1], Active: f[2], Sub: f[3]}
		if len(f) > 4 {
			r.Description = strings.Join(f[4:], " ")
		}
		out = append(out, r)
	}
	return out
}

// parseListUnitFiles maps unit -> unit file state from
// "systemctl list-unit-files --plain --no-legend" (2 or 3 columns depending
// on the systemd version; the third is the preset).
func parseListUnitFiles(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.Contains(f[0], ".") {
			continue
		}
		out[f[0]] = f[1]
	}
	return out
}

// parseShowBlocks splits "systemctl show" output for several units into one
// key=value map per unit; blocks are separated by blank lines.
func parseShowBlocks(text string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = map[string]string{}
		}
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		cur[k] = v
	}
	flush()
	return out
}

// unitState maps ActiveState/SubState onto the state vocabulary the UI
// shares with Windows services.
func unitState(active, sub string) string {
	switch active {
	case "active", "reloading", "refreshing":
		return "running"
	case "activating":
		return "start_pending"
	case "deactivating":
		return "stop_pending"
	case "inactive":
		return "stopped"
	case "failed":
		return "failed"
	case "":
		return "unknown"
	}
	_ = sub
	return active
}

// unitStartType maps a unit file state onto auto/manual/disabled. Static,
// indirect, generated and transient units have no [Install] section: they
// can be started by hand or by a dependency but never "enabled", which is
// exactly Windows' "manual".
func unitStartType(fileState string) string {
	switch fileState {
	case "enabled", "enabled-runtime", "alias":
		return "auto"
	case "disabled", "masked", "masked-runtime":
		return "disabled"
	case "static", "indirect", "generated", "transient", "linked", "linked-runtime", "bad":
		return "manual"
	case "":
		return "manual"
	}
	return "manual"
}

// isActiveState maps "systemctl is-active" stdout.
func isActiveState(s string) string {
	switch strings.TrimSpace(s) {
	case "active", "reloading", "refreshing":
		return "running"
	case "inactive":
		return "stopped"
	case "failed":
		return "failed"
	case "activating":
		return "start_pending"
	case "deactivating":
		return "stop_pending"
	}
	return "unknown"
}

// serviceFromShow builds a Service from one "systemctl show" block.
func serviceFromShow(b map[string]string) protocol.Service {
	s := protocol.Service{
		Name:        b["Id"],
		DisplayName: b["Description"],
		State:       unitState(b["ActiveState"], b["SubState"]),
		StartType:   unitStartType(b["UnitFileState"]),
		Description: b["Description"],
	}
	if b["LoadState"] == "masked" {
		s.StartType = "disabled"
	}
	if pid, err := strconv.Atoi(b["MainPID"]); err == nil && pid > 0 {
		s.PID = pid
	}
	if s.DisplayName == "" {
		s.DisplayName = s.Name
	}
	return s
}

// parseLoginctlSessions returns the session ids from
// "loginctl list-sessions --no-legend" (SESSION UID USER SEAT TTY ...).
func parseLoginctlSessions(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] != "" {
			out = append(out, f[0])
		}
	}
	return out
}

// parseLoginctlUsers pulls the USER column out of list-sessions output.
func parseLoginctlUsers(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[2] != "" && f[2] != "-" {
			out = append(out, f[2])
		}
	}
	return out
}

// ---- journal ----

// journalLevel maps a syslog priority (0 emerg .. 7 debug) onto
// error/warning/info.
func journalLevel(priority string) string {
	p, err := strconv.Atoi(strings.TrimSpace(priority))
	if err != nil {
		return "info"
	}
	switch {
	case p <= 3:
		return "error"
	case p == 4:
		return "warning"
	}
	return "info"
}

// journalString decodes a journal JSON field. journalctl emits a string for
// text, an array of byte values for non-UTF-8 payloads, an array of strings
// when a field occurs more than once, and null when the field is too large.
func journalString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var bytesArr []int
	if json.Unmarshal(raw, &bytesArr) == nil {
		b := make([]byte, 0, len(bytesArr))
		for _, v := range bytesArr {
			if v >= 0 && v < 256 {
				b = append(b, byte(v))
			}
		}
		return strings.ToValidUTF8(string(b), "�")
	}
	var many []json.RawMessage
	if json.Unmarshal(raw, &many) == nil {
		parts := make([]string, 0, len(many))
		for _, m := range many {
			if s := journalString(m); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// parseJournalJSON turns "journalctl -o json" NDJSON into entries. Lines
// that are not objects are skipped: a truncated last line must not lose the
// whole result.
func parseJournalJSON(text string) []protocol.EventLogEntry {
	var out []protocol.EventLogEntry
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var rec map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		e := protocol.EventLogEntry{Level: journalLevel(journalString(rec["PRIORITY"]))}
		if us, err := strconv.ParseInt(journalString(rec["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
			e.TS = us / 1_000_000
		}
		e.Source = journalString(rec["SYSLOG_IDENTIFIER"])
		if e.Source == "" {
			e.Source = journalString(rec["_COMM"])
		}
		if e.Source == "" {
			if t := journalString(rec["_TRANSPORT"]); t == "kernel" {
				e.Source = "kernel"
			} else if u := journalString(rec["_SYSTEMD_UNIT"]); u != "" {
				e.Source = u
			}
		}
		e.Message = journalString(rec["MESSAGE"])
		if pid := journalString(rec["_PID"]); pid != "" {
			// The pid is not an event id, but it is the closest thing the
			// journal has to one and it helps correlate with the process list.
			if n, err := strconv.Atoi(pid); err == nil {
				e.EventID = n
			}
		}
		out = append(out, e)
	}
	return out
}

// syslogLineRE covers the classic "Sep 15 03:56:01 host prog[pid]: msg" and
// the RFC 3339 "2026-09-15T03:56:01.123456+00:00 host prog[pid]: msg" forms.
var syslogLineRE = regexp.MustCompile(`^(?:([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})|(\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)) +(\S+) +([^:\[\]]+?)(?:\[(\d+)\])?: ?(.*)$`)

var (
	syslogErrRE  = regexp.MustCompile(`(?i)\b(error|err|fail(ed|ure)?|crit(ical)?|fatal|panic|emerg|alert|segfault|oops)\b`)
	syslogWarnRE = regexp.MustCompile(`(?i)\b(warn(ing)?|deprecated|refused|denied|timeout|timed out)\b`)
)

// parseSyslogLines converts a slice of raw syslog lines (any order) into
// entries sorted newest first. The plain-text syslog carries no priority, so
// the level is inferred from the message text; that is a fallback for hosts
// without journald and it is labelled as such in the source field.
func parseSyslogLines(lines []string, now time.Time) []protocol.EventLogEntry {
	var out []protocol.EventLogEntry
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		m := syslogLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var ts time.Time
		if m[1] != "" {
			// The classic format has no year: assume the current one, and if
			// that lands in the future (log written in December, read in
			// January) step back a year.
			if t, err := time.ParseInLocation("Jan _2 15:04:05", m[1], time.Local); err == nil {
				ts = t.AddDate(now.Year(), 0, 0)
				if ts.After(now.Add(24 * time.Hour)) {
					ts = ts.AddDate(-1, 0, 0)
				}
			}
		} else if t, err := time.Parse(time.RFC3339Nano, m[2]); err == nil {
			ts = t
		} else if t, err := time.Parse("2006-01-02T15:04:05.999999-0700", m[2]); err == nil {
			ts = t
		}
		e := protocol.EventLogEntry{TS: ts.Unix(), Source: strings.TrimSpace(m[4]), Message: m[6], Level: "info"}
		if ts.IsZero() {
			e.TS = 0
		}
		if n, err := strconv.Atoi(m[5]); err == nil {
			e.EventID = n
		}
		switch {
		case syslogErrRE.MatchString(e.Message):
			e.Level = "error"
		case syslogWarnRE.MatchString(e.Message):
			e.Level = "warning"
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS > out[j].TS })
	return out
}

// logLevelAllowed applies an EventLogQuery.Level filter to an entry level.
func logLevelAllowed(filter, level string) bool {
	switch strings.ToLower(filter) {
	case "error", "critical":
		return level == "error"
	case "warning", "warn":
		return level == "error" || level == "warning"
	}
	return true
}

// ---- apt ----

// aptInstRE matches "apt-get -s dist-upgrade" lines:
//
//	Inst coreutils [9.4-3ubuntu6.1] (9.4-3ubuntu6.2 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
//	Inst newpkg (1.0 Debian:12/bookworm [amd64])
var aptInstRE = regexp.MustCompile(`^Inst (\S+)(?: \[([^\]]*)\])? \(([^\s)]+) ([^)]*)\)`)

// parseAptSimulate reads the simulated dist-upgrade and returns one Update
// per "Inst" line (Conf/Remv lines are the same packages or removals).
func parseAptSimulate(text string) []protocol.Update {
	var out []protocol.Update
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		m := aptInstRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		origins := m[4]
		if i := strings.Index(origins, " ["); i >= 0 {
			origins = origins[:i]
		}
		out = append(out, aptUpdate(m[1], m[2], m[3], origins))
	}
	return out
}

// aptListRE matches "apt list --upgradable" lines:
//
//	coreutils/noble-updates 9.4-3ubuntu6.2 amd64 [upgradable from: 9.4-3ubuntu6.1]
var aptListRE = regexp.MustCompile(`^(\S+?)/(\S+) (\S+) (\S+)(?: \[upgradable from: ([^\]]*)\])?`)

func parseAptListUpgradable(text string) []protocol.Update {
	var out []protocol.Update
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		m := aptListRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, aptUpdate(m[1], m[5], m[3], m[2]))
	}
	return out
}

func aptUpdate(name, oldVer, newVer, origins string) protocol.Update {
	u := protocol.Update{ID: name, Version: newVer, Source: "apt", Title: name + " → " + newVer}
	if oldVer != "" {
		u.Title = name + " " + oldVer + " → " + newVer
	}
	if strings.Contains(strings.ToLower(origins), "security") {
		u.Severity = "security"
		u.Categories = []string{"Security"}
	}
	if origins != "" {
		u.Description = "from " + origins
	}
	return u
}

// ---- dnf / yum ----

// parseDnfCheckUpdate reads "dnf -q check-update" output:
//
//	name.arch    version-release    repo
//
// Long names wrap onto two lines (name alone, then version and repo
// indented). Parsing stops at the "Obsoleting Packages" section, which
// lists replacements, not upgrades.
func parseDnfCheckUpdate(text string) []protocol.Update {
	var out []protocol.Update
	seen := map[string]bool{}
	pending := ""
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			pending = ""
			continue
		}
		if strings.HasPrefix(trimmed, "Obsoleting") || strings.HasPrefix(trimmed, "Security:") || strings.HasPrefix(trimmed, "Last metadata") {
			if strings.HasPrefix(trimmed, "Obsoleting") {
				break
			}
			continue
		}
		f := strings.Fields(trimmed)
		switch {
		case len(f) == 1 && strings.Contains(f[0], "."):
			pending = f[0]
			continue
		case len(f) >= 2 && pending != "" && strings.HasPrefix(line, " "):
			f = append([]string{pending}, f...)
			pending = ""
		case len(f) < 3 || !strings.Contains(f[0], "."):
			pending = ""
			continue
		}
		name, ver, repo := f[0], f[1], f[2]
		if seen[name] {
			continue
		}
		seen[name] = true
		u := protocol.Update{ID: name, Version: ver, Source: "dnf", Title: name + " → " + ver, Description: "from " + repo}
		if strings.Contains(strings.ToLower(repo), "security") {
			u.Severity = "security"
			u.Categories = []string{"Security"}
		}
		out = append(out, u)
	}
	return out
}

// parseDnfSecurity reads "dnf -q updateinfo list --security":
//
//	FEDORA-2024-abc123 Important/Sec. openssl-3.2.1-2.fc40.x86_64
//
// and returns package name -> advisory severity.
func parseDnfSecurity(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.Contains(f[2], "-") {
			continue
		}
		name, arch := rpmNameFromNEVRA(f[2])
		sev := strings.TrimSuffix(strings.TrimSuffix(f[1], "/Sec."), "/Sec")
		if sev == "" || sev == f[1] {
			sev = "security"
		}
		out[name] = sev
		if arch != "" {
			out[name+"."+arch] = sev
		}
	}
	return out
}

// rpmSplitArch splits the "name.arch" form dnf check-update prints; names
// may contain dots ("python3.12"), the arch never does.
func rpmSplitArch(id string) (name, arch string) {
	if i := strings.LastIndex(id, "."); i > 0 && i < len(id)-1 {
		return id[:i], id[i+1:]
	}
	return id, ""
}

// rpmNameFromNEVRA splits "name-version-release.arch" (an epoch may sit in
// the version as "1:2.0") into name and arch. RPM names may contain dashes,
// so the split is at the second-last dash, where the version starts with a
// digit or an epoch.
func rpmNameFromNEVRA(s string) (name, arch string) {
	if i := strings.LastIndex(s, "."); i > 0 {
		arch = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, "-")
	if len(parts) < 3 {
		return s, arch
	}
	return strings.Join(parts[:len(parts)-2], "-"), arch
}

// ---- pacman ----

// parsePacmanQu reads "pacman -Qu" lines: "name old -> new" with an optional
// " [ignored]" suffix (IgnorePkg entries are listed but not installed).
func parsePacmanQu(text string) []protocol.Update {
	var out []protocol.Update
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[2] != "->" {
			continue
		}
		u := protocol.Update{ID: f[0], Version: f[3], Source: "pacman", Title: f[0] + " " + f[1] + " → " + f[3]}
		if len(f) > 4 && strings.Contains(strings.Join(f[4:], " "), "ignored") {
			u.Description = "ignored by pacman.conf"
		}
		out = append(out, u)
	}
	return out
}

// parsePacmanQ reads "pacman -Q" ("name version") into software entries.
func parsePacmanQ(text string) []protocol.Software {
	var out []protocol.Software
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			out = append(out, protocol.Software{Name: f[0], Version: f[1]})
		}
	}
	return out
}

// archKernelUpToDate compares the running kernel with the installed package
// version: uname says "6.10.3-arch1-1", pacman -Q says "linux 6.10.3.arch1-1".
// ok is false when the comparison is not possible.
func archKernelUpToDate(unameR, pacmanQ string) (upToDate, ok bool) {
	f := strings.Fields(pacmanQ)
	if len(f) < 2 || strings.TrimSpace(unameR) == "" {
		return false, false
	}
	norm := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r == '-' || r == '.' || r == '_' {
				return '.'
			}
			return r
		}, strings.TrimSpace(s))
	}
	return norm(unameR) == norm(f[1]), true
}

// archKernelPackage picks the pacman package that owns the running kernel
// from the uname flavour suffix.
func archKernelPackage(unameR string) string {
	for _, flavour := range []string{"lts", "zen", "hardened", "rt-lts", "rt"} {
		if strings.Contains(unameR, "-"+flavour) || strings.Contains(unameR, "."+flavour) {
			return "linux-" + flavour
		}
	}
	return "linux"
}

// ---- zypper ----

// parseZypperLu reads the "zypper -n lu" table:
//
//	S | Repository | Name | Current Version | Available Version | Arch
//	--+------------+------+-----------------+-------------------+-----
//	v | Main Update Repo | curl | 8.0.1-1.1 | 8.0.1-2.1 | x86_64
func parseZypperLu(text string) []protocol.Update {
	var out []protocol.Update
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "|") || strings.HasPrefix(strings.TrimSpace(line), "S ") {
			continue
		}
		cols := strings.Split(line, "|")
		for i := range cols {
			cols[i] = strings.TrimSpace(cols[i])
		}
		if len(cols) < 6 || cols[2] == "" || cols[2] == "Name" || strings.HasPrefix(cols[0], "--") {
			continue
		}
		name := cols[2]
		if seen[name] {
			continue
		}
		seen[name] = true
		u := protocol.Update{ID: name, Version: cols[4], Source: "zypper", Title: name + " " + cols[3] + " → " + cols[4], Description: "from " + cols[1]}
		if strings.Contains(strings.ToLower(cols[1]), "security") {
			u.Severity = "security"
			u.Categories = []string{"Security"}
		}
		out = append(out, u)
	}
	return out
}

// ---- installed software ----

// parseTabbedSoftware reads "name\tversion\tpublisher[\tstatus]" lines, the
// format both dpkg-query -f and rpm --qf are asked to print. A Debian
// maintainer "Name <email>" keeps only the name. The optional fourth column
// is dpkg's ${db:Status-Status}: anything but "installed" (config-files,
// half-installed, ...) is a package that is not actually on the system and
// is dropped; an empty column (older dpkg, rpm) keeps the row.
func parseTabbedSoftware(text string) []protocol.Software {
	var out []protocol.Software
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		if len(f) > 3 {
			if st := strings.TrimSpace(f[3]); st != "" && st != "installed" {
				continue
			}
		}
		s := protocol.Software{Name: f[0], Version: f[1]}
		if len(f) > 2 {
			pub := f[2]
			if i := strings.Index(pub, " <"); i > 0 {
				pub = pub[:i]
			}
			if pub != "(none)" && pub != "None" {
				s.Publisher = strings.TrimSpace(pub)
			}
		}
		out = append(out, s)
	}
	return out
}

// parseSnapList reads "snap list" (Name Version Rev Tracking Publisher Notes).
func parseSnapList(text string) []protocol.Software {
	var out []protocol.Software
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || (i == 0 && f[0] == "Name") {
			continue
		}
		s := protocol.Software{Name: f[0], Version: f[1]}
		if len(f) >= 5 {
			s.Publisher = strings.TrimSuffix(strings.TrimSuffix(f[4], "✓"), "**")
		}
		out = append(out, s)
	}
	return out
}

// parseFlatpakList reads "flatpak list --columns=application,version"
// (tab separated, no header).
func parseFlatpakList(text string) []protocol.Software {
	var out []protocol.Software
	for _, line := range strings.Split(text, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) == 0 || strings.TrimSpace(f[0]) == "" || f[0] == "Application ID" {
			continue
		}
		s := protocol.Software{Name: strings.TrimSpace(f[0]), Publisher: "flatpak"}
		if len(f) > 1 {
			s.Version = strings.TrimSpace(f[1])
		}
		out = append(out, s)
	}
	return out
}

// ---- hardware ----

// parseLspci keeps the display adapters out of "lspci" output.
func parseLspci(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if !strings.Contains(l, "VGA compatible controller") && !strings.Contains(l, "3D controller") && !strings.Contains(l, "Display controller") {
			continue
		}
		// "00:02.0 VGA compatible controller: Intel Corporation ... (rev 0c)"
		if i := strings.Index(l, "controller: "); i >= 0 {
			l = l[i+len("controller: "):]
		}
		if i := strings.LastIndex(l, " (rev "); i > 0 {
			l = l[:i]
		}
		out = append(out, strings.TrimSpace(l))
	}
	return uniqNonEmpty(out)
}

// pciVendorName resolves the handful of vendor ids that make GPUs, for the
// /sys/class/drm fallback when lspci is not installed.
func pciVendorName(id string) string {
	id = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(id), "0x"))
	switch id {
	case "10de":
		return "NVIDIA"
	case "1002":
		return "AMD/ATI"
	case "8086":
		return "Intel"
	case "15ad":
		return "VMware"
	case "1234":
		return "QEMU/Bochs"
	case "1af4", "1b36":
		return "Red Hat (virtio)"
	case "80ee":
		return "VirtualBox"
	case "1a03":
		return "ASPEED"
	case "102b":
		return "Matrox"
	case "5333":
		return "S3"
	case "1414":
		return "Microsoft Hyper-V"
	case "1ed5":
		return "Moore Threads"
	}
	return ""
}

// dmiClean drops the placeholder strings vendors leave in DMI fields so the
// UI shows blank instead of "To Be Filled By O.E.M.".
func dmiClean(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "to be filled by o.e.m.", "to be filled by o.e.m", "system product name", "system manufacturer",
		"system version", "system serial number", "default string", "none", "not specified", "not applicable",
		"n/a", "unknown", "undefined", "empty", "0", "00000000", "chassis manufacturer", "chassis version",
		"chassis serial number", "base board serial number", "oem", "o.e.m.":
		return ""
	}
	return s
}

// parseResolvConfDomain returns the first "domain" or "search" entry.
func parseResolvConfDomain(text string) string {
	search := ""
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch f[0] {
		case "domain":
			return strings.TrimSuffix(f[1], ".")
		case "search":
			if search == "" {
				search = strings.TrimSuffix(f[1], ".")
			}
		}
	}
	return search
}

// parseLastUser picks the most recent human login out of "last -w" output,
// skipping the pseudo entries for reboots and shutdowns.
func parseLastUser(text string) string {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "reboot", "shutdown", "runlevel", "wtmp", "btmp":
			continue
		}
		return f[0]
	}
	return ""
}

func uniqNonEmpty(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
