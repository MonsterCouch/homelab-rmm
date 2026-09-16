package agent

// winparse.go holds the Windows helpers that need no Windows API: string
// shaping, output parsers and code-to-name mappings. Keeping them free of a
// build constraint means they are unit-tested on every platform, including
// the Linux box that cross-compiles the Windows agent, instead of only
// type-checked. Every identifier is prefixed win/wua/wevt so the file cannot
// collide with the Linux platform files that share this package.

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- generic text helpers ----

// winFirstLine returns the first non-blank line of the first non-blank
// candidate, trimmed: the one line of a tool's stderr worth putting in an
// error message.
func winFirstLine(candidates ...string) string {
	for _, c := range candidates {
		for _, line := range strings.Split(c, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				return line
			}
		}
	}
	return ""
}

// winCleanMessage makes operator-supplied text safe for a command line and a
// dialog box: control characters become spaces and the result is capped at
// max runes (shutdown.exe refuses /c comments over 512 characters).
func winCleanMessage(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

// winMaxLine bounds how much of a line without a newline winLineSplitter
// holds before delivering it in pieces; a script that prints a megabyte
// without a line break must not grow the agent's heap without limit.
const winMaxLine = 1 << 20

// winLineSplitter is an io.Writer that mirrors every byte into sink (the
// full capture) and hands each complete line, CR/LF stripped and decoded,
// to onLine. It lets a long-running child's stdout stay exec's own pipe
// (which exec's WaitDelay can close) while still being watched live.
type winLineSplitter struct {
	sink   io.Writer
	decode func([]byte) string // nil = plain string conversion
	onLine func(string)
	buf    []byte
}

func (w *winLineSplitter) Write(p []byte) (int, error) {
	if w.sink != nil {
		w.sink.Write(p)
	}
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.emit(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) >= winMaxLine {
		w.emit(w.buf)
		w.buf = nil
	}
	if len(w.buf) == 0 {
		w.buf = nil // release the backing array between lines
	}
	return len(p), nil
}

func (w *winLineSplitter) emit(line []byte) {
	line = bytes.TrimRight(line, "\r")
	var s string
	if w.decode != nil {
		s = w.decode(line)
	} else {
		s = string(line)
	}
	if w.onLine != nil {
		w.onLine(s)
	}
}

// flush delivers a trailing line that had no newline; call it once the
// child has exited.
func (w *winLineSplitter) flush() {
	if len(w.buf) > 0 {
		w.emit(w.buf)
		w.buf = nil
	}
}

// ---- OS label ----

// winLabel composes "Windows 11 Pro 23H2 (build 22631.4037)" from the
// CurrentVersion registry values. fallback is gopsutil's platform string for
// when the registry is unreadable.
func winLabel(product, displayVersion, build, ubr, fallback string) string {
	product = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(product), "Microsoft "))
	if product == "" {
		product = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(fallback), "Microsoft "))
	}
	if product == "" {
		product = "Windows"
	}
	// ProductName still says "Windows 10 ..." on Windows 11; the build number
	// is the only reliable tell.
	if n, err := strconv.Atoi(strings.TrimSpace(build)); err == nil && n >= 22000 && strings.Contains(product, "Windows 10") {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	var b strings.Builder
	b.WriteString(product)
	if displayVersion = strings.TrimSpace(displayVersion); displayVersion != "" {
		b.WriteString(" " + displayVersion)
	}
	if build = strings.TrimSpace(build); build != "" {
		b.WriteString(" (build " + build)
		if ubr = strings.TrimSpace(ubr); ubr != "" {
			b.WriteString("." + ubr)
		}
		b.WriteString(")")
	}
	return b.String()
}

// ---- users and sessions ----

// winCleanUser normalises LogonUI's LastLoggedOnUser: ".\bob" is a local
// account, "CORP\bob" a domain one, and both may carry stray whitespace.
func winCleanUser(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, `.\`)
	return s
}

// winSessionUser formats a WTS session's user: local accounts (domain equals
// the computer name) show as "bob", domain accounts as "CORP\bob".
func winSessionUser(domain, user, hostname string) string {
	user = strings.TrimSpace(user)
	domain = strings.TrimSpace(domain)
	if user == "" {
		return ""
	}
	if domain == "" || strings.EqualFold(domain, hostname) {
		return user
	}
	return domain + `\` + user
}

// winParseQueryUser extracts the users of Active sessions from "query user"
// output, the fallback for when the WTS API path fails. Columns are
// whitespace separated and the SESSIONNAME column is blank for disconnected
// sessions, so the state is found relative to the numeric ID column.
func winParseQueryUser(out string) []string {
	var users []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		t = strings.TrimSpace(strings.TrimPrefix(t, ">")) // ">" marks the caller's own session
		f := strings.Fields(t)
		if len(f) < 3 || strings.EqualFold(f[0], "USERNAME") {
			continue
		}
		state := ""
		if _, err := strconv.Atoi(f[1]); err == nil {
			state = f[2]
		} else if len(f) >= 4 {
			if _, err := strconv.Atoi(f[2]); err == nil {
				state = f[3]
			}
		}
		if !strings.EqualFold(state, "Active") {
			continue
		}
		key := strings.ToLower(f[0])
		if !seen[key] {
			seen[key] = true
			users = append(users, f[0])
		}
	}
	return users
}

// winDomainRole names Win32_ComputerSystem.DomainRole.
func winDomainRole(role uint16) string {
	switch role {
	case 0:
		return "standalone workstation"
	case 1:
		return "member workstation"
	case 2:
		return "standalone server"
	case 3:
		return "member server"
	case 4:
		return "backup domain controller"
	case 5:
		return "primary domain controller"
	}
	return ""
}

// winAVState decodes SecurityCenter2's productState bit field. The middle
// byte says whether real-time protection is on (0x10/0x11) and the low byte
// whether definitions are current (0x00) or stale (0x10).
func winAVState(state uint32) string {
	enabled := (state>>8)&0xff == 0x10 || (state>>8)&0xff == 0x11
	stale := state&0xff == 0x10
	s := "disabled"
	if enabled {
		s = "enabled"
	}
	if stale {
		s += ", definitions out of date"
	} else {
		s += ", up to date"
	}
	return s
}

// winLicenseStatus names SoftwareLicensingProduct.LicenseStatus.
func winLicenseStatus(status uint32) string {
	switch status {
	case 0:
		return "unlicensed"
	case 1:
		return "licensed"
	case 2:
		return "initial grace period"
	case 3:
		return "additional grace period"
	case 4:
		return "non-genuine grace period"
	case 5:
		return "notification"
	case 6:
		return "extended grace period"
	}
	return "unknown (" + strconv.FormatUint(uint64(status), 10) + ")"
}

// ---- installed software ----

// winUninstallEntry is what one Uninstall registry subkey says about itself.
type winUninstallEntry struct {
	Name, Version, Publisher, InstallDate string
	ReleaseType, ParentKeyName            string
	SystemComponent                       uint64
}

// winSoftwareFromUninstall turns a registry entry into a Software row, or
// reports false for the entries an operator does not want to see: system
// components, hotfixes and patches of another product, and nameless keys.
func winSoftwareFromUninstall(e winUninstallEntry) (protocol.Software, bool) {
	name := strings.TrimSpace(e.Name)
	if name == "" || e.SystemComponent == 1 || strings.TrimSpace(e.ParentKeyName) != "" {
		return protocol.Software{}, false
	}
	switch strings.ToLower(strings.TrimSpace(e.ReleaseType)) {
	case "update", "hotfix", "security update", "update rollup", "service pack":
		return protocol.Software{}, false
	}
	lower := strings.ToLower(name)
	for _, p := range []string{"kb", "update for ", "security update for ", "hotfix for "} {
		if strings.HasPrefix(lower, p) && (p != "kb" || winLooksLikeKB(name)) {
			return protocol.Software{}, false
		}
	}
	return protocol.Software{
		Name:      name,
		Version:   strings.TrimSpace(e.Version),
		Publisher: strings.TrimSpace(e.Publisher),
		Installed: winInstallDate(e.InstallDate),
	}, true
}

// winLooksLikeKB reports "KB1234567" style names.
func winLooksLikeKB(name string) bool {
	if len(name) < 3 || !strings.EqualFold(name[:2], "KB") {
		return false
	}
	_, err := strconv.Atoi(strings.Fields(name[2:])[0])
	return err == nil
}

// winInstallDate turns the registry's "20240115" into "2024-01-15"; other
// shapes are passed through trimmed because some installers write free text.
func winInstallDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 8 {
		if _, err := strconv.Atoi(s); err == nil {
			return s[:4] + "-" + s[4:6] + "-" + s[6:]
		}
	}
	return s
}

// winCIMDate turns a CIM_DATETIME ("20230512000000.000000+000") into
// "2023-05-12"; anything malformed yields "".
func winCIMDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 8 {
		return ""
	}
	if _, err := strconv.Atoi(s[:8]); err != nil {
		return ""
	}
	return s[:4] + "-" + s[4:6] + "-" + s[6:8]
}

// winDedupeSoftware drops repeated name+version pairs (the same product is
// often registered under both the 64-bit and WOW6432Node hives) while
// keeping whichever copy carried a publisher or a date.
func winDedupeSoftware(list []protocol.Software) []protocol.Software {
	out := make([]protocol.Software, 0, len(list))
	idx := map[string]int{}
	for _, s := range list {
		s.Name = strings.TrimSpace(s.Name)
		if s.Name == "" {
			continue
		}
		key := strings.ToLower(s.Name) + "\x00" + strings.ToLower(strings.TrimSpace(s.Version))
		if i, ok := idx[key]; ok {
			if out[i].Publisher == "" {
				out[i].Publisher = s.Publisher
			}
			if out[i].Installed == "" {
				out[i].Installed = s.Installed
			}
			continue
		}
		idx[key] = len(out)
		out = append(out, s)
	}
	return out
}

// winPendingRenames reports whether PendingFileRenameOperations holds any
// real entry; the value is a REG_MULTI_SZ of source/destination pairs and
// is frequently present but empty.
func winPendingRenames(vals []string) bool {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// ---- services ----

// winServiceStateName maps SERVICE_STATUS.dwCurrentState to the wire
// vocabulary. The numbers are the SCM constants (SERVICE_STOPPED = 1 ...).
func winServiceStateName(state uint32) string {
	switch state {
	case 1:
		return "stopped"
	case 2:
		return "start_pending"
	case 3:
		return "stop_pending"
	case 4:
		return "running"
	case 5:
		return "continue_pending"
	case 6:
		return "pause_pending"
	case 7:
		return "paused"
	}
	return "unknown"
}

// winServiceStartTypeName maps QUERY_SERVICE_CONFIG.dwStartType
// (SERVICE_BOOT_START = 0 ... SERVICE_DISABLED = 4) plus the delayed
// auto-start flag to the wire vocabulary.
func winServiceStartTypeName(startType uint32, delayed bool) string {
	switch startType {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		if delayed {
			return "auto_delayed"
		}
		return "auto"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	}
	return "unknown"
}

// winCleanServiceDescription blanks unresolved MUI references
// ("@%SystemRoot%\system32\foo.dll,-101") which are noise, not a description.
func winCleanServiceDescription(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "@") && strings.Contains(s, ",-") {
		return ""
	}
	return s
}

// ---- event log ----

var winEventLogNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _\-/]*$`)

// winValidEventLogName guards the channel name that goes on the wevtutil
// command line: only characters real channel names use, and never a
// leading "/" or "-", so a crafted name cannot read as an option even
// though it is passed as its own argument.
func winValidEventLogName(name string) bool {
	return name != "" && len(name) <= 200 && winEventLogNameRE.MatchString(name)
}

// winEventLogXPath builds the wevtutil /q: filter. Level 1 is Critical,
// 2 Error, 3 Warning; "info" and "all" impose no level filter. since is a
// Unix time in seconds (milliseconds are tolerated).
func winEventLogXPath(level string, since int64) string {
	var conds []string
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		conds = append(conds, "(Level=1)")
	case "error":
		conds = append(conds, "(Level=1 or Level=2)")
	case "warning", "warn":
		conds = append(conds, "(Level=1 or Level=2 or Level=3)")
	}
	if since > 0 {
		if since > 1e12 { // milliseconds
			since /= 1000
		}
		conds = append(conds, "TimeCreated[@SystemTime>='"+time.Unix(since, 0).UTC().Format("2006-01-02T15:04:05.000Z")+"']")
	}
	if len(conds) == 0 {
		return ""
	}
	return "*[System[" + strings.Join(conds, " and ") + "]]"
}

// winEventLevelName maps the numeric Level of an event record.
func winEventLevelName(level int) string {
	switch level {
	case 1:
		return "critical"
	case 2:
		return "error"
	case 3:
		return "warning"
	case 4, 0:
		return "info"
	case 5:
		return "verbose"
	}
	return "info"
}

// wevtEvent mirrors the parts of one <Event> in wevtutil's RenderedXml
// output that the UI shows. Numeric fields are read as strings because an
// empty element would otherwise fail the whole decode.
type wevtEvent struct {
	System struct {
		Provider struct {
			Name            string `xml:"Name,attr"`
			EventSourceName string `xml:"EventSourceName,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channel string `xml:"Channel"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner string `xml:",innerxml"`
	} `xml:"UserData"`
	RenderingInfo struct {
		Message string `xml:"Message"`
	} `xml:"RenderingInfo"`
}

const wevtMaxMessage = 8000

// winParseWevtutilXML decodes the concatenated <Event> elements wevtutil
// prints (there is no document root) into wire entries. Decoding is per
// event and lenient, so one malformed record costs one entry, not the
// whole page.
func winParseWevtutilXML(data []byte) ([]protocol.EventLogEntry, error) {
	entries := []protocol.EventLogEntry{}
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var lastErr error
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			lastErr = err
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var ev wevtEvent
		if err := d.DecodeElement(&ev, &se); err != nil {
			lastErr = err
			continue
		}
		entries = append(entries, wevtToEntry(ev))
	}
	if len(entries) == 0 && lastErr != nil {
		return entries, fmt.Errorf("parse wevtutil output: %w", lastErr)
	}
	return entries, nil
}

func wevtToEntry(ev wevtEvent) protocol.EventLogEntry {
	e := protocol.EventLogEntry{}
	if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(ev.System.TimeCreated.SystemTime)); err == nil {
		e.TS = t.Unix()
	}
	lvl, _ := strconv.Atoi(strings.TrimSpace(ev.System.Level))
	e.Level = winEventLevelName(lvl)
	e.Source = strings.TrimSpace(ev.System.Provider.Name)
	if e.Source == "" {
		e.Source = strings.TrimSpace(ev.System.Provider.EventSourceName)
	}
	if e.Source == "" {
		e.Source = strings.TrimSpace(ev.System.Channel)
	}
	e.EventID, _ = strconv.Atoi(strings.TrimSpace(ev.System.EventID))
	msg := strings.TrimSpace(ev.RenderingInfo.Message)
	if msg == "" {
		// No message template was resolvable (provider not registered on this
		// box): show the raw parameters instead of nothing.
		var parts []string
		for _, dp := range ev.EventData.Data {
			v := strings.TrimSpace(dp.Value)
			if v == "" {
				continue
			}
			if dp.Name != "" {
				v = dp.Name + "=" + v
			}
			parts = append(parts, v)
		}
		msg = strings.Join(parts, " | ")
	}
	if msg == "" && strings.TrimSpace(ev.UserData.Inner) != "" {
		msg = winXMLText(ev.UserData.Inner)
	}
	msg = strings.ReplaceAll(msg, "\r\n", "\n")
	if r := []rune(msg); len(r) > wevtMaxMessage {
		msg = string(r[:wevtMaxMessage]) + "…"
	}
	e.Message = msg
	return e
}

// winXMLText flattens an XML fragment to its character data, one space
// between leaves, for the UserData fallback.
func winXMLText(fragment string) string {
	d := xml.NewDecoder(strings.NewReader(fragment))
	d.Strict = false
	var parts []string
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		if cd, ok := tok.(xml.CharData); ok {
			if s := strings.TrimSpace(string(cd)); s != "" {
				parts = append(parts, s)
			}
		}
	}
	return strings.Join(parts, " ")
}

// winFilterEventLog keeps entries whose message or source contains search,
// case-insensitively; an empty search keeps everything.
func winFilterEventLog(entries []protocol.EventLogEntry, search string) []protocol.EventLogEntry {
	search = strings.ToLower(strings.TrimSpace(search))
	if search == "" {
		return entries
	}
	out := make([]protocol.EventLogEntry, 0, len(entries))
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Message), search) || strings.Contains(strings.ToLower(e.Source), search) {
			out = append(out, e)
		}
	}
	return out
}

// ---- Windows Update (WUA via PowerShell) ----

// wuaList accepts a JSON array, a single object or null. Windows PowerShell's
// ConvertTo-Json collapses one-element arrays into bare objects in some
// shapes, and the agent must not lose the last update because of it.
type wuaList[T any] []T

func (l *wuaList[T]) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*l = nil
		return nil
	}
	if b[0] == '[' {
		var arr []T
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*l = arr
		return nil
	}
	var one T
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*l = []T{one}
	return nil
}

type wuaScanUpdate struct {
	ID             string          `json:"id"`
	Revision       int             `json:"revision"`
	Title          string          `json:"title"`
	KB             wuaList[string] `json:"kb"`
	Severity       string          `json:"severity"`
	Categories     wuaList[string] `json:"categories"`
	Size           float64         `json:"size"`
	Downloaded     bool            `json:"downloaded"`
	RebootBehavior int             `json:"reboot_behavior"`
	Description    string          `json:"description"`
	Mandatory      bool            `json:"mandatory"`
}

// wuaHistoryItem is one IUpdateSearcher::QueryHistory entry - what the
// device has actually installed. A history entry carries no KB list and no
// categories, so the KB number has to come out of the title.
type wuaHistoryItem struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type wuaScanOutput struct {
	Updates       wuaList[wuaScanUpdate]  `json:"updates"`
	History       wuaList[wuaHistoryItem] `json:"history"`
	RebootPending bool                    `json:"reboot_pending"`
	Error         string                  `json:"error"`
	ErrorHResult  string                  `json:"error_hresult"`
}

type wuaInstallItem struct {
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Result  int     `json:"result"`
	HResult float64 `json:"hresult"`
	Reboot  bool    `json:"reboot"`
	Error   string  `json:"error"`
}

type wuaInstallOutput struct {
	Results        wuaList[wuaInstallItem] `json:"results"`
	RebootRequired bool                    `json:"reboot_required"`
	Error          string                  `json:"error"`
	ErrorHResult   string                  `json:"error_hresult"`
}

// wuaLineKind classifies one line of the PowerShell scripts' stdout.
type wuaLineKind int

const (
	wuaLineBlank    wuaLineKind = iota
	wuaLineProgress             // "PROGRESS <text>": forwarded live to the operator
	wuaLineResult               // "RESULT <json>": the final payload
	wuaLineOther                // host warnings and stray output: kept in the log
)

// winWUALine classifies a stdout line and strips its prefix.
func winWUALine(line string) (wuaLineKind, string) {
	line = strings.TrimRight(line, "\r")
	switch {
	case strings.HasPrefix(line, "PROGRESS "):
		return wuaLineProgress, strings.TrimSpace(strings.TrimPrefix(line, "PROGRESS "))
	case strings.HasPrefix(line, "RESULT "):
		return wuaLineResult, strings.TrimSpace(strings.TrimPrefix(line, "RESULT "))
	case strings.TrimSpace(line) == "":
		return wuaLineBlank, ""
	}
	return wuaLineOther, line
}

// winSplitWUAOutput separates a whole stdout capture into progress lines,
// the final result JSON and everything else.
func winSplitWUAOutput(stdout string) (progress, other []string, result string) {
	for _, line := range strings.Split(strings.ReplaceAll(stdout, "\r\n", "\n"), "\n") {
		switch kind, text := winWUALine(line); kind {
		case wuaLineProgress:
			progress = append(progress, text)
		case wuaLineResult:
			result = text
		case wuaLineOther:
			other = append(other, text)
		}
	}
	return progress, other, result
}

// winParseWUAScan converts the scan script's JSON into the wire result.
// A WUA-level failure (search threw) comes back in Error with an empty
// list rather than as a Go error, so the operator sees the HRESULT.
func winParseWUAScan(result string) (*protocol.UpdatesScanResult, error) {
	if strings.TrimSpace(result) == "" {
		return nil, errors.New("scan produced no RESULT line")
	}
	var out wuaScanOutput
	if err := json.Unmarshal([]byte(result), &out); err != nil {
		return nil, fmt.Errorf("decode scan result: %w", err)
	}
	res := &protocol.UpdatesScanResult{Updates: []protocol.Update{}, RebootPending: out.RebootPending}
	for _, u := range out.Updates {
		if strings.TrimSpace(u.ID) == "" {
			continue
		}
		up := protocol.Update{
			ID:          strings.TrimSpace(u.ID),
			Title:       strings.TrimSpace(u.Title),
			Severity:    strings.TrimSpace(u.Severity),
			SizeBytes:   int64(u.Size),
			Downloaded:  u.Downloaded,
			RebootReq:   u.RebootBehavior != 0, // 1 = always, 2 = can request
			Description: strings.TrimSpace(u.Description),
			Source:      "wua",
		}
		var kbs []string
		for _, k := range u.KB {
			if k = strings.TrimSpace(k); k != "" {
				kbs = append(kbs, "KB"+strings.TrimPrefix(strings.ToUpper(k), "KB"))
			}
		}
		up.KB = strings.Join(kbs, ", ")
		for _, c := range u.Categories {
			if c = strings.TrimSpace(c); c != "" {
				up.Categories = append(up.Categories, c)
			}
		}
		res.Updates = append(res.Updates, up)
	}
	// Installed history. WUA is the only record of what the device already
	// has: without it the console's Installed tab stays empty until a pending
	// update happens to vanish from a later scan. An id that is still pending
	// wins over its history entry - a cumulative update that installed and is
	// waiting for a reboot is offered again, and must not be reported as done.
	seen := map[string]bool{}
	for _, u := range res.Updates {
		seen[strings.ToLower(u.ID)] = true
	}
	for _, h := range out.History {
		id := strings.TrimSpace(h.ID)
		if id == "" || seen[strings.ToLower(id)] {
			continue
		}
		seen[strings.ToLower(id)] = true
		title := strings.TrimSpace(h.Title)
		res.Updates = append(res.Updates, protocol.Update{
			ID:        id,
			Title:     title,
			KB:        winKBFromTitle(title),
			Installed: true,
			Source:    "wua",
		})
	}
	sort.SliceStable(res.Updates, func(i, j int) bool {
		return strings.ToLower(res.Updates[i].Title) < strings.ToLower(res.Updates[j].Title)
	})
	if out.Error != "" {
		res.Error = out.Error
		if out.ErrorHResult != "" && !strings.Contains(out.Error, out.ErrorHResult) {
			res.Error += " (" + out.ErrorHResult + ")"
		}
	}
	return res, nil
}

// winParseWUAInstall converts the install script's JSON into the wire
// result. Result codes: 2 succeeded, 3 succeeded with errors (both count as
// installed), 4 failed, 5 aborted, 0 not started (the update was not offered).
func winParseWUAInstall(result string) (*protocol.UpdatesInstallResult, error) {
	if strings.TrimSpace(result) == "" {
		return nil, errors.New("install produced no RESULT line")
	}
	var out wuaInstallOutput
	if err := json.Unmarshal([]byte(result), &out); err != nil {
		return nil, fmt.Errorf("decode install result: %w", err)
	}
	res := &protocol.UpdatesInstallResult{Installed: []string{}, Failed: map[string]string{}, RebootReq: out.RebootRequired}
	for _, r := range out.Results {
		id := strings.TrimSpace(r.ID)
		if id == "" {
			continue
		}
		if r.Reboot {
			res.RebootReq = true
		}
		switch r.Result {
		case 2, 3:
			res.Installed = append(res.Installed, id)
		default:
			res.Failed[id] = winWUAResultText(r.Result, int64(r.HResult), r.Error)
		}
	}
	if out.Error != "" {
		msg := out.Error
		if out.ErrorHResult != "" && !strings.Contains(msg, out.ErrorHResult) {
			msg += " (" + out.ErrorHResult + ")"
		}
		if len(out.Results) == 0 {
			return res, errors.New("windows update: " + msg)
		}
		res.Log = "windows update: " + msg
	}
	return res, nil
}

// winMarkUnreported adds a Failed entry for every requested id the install
// script neither installed nor failed. Windows Update simply did not offer
// it (already installed, hidden, superseded or not applicable), and without
// this the id would vanish from the result without a word.
func winMarkUnreported(res *protocol.UpdatesInstallResult, requested []string) {
	if res == nil || len(requested) == 0 {
		return
	}
	seen := map[string]bool{}
	for _, id := range res.Installed {
		seen[strings.ToLower(id)] = true
	}
	for id := range res.Failed {
		seen[strings.ToLower(id)] = true
	}
	for _, id := range requested {
		k := strings.ToLower(strings.TrimSpace(id))
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		if res.Failed == nil {
			res.Failed = map[string]string{}
		}
		res.Failed[id] = "not offered by Windows Update (already installed, hidden, superseded or not applicable)"
	}
}

// wuaKnownHResults gives operators a sentence for the HRESULTs that come up
// again and again instead of a bare hex code.
var wuaKnownHResults = map[uint32]string{
	0x80070422: "the Windows Update service is disabled",
	0x80240016: "another installation is already in progress",
	0x80240017: "the update is not applicable to this computer",
	0x80240020: "an interactive user session is required",
	0x80240022: "all updates failed to install",
	0x8024402C: "the update server could not be reached (DNS/proxy)",
	0x80072EE2: "the request to the update server timed out",
	0x80070005: "access denied",
	0x8024000B: "the operation was cancelled",
	0x80242016: "the update state after installation is unexpected; a reboot may be pending",
}

// winWUAResultText renders an OperationResultCode plus HRESULT and any
// script-supplied error into one line.
func winWUAResultText(code int, hresult int64, errText string) string {
	var text string
	switch code {
	case 0:
		text = "not started"
	case 1:
		text = "in progress"
	case 2:
		text = "succeeded"
	case 3:
		text = "succeeded with errors"
	case 4:
		text = "failed"
	case 5:
		text = "aborted"
	default:
		text = fmt.Sprintf("result code %d", code)
	}
	if hresult != 0 {
		h := uint32(hresult)
		text += fmt.Sprintf(" (HRESULT 0x%08X", h)
		if known, ok := wuaKnownHResults[h]; ok {
			text += ": " + known
		}
		text += ")"
	}
	if errText = strings.TrimSpace(errText); errText != "" {
		text += ": " + errText
	}
	return text
}

// winIsUpdateID reports a WUA UpdateID (a GUID), the only shape the install
// script accepts on its command line.
var winUpdateIDRE = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

func winIsUpdateID(id string) bool { return winUpdateIDRE.MatchString(id) }

// winKBFromTitle pulls the KB number out of an update title. A WUA history
// entry has no KBArticleIDs, so its title is the only place the number
// appears ("2026-09 Security Update (KB5129195) (26200.9457)").
var winKBTitleRE = regexp.MustCompile(`(?i)\bKB(\d{5,10})\b`)

func winKBFromTitle(title string) string {
	if m := winKBTitleRE.FindStringSubmatch(title); m != nil {
		return "KB" + m[1]
	}
	return ""
}

// winSplitInstallIDs partitions an install batch into the update GUIDs the
// WUA install script can take and the ids this agent cannot install, each
// with the reason the operator gets back as a per-id failure.
//
// Every id used to be validated up front and the FIRST offender aborted the
// whole request, so a single winget row in the batch - and a Windows device's
// patch list is mostly winget rows - marked every genuine Windows update in
// it failed with the winget message, without installing anything.
func winSplitInstallIDs(ids []string) (guids []string, skipped map[string]string) {
	skip := func(id, reason string) {
		if skipped == nil {
			skipped = map[string]string{}
		}
		skipped[id] = reason
	}
	for _, raw := range ids {
		id := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "wua:"))
		switch {
		case strings.HasPrefix(id, "winget:"):
			// winget upgrades are reported as extras but installing them from
			// the SYSTEM account is unreliable; refuse this one id rather than
			// pretend, and let the rest of the batch through.
			skip(raw, "winget upgrades cannot be installed from the agent service account")
		case winIsUpdateID(id):
			guids = append(guids, id)
		default:
			skip(raw, fmt.Sprintf("invalid update id %q", id))
		}
	}
	return guids, skipped
}

// winJoinScanError appends a second problem to a scan's error text without
// losing the first: the Windows Update half and the winget half of a scan
// fail independently, and the server only concludes "no longer reported =>
// installed" for a scan that reported no error at all.
func winJoinScanError(existing, add string) string {
	existing, add = strings.TrimSpace(existing), strings.TrimSpace(add)
	switch {
	case add == "":
		return existing
	case existing == "":
		return add
	default:
		return existing + "; " + add
	}
}

// winUnderRoot reports whether path sits inside root, comparing
// case-insensitively and treating / and \ alike, because Windows does.
func winUnderRoot(path, root string) bool {
	norm := func(s string) string {
		return strings.TrimRight(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "/", `\`)), `\`)
	}
	p, r := norm(path), norm(root)
	if p == "" || r == "" {
		return false
	}
	return strings.HasPrefix(p, r+`\`)
}

// winTrustedExe reports whether an executable resolved through PATH is safe
// for the agent to run: it must live under one of roots (%SystemRoot%,
// %ProgramFiles%, %ProgramW6432%), which only administrators can write. The
// agent runs as LocalSystem, so a writable directory that made it onto PATH
// must never be able to shadow a tool - the same rule systemExe applies to
// System32 (exec_windows.go).
func winTrustedExe(path string, roots []string) bool {
	for _, root := range roots {
		if winUnderRoot(path, root) {
			return true
		}
	}
	return false
}

// winTrustedRoots is the administrator-only root list for winTrustedExe.
func winTrustedRoots() []string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return []string{root, os.Getenv("ProgramW6432"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")}
}

// ---- winget ----

// wingetColumns holds the rune offsets of the columns in a "winget upgrade"
// table header; -1 means the column is absent (old winget has no Source).
type wingetColumns struct{ name, id, version, available, source int }

// winWingetHeader locates the table header's columns. winget aligns cells
// to the header, so the header's word offsets are the cell boundaries.
func winWingetHeader(line string) (wingetColumns, bool) {
	cols := wingetColumns{name: -1, id: -1, version: -1, available: -1, source: -1}
	r := []rune(line)
	for i := 0; i < len(r); {
		if unicode.IsSpace(r[i]) {
			i++
			continue
		}
		j := i
		for j < len(r) && !unicode.IsSpace(r[j]) {
			j++
		}
		switch string(r[i:j]) {
		case "Name":
			cols.name = i
		case "Id":
			cols.id = i
		case "Version":
			cols.version = i
		case "Available":
			cols.available = i
		case "Source":
			cols.source = i
		}
		i = j
	}
	ok := cols.name >= 0 && cols.id > cols.name && cols.version > cols.id && cols.available > cols.version &&
		(cols.source < 0 || cols.source > cols.available)
	return cols, ok
}

// winParseWingetUpgrade reads the table "winget upgrade" prints and returns
// one Update per row with Source "winget". winget's progress spinner is
// carriage-return animation on the first lines; only the text after the
// last \r of a line is real.
func winParseWingetUpgrade(out string) []protocol.Update {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	for i, l := range lines {
		if j := strings.LastIndex(l, "\r"); j >= 0 {
			lines[i] = l[j+1:]
		}
	}
	var updates []protocol.Update
	for i := 0; i+1 < len(lines); i++ {
		cols, ok := winWingetHeader(lines[i])
		if !ok || !strings.HasPrefix(strings.TrimSpace(lines[i+1]), "---") {
			continue
		}
		j := i + 2
		for ; j < len(lines); j++ {
			row := []rune(lines[j])
			if strings.TrimSpace(lines[j]) == "" {
				break
			}
			cell := func(a, b int) string {
				if a < 0 || a >= len(row) {
					return ""
				}
				if b < 0 || b > len(row) {
					b = len(row)
				}
				return strings.TrimSpace(string(row[a:b]))
			}
			name := cell(cols.name, cols.id)
			id := cell(cols.id, cols.version)
			version := cell(cols.version, cols.available)
			available := cell(cols.available, cols.source)
			source := cell(cols.source, -1)
			if id == "" || available == "" || strings.ContainsAny(id, " \t") {
				break // the "N upgrades available." trailer or a wrapped line
			}
			if source == "" {
				source = "winget"
			}
			updates = append(updates, protocol.Update{
				ID:          "winget:" + id,
				Title:       name,
				Version:     available,
				Description: "installed " + version + ", available " + available + " (" + source + ")",
				Source:      "winget",
			})
		}
		i = j
	}
	return updates
}

// ---- power ----

// winShutdownArgs builds the shutdown.exe argument list for reboot or
// shutdown. /f closes applications without warning (an unattended box has
// nobody to answer the prompt), /d p:0:0 records a planned "other" reason.
func winShutdownArgs(action string, delaySec int, message string) []string {
	flag := "/r"
	if action == "shutdown" {
		flag = "/s"
	}
	if delaySec < 0 {
		delaySec = 0
	}
	if delaySec > 315360000 { // shutdown.exe's own maximum (10 years)
		delaySec = 315360000
	}
	args := []string{flag, "/f", "/t", strconv.Itoa(delaySec), "/d", "p:0:0"}
	if msg := winCleanMessage(message, 512); msg != "" {
		args = append(args, "/c", msg)
	}
	return args
}
