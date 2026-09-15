//go:build linux

package agent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const (
	eventLogDefaultLimit = 200
	eventLogMaxLimit     = 5000
	journalTimeout       = 90 * time.Second
	// syslogTailBytes is how much of a plain-text log the fallback reads
	// from the end; enough for thousands of lines without loading a
	// multi-gigabyte file.
	syslogTailBytes = 16 << 20
)

// queryEventLog reads journald when it is there and tails the classic
// syslog files otherwise. Log "" / "System" / "Application" mean the whole
// journal, "kernel" the kernel ring, "Security" the auth facilities and
// anything else is a unit name.
func queryEventLog(q protocol.EventLogQuery) ([]protocol.EventLogEntry, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = eventLogDefaultLimit
	}
	if limit > eventLogMaxLimit {
		limit = eventLogMaxLimit
	}
	if hasCmd("journalctl") {
		return journalQuery(q, limit)
	}
	return syslogQuery(q, limit)
}

// journalScope translates the Log selector into journalctl arguments.
func journalScope(log string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(log)) {
	case "", "system", "application", "journal", "all":
		return nil, nil
	case "kernel", "dmesg":
		return []string{"-k"}, nil
	case "security", "auth":
		// auth (4) and authpriv (10) facilities, or anything the audit
		// subsystem forwarded.
		return []string{"SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "+", "_TRANSPORT=audit"}, nil
	}
	name := strings.TrimSpace(log)
	if !validUnitName(name) {
		return nil, fmt.Errorf("invalid log or unit name %q", log)
	}
	// The selector is "unit or identifier" and operators type whichever they
	// know: on Debian "sshd" is the syslog identifier of ssh.service, so a
	// plain "-u sshd" finds nothing. Explicit matches OR the two views (plus
	// systemd's own "Started/Stopped" lines about the unit, which is what
	// "-u" adds internally).
	return journalMatchesFor(name), nil
}

func journalQuery(q protocol.EventLogQuery, limit int) ([]protocol.EventLogEntry, error) {
	base := []string{"-o", "json", "--no-pager", "-q", "-r"}
	switch strings.ToLower(q.Level) {
	case "error", "critical":
		base = append(base, "-p", "err")
	case "warning", "warn":
		base = append(base, "-p", "warning")
	}
	if q.SinceTS > 0 {
		base = append(base, "--since", "@"+strconv.FormatInt(q.SinceTS, 10))
	}
	scope, err := journalScope(q.Log)
	if err != nil {
		return nil, err
	}
	search := strings.TrimSpace(q.Search)
	args := append([]string{"-n", strconv.Itoa(limit)}, base...)
	if search != "" {
		// The pattern is PCRE; quoting it makes the operator's text a literal
		// search, which is what the Windows side does too.
		args = append(args, "--case-sensitive=false", "-g", regexp.QuoteMeta(search))
	}
	args = append(args, scope...)
	out, stderr, code, err := runCmdTimeout(journalTimeout, "journalctl", args...)
	if err != nil && search != "" && (strings.Contains(stderr, "pattern") || strings.Contains(stderr, "case-sensitive")) {
		// journalctl built without PCRE2 (or too old for the flag): fetch a
		// bigger window and filter here.
		fetch := limit * 20
		if fetch > 20000 {
			fetch = 20000
		}
		args = append(append([]string{"-n", strconv.Itoa(fetch)}, base...), scope...)
		out, stderr, code, err = runCmdTimeout(journalTimeout, "journalctl", args...)
	}
	if err != nil {
		// With -g, "no entry matched" is exit 1 and silence, not a failure.
		noMatch := search != "" && code == 1 && strings.TrimSpace(stderr) == ""
		if strings.TrimSpace(out) == "" && !noMatch {
			return nil, fmt.Errorf("journalctl: %s", orFirst(firstLine(stderr), err.Error()))
		}
		// Partial output (e.g. a corrupted journal file) is still worth showing.
	}
	entries := parseJournalJSON(out)
	return filterEntries(entries, q.Level, search, q.SinceTS, limit), nil
}

// filterEntries applies the query constraints in Go, which both backs up
// the command-line filters and is the only filtering the syslog path has.
func filterEntries(entries []protocol.EventLogEntry, level, search string, since int64, limit int) []protocol.EventLogEntry {
	out := make([]protocol.EventLogEntry, 0, len(entries))
	needle := strings.ToLower(search)
	for _, e := range entries {
		if !logLevelAllowed(level, e.Level) {
			continue
		}
		if since > 0 && e.TS > 0 && e.TS < since {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(e.Message), needle) && !strings.Contains(strings.ToLower(e.Source), needle) {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// syslogQuery is the no-journald fallback: tail the right plain-text log.
func syslogQuery(q protocol.EventLogQuery, limit int) ([]protocol.EventLogEntry, error) {
	var candidates []string
	switch strings.ToLower(strings.TrimSpace(q.Log)) {
	case "kernel", "dmesg":
		candidates = []string{"/var/log/kern.log", "/var/log/dmesg", "/var/log/messages", "/var/log/syslog"}
	case "security", "auth":
		candidates = []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages", "/var/log/syslog"}
	default:
		candidates = []string{"/var/log/syslog", "/var/log/messages"}
	}
	var path string
	for _, c := range candidates {
		if fileExists(c) {
			path = c
			break
		}
	}
	if path == "" {
		return nil, errors.New("no journald and no syslog file found under /var/log")
	}
	lines, err := tailFileLines(path, syslogTailBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	entries := parseSyslogLines(lines, time.Now())
	// A unit-style Log selector on a syslog host narrows by program name.
	if l := strings.TrimSpace(q.Log); l != "" && !isBroadLog(l) {
		prog := strings.TrimSuffix(l, ".service")
		kept := entries[:0]
		for _, e := range entries {
			if strings.EqualFold(e.Source, prog) {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	return filterEntries(entries, q.Level, strings.TrimSpace(q.Search), q.SinceTS, limit), nil
}

func isBroadLog(l string) bool {
	switch strings.ToLower(l) {
	case "system", "application", "journal", "all", "kernel", "dmesg", "security", "auth":
		return true
	}
	return false
}

// tailFileLines returns the complete lines within the last maxBytes of a
// file, oldest first. The first partial line of the window is dropped.
func tailFileLines(path string, maxBytes int64) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	partial := false
	if st.Size() > maxBytes {
		start = st.Size() - maxBytes
		partial = true
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var lines []string
	for sc.Scan() {
		if partial {
			partial = false
			continue
		}
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil && len(lines) == 0 {
		return nil, err
	}
	return lines, nil
}
