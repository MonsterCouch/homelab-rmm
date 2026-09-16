//go:build windows

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// The page size and the search window are the contract documented in
// docs/API.md, and they are deliberately the Linux agent's numbers too: the
// same request must not read five times more of the log on one OS than on
// the other.
const (
	eventLogDefaultLimit = 200
	eventLogMaxLimit     = 5000
	// eventLogSearchWindow is how many of the newest matching records a text
	// search reads before filtering, INDEPENDENT of the page size. The
	// search is applied by the agent, not by the log service, and while the
	// window was a multiple of limit the same query found its matches at
	// limit=50 and none at limit=20.
	eventLogSearchWindow = 5000
	eventLogTimeout      = 90 * time.Second
)

// The two wevtutil output formats. RenderedXml resolves every message
// through the provider's own resources, which is why it is the first pass -
// but it silently omits any record it cannot render, so XML is the repair
// pass (winMergeRenderedEvents).
const (
	wevtFormatRendered = "RenderedXml"
	wevtFormatRaw      = "XML"
)

// wevtutilArgs builds the query: newest first, UTF-16 output so event text
// outside the system ANSI code page reaches the operator intact, the asked-for
// render format, and an XPath filter when there is one.
func wevtutilArgs(logName string, count int, xpath, format string) []string {
	args := []string{"qe", logName, "/c:" + strconv.Itoa(count), "/rd:true", "/f:" + format, "/uni:true"}
	if xpath != "" {
		args = append(args, "/q:"+xpath)
	}
	return args
}

// winEventLogLimit clamps a requested page size to the documented range.
func winEventLogLimit(limit int) int {
	if limit <= 0 {
		return eventLogDefaultLimit
	}
	return min(limit, eventLogMaxLimit)
}

// winEventLogFetch is how many records wevtutil is asked for. Without a
// search that is the page itself; with one it is the fixed search window, so
// how far back an operator searches never depends on the page size they
// happen to have selected.
func winEventLogFetch(limit int, search string) int {
	if strings.TrimSpace(search) == "" {
		return limit
	}
	return max(limit, eventLogSearchWindow)
}

// queryEventLog reads a channel through wevtutil. wevtutil is preferred over
// the EvtQuery API because it renders messages with the provider's own
// resources in one call, which the raw API needs a page of code to do.
func queryEventLog(q protocol.EventLogQuery) ([]protocol.EventLogEntry, error) {
	logName := strings.TrimSpace(q.Log)
	if logName == "" {
		logName = "System"
	}
	if !winValidEventLogName(logName) {
		return nil, fmt.Errorf("invalid event log name %q", q.Log)
	}
	limit := winEventLogLimit(q.Limit)
	ctx, cancel := context.WithTimeout(context.Background(), eventLogTimeout)
	defer cancel()
	entries, err := winReadEventLog(ctx, logName, winEventLogFetch(limit, q.Search), winEventLogXPath(q.Level, q.SinceTS))
	if err != nil {
		return nil, fmt.Errorf("query event log %s: %w", logName, err)
	}
	// Search, cut to the page, and only then apply the display cap:
	// truncating first hid everything past 8000 characters of a long message
	// from the search as well as from the reader.
	entries = winFilterEventLog(entries, q.Search)
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return winTruncateEventMessages(entries), nil
}

// winReadEventLog runs the wevtutil pass (or passes) behind one query.
// Output is read as UTF-16: wevtutil writes the console code page otherwise,
// which turns every character the code page cannot hold - Greek, Cyrillic,
// CJK, a tick mark - into "?" before the agent sees a byte, making those
// events unreadable and unsearchable.
func winReadEventLog(ctx context.Context, logName string, fetch int, xpath string) ([]protocol.EventLogEntry, error) {
	out, stderr, err := runHiddenUTF16(ctx, "wevtutil.exe", wevtutilArgs(logName, fetch, xpath, wevtFormatRendered)...)
	if err != nil {
		return nil, err
	}
	rendered, err := winParseWevtutilRecords([]byte(out))
	if err != nil {
		return nil, err
	}
	warning := winFirstLine(stderr)
	if warning == "" {
		return winRecordEntries(rendered), nil
	}
	// A record whose provider message cannot be resolved is not an error to
	// wevtutil: it prints "Failed to render events. Error=N" on stderr, exits
	// 0 and leaves the record out of the page, so the caller reads short with
	// nothing to go on. Say so in the log, then re-read the same window as
	// raw XML - which drops nothing - and keep the rendered messages for the
	// records that did render.
	slog.Warn("event log: wevtutil could not render every record, re-reading the window as raw XML",
		"log", logName, "wevtutil", warning)
	rawOut, rawStderr, err := runHiddenUTF16(ctx, "wevtutil.exe", wevtutilArgs(logName, fetch, xpath, wevtFormatRaw)...)
	if err != nil {
		slog.Warn("event log: the raw re-read failed, the page is short by the records that would not render",
			"log", logName, "err", err)
		return winRecordEntries(rendered), nil
	}
	if w := winFirstLine(rawStderr); w != "" {
		slog.Warn("event log: wevtutil warned on the raw re-read", "log", logName, "wevtutil", w)
	}
	raw, err := winParseWevtutilRecords([]byte(rawOut))
	if err != nil {
		slog.Warn("event log: the raw re-read could not be parsed", "log", logName, "err", err)
		return winRecordEntries(rendered), nil
	}
	return winMergeRenderedEvents(raw, rendered), nil
}
