//go:build windows

package agent

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const (
	eventLogDefaultLimit = 100
	eventLogMaxLimit     = 1000
	// eventLogSearchFetch bounds how far back a text search reads before
	// filtering; the search is applied by the agent, not by the log service.
	eventLogSearchFetch = 2000
	eventLogTimeout     = 90 * time.Second
)

// wevtutilArgs builds the query: newest first, rendered XML so the message
// template is already resolved, and an XPath filter when there is one.
func wevtutilArgs(logName string, count int, xpath string) []string {
	args := []string{"qe", logName, "/c:" + strconv.Itoa(count), "/rd:true", "/f:RenderedXml"}
	if xpath != "" {
		args = append(args, "/q:"+xpath)
	}
	return args
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
	limit := q.Limit
	if limit <= 0 {
		limit = eventLogDefaultLimit
	}
	if limit > eventLogMaxLimit {
		limit = eventLogMaxLimit
	}
	fetch := limit
	if strings.TrimSpace(q.Search) != "" {
		fetch = min(limit*10, eventLogSearchFetch)
	}
	ctx, cancel := context.WithTimeout(context.Background(), eventLogTimeout)
	defer cancel()
	// wevtutil writes the ANSI code page, not the OEM one, once its stdout
	// is a pipe: an event message with an accented character is mangled if
	// it is decoded like shutdown.exe's output.
	out, _, err := runHiddenACP(ctx, "wevtutil.exe", wevtutilArgs(logName, fetch, winEventLogXPath(q.Level, q.SinceTS))...)
	if err != nil {
		return nil, fmt.Errorf("query event log %s: %w", logName, err)
	}
	entries, err := winParseWevtutilXML([]byte(out))
	if err != nil {
		return nil, fmt.Errorf("query event log %s: %w", logName, err)
	}
	entries = winFilterEventLog(entries, q.Search)
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}
