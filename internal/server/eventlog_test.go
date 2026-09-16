package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// ---- evt-06: the event log is an ordinary read for a viewer EXCEPT for the
// channels that are really an audit trail. Security hands over logon and
// account-enumeration records with names and SIDs, and the PowerShell
// channels hand over whole command lines and script blocks; downloading a
// file from the same device has been requireWrite and audited all along, and
// the event-log route was neither. ----

func TestSensitiveEventLogChannelsAreWriteOnlyAndAudited(t *testing.T) {
	s, ts, admin := newTestServerWith(t, Config{})
	admin.mustJSON("POST", "/api/users", map[string]string{"username": "ro", "password": "password123", "role": "viewer"}, nil)
	ro := newBrowser(t, ts)
	ro.mustJSON("POST", "/api/auth/login", map[string]string{"username": "ro", "password": "password123"}, nil)

	const agentID = "0123456789abcdef"
	path := func(log string) string {
		return "/api/agents/" + agentID + "/eventlog?limit=10&log=" + url.QueryEscape(log)
	}
	// Case and spacing must not open a back door: both agents resolve the
	// channel name case-insensitively.
	for _, log := range []string{"Security", "security", " SECURITY ", "auth",
		"Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"} {
		if st, body := ro.do("GET", path(log), nil); st != http.StatusForbidden {
			t.Errorf("viewer read of %q = %d (%s), want 403", log, st, body)
		}
	}
	// The ordinary channels stay readable for a viewer. The device does not
	// exist here, so the status is whatever the hub says - just never
	// "read-only account".
	for _, log := range []string{"System", "Application", "Microsoft-Windows-TaskScheduler/Operational", ""} {
		if st, _ := ro.do("GET", path(log), nil); st == http.StatusForbidden {
			t.Errorf("viewer read of %q was refused", log)
		}
	}
	if n := auditRows(t, s, "eventlog.query"); n != 0 {
		t.Fatalf("refused reads left %d audit rows", n)
	}

	// A writer gets through, and the read is on the record.
	if st, _ := admin.do("GET", path("Security"), nil); st == http.StatusForbidden {
		t.Fatalf("an admin was refused the Security log")
	}
	admin.do("GET", path("System"), nil)
	if n := auditRows(t, s, "eventlog.query"); n != 1 {
		t.Fatalf("eventlog.query audit rows = %d, want exactly the Security read", n)
	}
	var target, details string
	if err := s.db.QueryRow(`SELECT target, details FROM audit WHERE action = 'eventlog.query'`).Scan(&target, &details); err != nil {
		t.Fatal(err)
	}
	if target != agentID || !strings.Contains(details, "Security") {
		t.Errorf("audit row does not name the device and channel: target %q details %q", target, details)
	}
}

func auditRows(t *testing.T, s *Server, action string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
