package server

import (
	"net/http"
	"testing"
	"time"
)

// "Resolve all" by a technician limited to some organizations used to read
// the open alerts and update each one inside the read. With the database's
// single connection held by the read, the first update waited forever and
// every other request queued behind it.
func TestResolveAllScopedDoesNotHangAndStaysInScope(t *testing.T) {
	s, ts, admin := newTestServer(t)
	orgA, _ := s.db.CreateOrganization("A")
	orgB, _ := s.db.CreateOrganization("B")
	for _, a := range []struct{ id, org string }{{"agent-a", orgA.ID}, {"agent-b", orgB.ID}} {
		if _, err := s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id)
			VALUES(?, ?, ?, 'linux', 'Test', 'amd64', '1', ?, ?, ?, ?)`, a.id, a.id, a.id, "hash-"+a.id, now(), now(), a.org); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if _, err := s.db.Exec(`INSERT INTO alerts(agent_id, severity, title, opened_at) VALUES(?, 'warning', 'test', ?)`, a.id, now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	admin.mustJSON("POST", "/api/users", map[string]any{"username": "techa", "password": "password123", "role": RoleTech, "org_scope": []string{orgA.ID}}, nil)
	tech := newBrowser(t, ts)
	tech.mustJSON("POST", "/api/auth/login", map[string]string{"username": "techa", "password": "password123"}, nil)

	done := make(chan struct{})
	var res struct {
		Resolved int64 `json:"resolved"`
	}
	go func() {
		defer close(done)
		tech.c.Timeout = 10 * time.Second
		tech.mustJSON("POST", "/api/alerts/resolve-all", nil, &res)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("resolve-all hung")
	}
	if res.Resolved != 3 {
		t.Fatalf("resolved %d, want the 3 in the technician's organization", res.Resolved)
	}
	var openA, openB int
	s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE agent_id = 'agent-a' AND status != 'resolved'`).Scan(&openA)
	s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE agent_id = 'agent-b' AND status != 'resolved'`).Scan(&openB)
	if openA != 0 || openB != 3 {
		t.Fatalf("open after: org A %d (want 0), org B %d (want 3)", openA, openB)
	}
	// and the server still answers
	if st, _ := admin.do("GET", "/api/alerts", nil); st != http.StatusOK {
		t.Fatalf("server not answering after resolve-all: %d", st)
	}
}
