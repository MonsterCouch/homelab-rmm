package server

import (
	"testing"
)

func TestAgentIsolation(t *testing.T) {
	s, _, b := newTestServer(t)

	// 1. Enroll/insert a dummy agent
	agentID := "test_isolate_box"
	nowSec := now()
	_, err := s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen)
		VALUES(?, 'box1', 'Box 1', 'windows', 'Windows 11', 'amd64', 'test', 'hash', ?, ?)`, agentID, nowSec, nowSec)
	if err != nil {
		t.Fatal(err)
	}

	// Initial status should be isolated=false
	a, err := s.db.GetAgent(agentID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Isolated {
		t.Fatal("expected initial agent not to be isolated")
	}

	// 2. Isolate agent via API
	var isoRes map[string]any
	b.mustJSON("POST", "/api/agents/"+agentID+"/isolate", map[string]any{"isolate": true}, &isoRes)
	if isoRes["ok"] != true || isoRes["isolated"] != true {
		t.Fatalf("unexpected isolate response: %+v", isoRes)
	}

	// Verify in DB
	a, err = s.db.GetAgent(agentID)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Isolated {
		t.Fatal("expected agent to be isolated after API call")
	}
	if a.IsolatedAt == 0 {
		t.Fatal("expected isolated_at to be populated")
	}
	if a.IsolatedBy != "admin" {
		t.Fatalf("expected isolated_by='admin', got %q", a.IsolatedBy)
	}

	// 3. Release agent via API
	var relRes map[string]any
	b.mustJSON("POST", "/api/agents/"+agentID+"/isolate", map[string]any{"isolate": false}, &relRes)
	if relRes["ok"] != true || relRes["isolated"] != false {
		t.Fatalf("unexpected release response: %+v", relRes)
	}

	a, err = s.db.GetAgent(agentID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Isolated {
		t.Fatal("expected agent to be released from isolation")
	}
}
