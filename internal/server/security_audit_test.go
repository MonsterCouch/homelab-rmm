package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSecurityAudit_VULN001_AgentScoping verifies that a technician scoped to Org A
// cannot access, query, update, isolate, run scripts on, download files from, or manage
// an agent assigned to Org B (VULN-001 IDOR fix).
func TestSecurityAudit_VULN001_AgentScoping(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	// Create Org A and Org B
	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Client Alpha"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Client Beta"}, &orgB)

	// Insert Agent A under Org A and Agent B under Org B
	nowSec := now()
	agentAID := "agent_alpha_01"
	agentBID := "agent_beta_01"

	_, err := s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'host-alpha', 'Alpha Server', 'linux', 'Ubuntu 22.04', 'amd64', 'test', 'hash_a', ?, ?, ?, ?)`,
		agentAID, nowSec, nowSec, orgA.ID, "site_default")
	if err != nil {
		t.Fatalf("insert agent A: %v", err)
	}

	_, err = s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'host-beta', 'Beta Server', 'linux', 'Ubuntu 22.04', 'amd64', 'test', 'hash_b', ?, ?, ?, ?)`,
		agentBID, nowSec, nowSec, orgB.ID, "site_default")
	if err != nil {
		t.Fatalf("insert agent B: %v", err)
	}

	// Create technician scoped strictly to Org A
	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_alpha",
		"password":  "AlphaPass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_alpha",
		"password": "AlphaPass123!",
	}, nil)

	// 1. Agent listing must only return agent_alpha_01, never agent_beta_01
	var listed []Agent
	bTech.mustJSON("GET", "/api/agents", nil, &listed)
	foundAlpha := false
	for _, a := range listed {
		if a.ID == agentBID {
			t.Fatalf("VULN-001 failure: technician scoped to Org A saw Agent B in agent list")
		}
		if a.ID == agentAID {
			foundAlpha = true
		}
	}
	if !foundAlpha {
		t.Errorf("technician should see Agent A in their scoped organization")
	}

	// 2. Direct GET /api/agents/{agentBID} must return 404 Not Found
	if st, body := bTech.do("GET", "/api/agents/"+agentBID, nil); st != http.StatusNotFound {
		t.Fatalf("VULN-001 failure: GET agent outside org scope returned %d (body: %s)", st, body)
	}

	// 3. Direct GET /api/agents/{agentAID} must return 200 OK
	if st, _ := bTech.do("GET", "/api/agents/"+agentAID, nil); st != http.StatusOK {
		t.Fatalf("expected 200 OK for agent inside org scope, got %d", st)
	}

	// 4. Mutation endpoints for Agent B must return 404 Not Found
	mutations := []struct {
		method string
		path   string
		body   any
	}{
		{"POST", "/api/agents/" + agentBID + "/isolate", map[string]any{"isolate": true}},
		{"POST", "/api/agents/" + agentBID + "/run-script", map[string]any{"code": "whoami", "shell": "sh"}},
		{"GET", "/api/agents/" + agentBID + "/fs/download?path=/etc/shadow", nil},
		{"POST", "/api/agents/" + agentBID + "/software/install", map[string]any{"software_id": 1}},
		{"POST", "/api/agents/" + agentBID + "/refresh", nil},
		{"POST", "/api/agents/" + agentBID + "/procs/kill", map[string]any{"pid": 1234}},
		{"POST", "/api/agents/" + agentBID + "/services/stop", map[string]any{"name": "sshd"}},
		{"DELETE", "/api/agents/" + agentBID, nil},
	}

	for _, m := range mutations {
		if st, body := bTech.do(m.method, m.path, m.body); st != http.StatusNotFound {
			t.Fatalf("VULN-001 failure: %s %s on agent outside org scope returned %d (body: %s)", m.method, m.path, st, body)
		}
	}
}

// TestSecurityAudit_VULN002_EnrollmentHijacking verifies that an enrollment token for
// Org A cannot adopt or rekey an existing offline agent belonging to Org B, even if
// the hostname and OS match identically (VULN-002 fix).
func TestSecurityAudit_VULN002_EnrollmentHijacking(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	// Create Org A and Org B
	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Target Company"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Attacker Tenant"}, &orgB)

	// Generate enrollment tokens for each
	var tokA, tokB struct{ Token string }
	bAdmin.mustJSON("POST", "/api/enroll", map[string]any{"name": "target_tok", "org_id": orgA.ID, "uses": 5}, &tokA)
	bAdmin.mustJSON("POST", "/api/enroll", map[string]any{"name": "attacker_tok", "org_id": orgB.ID, "uses": 5}, &tokB)

	// Target organization enrolls an agent with hostname 'db-primary'
	targetAgent := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tokA.Token}}, "db-primary", "linux")
	targetID := targetAgent.id
	targetKey := targetAgent.key

	// Target agent disconnects and becomes offline
	targetAgent.ws.Close()
	s.hub.waitClosed(2 * time.Second)

	// Attacker connects using Org B's token, claiming hostname 'db-primary' and OS 'linux'
	attackerAgent := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tokB.Token}}, "db-primary", "linux")
	defer attackerAgent.ws.Close()

	// VULN-002 Verification:
	// Attacker MUST NOT receive Target's agent ID
	if attackerAgent.id == targetID {
		t.Fatalf("VULN-002 failure: Attacker in Org B hijacked Target agent record %s from Org A!", targetID)
	}

	// Verify database record integrity: target agent record must remain scoped to Org A with its original key
	targetRecord, err := s.db.GetAgent(targetID)
	if err != nil {
		t.Fatalf("get target agent: %v", err)
	}
	if targetRecord.OrgID != orgA.ID {
		t.Fatalf("target agent org changed: want %s, got %s", orgA.ID, targetRecord.OrgID)
	}
	// Verify target's key was not overwritten by attacker
	var keyHash string
	_ = s.db.QueryRow(`SELECT key_hash FROM agents WHERE id = ?`, targetID).Scan(&keyHash)
	if keyHash != hashKey(targetKey) {
		t.Fatalf("target agent key was overwritten by attacker enrollment!")
	}
}

// TestSecurityAudit_VULN003_SoftwareCatalogAdmin verifies that non-admin technicians
// cannot create, edit, or delete software catalog entries or custom commands (VULN-003 fix).
func TestSecurityAudit_VULN003_SoftwareCatalogAdmin(t *testing.T) {
	_, ts, bAdmin := newTestServer(t)

	// Create technician user (has write permission, but is NOT admin)
	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username": "tech_user",
		"password": "TechPassword123!",
		"role":     "tech",
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_user",
		"password": "TechPassword123!",
	}, nil)

	// 1. Technician attempting to create a catalog item must receive 403 Forbidden
	st, body := bTech.do("POST", "/api/software-catalog", map[string]any{
		"name":                 "Ransomware Payload",
		"category":             "utilities",
		"os_supported":         "all",
		"install_type_windows": "custom",
		"custom_cmd_windows":   "powershell -c Invoke-Mimikatz",
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-003 failure: technician created software catalog item; status %d (body: %s)", st, body)
	}

	// 2. Technician attempting to update a catalog item must receive 403 Forbidden
	st, _ = bTech.do("PUT", "/api/software-catalog/1", map[string]any{
		"name": "Modified Package",
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-003 failure: technician updated software catalog item; status %d", st)
	}

	// 3. Technician attempting to delete a catalog item must receive 403 Forbidden
	st, _ = bTech.do("DELETE", "/api/software-catalog/1", nil)
	if st != http.StatusForbidden {
		t.Fatalf("VULN-003 failure: technician deleted software catalog item; status %d", st)
	}

	// 4. Admin CAN create software catalog items
	var created SoftwareCatalogItem
	bAdmin.mustJSON("POST", "/api/software-catalog", map[string]any{
		"name":        "Admin Approved Utility",
		"category":    "utilities",
		"os":          "all",
		"install_cmd": "winget install Admin.Utility",
	}, &created)
	if created.ID == "" {
		t.Fatalf("admin failed to create catalog item")
	}
}

// TestSecurityAudit_VULN004_SubnetScanDoS verifies that unbounded subnet sizes (/8, /0)
// are rejected at the API layer with 400 Bad Request to prevent DoS (VULN-004 fix).
func TestSecurityAudit_VULN004_SubnetScanDoS(t *testing.T) {
	_, _, b := newTestServer(t)

	// Dangerous massive subnets
	badSubnets := []string{
		"10.0.0.0/8",     // 16.7 million IPs
		"0.0.0.0/0",      // Whole IPv4 internet
		"172.16.0.0/12",  // 1 million IPs
		"192.168.0.0/16", // 65,536 IPs (exceeds /22 cap)
		"invalid-cidr",   // Bad syntax
	}

	for _, sub := range badSubnets {
		st, body := b.do("POST", "/api/network-scans", map[string]any{"subnet": sub})
		if st != http.StatusBadRequest {
			t.Fatalf("VULN-004 failure: scan with subnet %q accepted; expected 400, got %d (body: %s)", sub, st, body)
		}
	}

	// Allowed subnet range (/24 = 254 addresses)
	st, body := b.do("POST", "/api/network-scans", map[string]any{"subnet": "192.168.10.0/24"})
	if st != http.StatusAccepted {
		t.Fatalf("valid /24 subnet rejected: expected 202 Accepted, got %d (body: %s)", st, body)
	}
}

// TestSecurityAudit_VULN005_SNMPPacketBounds verifies that crafted SNMP responses with
// oversized length octets or out-of-bound slices do not panic or crash the server (VULN-005 fix).
func TestSecurityAudit_VULN005_SNMPPacketBounds(t *testing.T) {
	craftedPayloads := [][]byte{
		// Tag 0x04 (OCTET STRING) with 0x85 length (5 length bytes -> integer shift overflow in old code)
		{0x04, 0x85, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0x41, 0x42},
		// Tag 0x04 with length 0x82 but truncated length octets
		{0x04, 0x82, 0x01},
		// Tag 0x04 with single length 0x7F (127 bytes) exceeding packet slice
		{0x04, 0x7F, 0x41, 0x42},
		// Tag 0x43 (TimeTicks) with length 0x88 (exceeding uint64 bounds)
		{0x43, 0x88, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		// Malformed outer sequence length
		{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF},
	}

	for idx, pkt := range craftedPayloads {
		// Must execute without panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("VULN-005 failure: parseSNMPStrings panicked on test payload #%d: %v", idx, r)
				}
			}()
			stringsFound, uptime := parseSNMPStrings(pkt)
			_ = stringsFound
			_ = uptime
		}()
	}

	// Ensure legitimate packet still parses correctly
	validPacket := []byte{
		0x04, 0x08, 'R', 'o', 'u', 't', 'e', 'r', '0', '1',
	}
	strs, _ := parseSNMPStrings(validPacket)
	if len(strs) != 1 || strs[0] != "Router01" {
		t.Fatalf("valid SNMP packet failed to parse: got %v", strs)
	}
}

// TestSecurityAudit_VULN006_TicketTenantPII verifies that tickets are isolated by
// organization, and internal notes are not leaked to unprivileged viewers (VULN-006 fix).
func TestSecurityAudit_VULN006_TicketTenantPII(t *testing.T) {
	_, ts, bAdmin := newTestServer(t)

	// Create Org A and Org B
	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Client Alpha"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Client Beta"}, &orgB)

	// Create Ticket in Org A with an internal technician note containing credentials
	var ticketA Ticket
	bAdmin.mustJSON("POST", "/api/tickets", map[string]any{
		"subject":         "Alpha Network Outage",
		"description":     "Router offline",
		"requester_name":  "Alice Alpha",
		"requester_email": "alice@alpha.example",
		"org_id":          orgA.ID,
		"priority":        "high",
	}, &ticketA)

	bAdmin.mustJSON("POST", fmt.Sprintf("/api/tickets/%d/comments", ticketA.ID), map[string]any{
		"body":        "CONFIDENTIAL: Router admin password is SuperSecretPass!2026",
		"is_internal": true,
	}, nil)

	// Create Ticket in Org B
	var ticketB Ticket
	bAdmin.mustJSON("POST", "/api/tickets", map[string]any{
		"subject":         "Beta Printer Issue",
		"description":     "Paper jam",
		"requester_name":  "Bob Beta",
		"requester_email": "bob@beta.example",
		"org_id":          orgB.ID,
		"priority":        "low",
	}, &ticketB)

	// 1. Technician scoped strictly to Org B cannot see Ticket A
	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_beta",
		"password":  "BetaPass123!",
		"role":      "tech",
		"org_scope": []string{orgB.ID},
	}, nil)

	bTechB := newBrowser(t, ts)
	bTechB.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_beta",
		"password": "BetaPass123!",
	}, nil)

	var ticketsSeen []Ticket
	bTechB.mustJSON("GET", "/api/tickets", nil, &ticketsSeen)
	for _, tk := range ticketsSeen {
		if tk.ID == ticketA.ID {
			t.Fatalf("VULN-006 failure: technician scoped to Org B saw Ticket A in listing")
		}
	}

	st, _ := bTechB.do("GET", fmt.Sprintf("/api/tickets/%d", ticketA.ID), nil)
	if st != http.StatusNotFound {
		t.Fatalf("VULN-006 failure: technician scoped to Org B accessed Ticket A with status %d", st)
	}

	// 2. Read-only viewer in Org A can view Ticket A, but internal comments must be redacted
	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "viewer_alpha",
		"password":  "ViewerPass123!",
		"role":      "viewer",
		"org_scope": []string{orgA.ID},
	}, nil)

	bViewerA := newBrowser(t, ts)
	bViewerA.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "viewer_alpha",
		"password": "ViewerPass123!",
	}, nil)

	var ticketDetail TicketWithComments
	bViewerA.mustJSON("GET", fmt.Sprintf("/api/tickets/%d", ticketA.ID), nil, &ticketDetail)
	for _, c := range ticketDetail.Comments {
		if c.IsInternal || strings.Contains(c.Body, "SuperSecretPass!2026") {
			t.Fatalf("VULN-006 failure: viewer received internal confidential comment: %s", c.Body)
		}
	}
}

// TestSecurityAudit_Review_TicketUpdatePreservesFields verifies that partial updates
// to a ticket do not wipe org_id, site_id, or agent_id, which would lock out scoped techs.
func TestSecurityAudit_Review_TicketUpdatePreservesFields(t *testing.T) {
	_, ts, bAdmin := newTestServer(t)

	var orgA Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Client Alpha"}, &orgA)

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_scoped",
		"password":  "ScopedPass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	var tk Ticket
	bAdmin.mustJSON("POST", "/api/tickets", map[string]any{
		"subject":         "Issue 1",
		"description":     "Detailed desc",
		"org_id":          orgA.ID,
		"priority":        "high",
		"requester_phone": "555-1234",
	}, &tk)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_scoped",
		"password": "ScopedPass123!",
	}, nil)

	// Partial update changing only status
	var updated Ticket
	bTech.mustJSON("PUT", fmt.Sprintf("/api/tickets/%d", tk.ID), map[string]string{
		"status": "in_progress",
	}, &updated)

	if updated.OrgID != orgA.ID {
		t.Fatalf("partial update wiped org_id: got %q, want %q", updated.OrgID, orgA.ID)
	}
	if updated.RequesterPhone != "555-1234" {
		t.Fatalf("partial update wiped requester_phone: got %q", updated.RequesterPhone)
	}

	// Tech must still be able to read the ticket
	var readBack TicketWithComments
	bTech.mustJSON("GET", fmt.Sprintf("/api/tickets/%d", tk.ID), nil, &readBack)
	if readBack.Ticket.Status != "in_progress" {
		t.Fatalf("unexpected status: %s", readBack.Ticket.Status)
	}
}

// TestSecurityAudit_Review_AlertsAndPatchesScoping verifies that scoped techs cannot view
// or resolve alerts/patches belonging to other organizations.
func TestSecurityAudit_Review_AlertsAndPatchesScoping(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org A"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org B"}, &orgB)

	nowSec := now()
	agentA := "ag_a_sc"
	agentB := "ag_b_sc"

	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-a', 'Box A', 'linux', 'Ubuntu', 'amd64', 'test', 'hash1', ?, ?, ?, ?)`, agentA, nowSec, nowSec, orgA.ID, "site_default")
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-b', 'Box B', 'linux', 'Ubuntu', 'amd64', 'test', 'hash2', ?, ?, ?, ?)`, agentB, nowSec, nowSec, orgB.ID, "site_default")

	// Insert alerts (rule_id omitted to avoid FK constraint)
	if _, err := s.db.Exec(`INSERT INTO alerts(agent_id, severity, title, status, opened_at) VALUES(?, 'warning', 'Disk full A', 'open', ?)`, agentA, nowSec); err != nil {
		t.Fatalf("insert alert A: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO alerts(agent_id, severity, title, status, opened_at) VALUES(?, 'critical', 'Disk full B', 'open', ?)`, agentB, nowSec); err != nil {
		t.Fatalf("insert alert B: %v", err)
	}

	// Insert patches
	if _, err := s.db.Exec(`INSERT INTO patches(agent_id, patch_id, title, status, severity, first_seen, last_seen) VALUES(?, 'KB100', 'Patch A', 'available', 'critical', ?, ?)`, agentA, nowSec, nowSec); err != nil {
		t.Fatalf("insert patch A: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO patches(agent_id, patch_id, title, status, severity, first_seen, last_seen) VALUES(?, 'KB200', 'Patch B', 'available', 'critical', ?, ?)`, agentB, nowSec, nowSec); err != nil {
		t.Fatalf("insert patch B: %v", err)
	}

	// Technician scoped only to Org A
	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_org_a",
		"password":  "OrgAPass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTechA := newBrowser(t, ts)
	bTechA.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_org_a",
		"password": "OrgAPass123!",
	}, nil)

	// 1. Alerts listing must not include Org B's alert
	var alerts []Alert
	bTechA.mustJSON("GET", "/api/alerts", nil, &alerts)
	for _, al := range alerts {
		if al.AgentID == agentB {
			t.Fatalf("cross-tenant alert leakage: tech in Org A saw alert for Agent B")
		}
	}

	// 2. Patches listing must not include Org B's patch
	var patches []Patch
	bTechA.mustJSON("GET", "/api/patches", nil, &patches)
	for _, p := range patches {
		if p.AgentID == agentB {
			t.Fatalf("cross-tenant patch leakage: tech in Org A saw patch for Agent B")
		}
	}

	// 3. Patch status mutation for Org B must not apply
	bTechA.do("POST", "/api/patches/status", map[string]any{
		"items":  []map[string]string{{"agent_id": agentB, "patch_id": "KB200"}},
		"status": "approved",
	})
	var patchBStatus string
	s.db.QueryRow(`SELECT status FROM patches WHERE agent_id = ? AND patch_id = ?`, agentB, "KB200").Scan(&patchBStatus)
	if patchBStatus != "available" {
		t.Fatalf("cross-tenant patch mutation succeeded: status is %q, want 'available'", patchBStatus)
	}

	// 4. Dashboard must only reflect Org A metrics
	var dash map[string]any
	bTechA.mustJSON("GET", "/api/dashboard", nil, &dash)
	if openAl, ok := dash["open_alerts"].(float64); !ok || openAl > 1 {
		t.Fatalf("dashboard leaked alert counts: open_alerts = %v", dash["open_alerts"])
	}
}

// TestSecurityAudit_VULN007_TaskTargetScoping verifies that scoped technicians
// cannot create, run, update, or delete scheduled tasks targeting devices or orgs
// outside their assigned scope (VULN-007 fix).
func TestSecurityAudit_VULN007_TaskTargetScoping(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org A"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org B"}, &orgB)

	nowSec := now()
	agentA := "ag_task_a"
	agentB := "ag_task_b"
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-a', 'Box A', 'linux', 'Ubuntu', 'amd64', 'test', 'hash1', ?, ?, ?, ?)`, agentA, nowSec, nowSec, orgA.ID, "site_default")
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-b', 'Box B', 'linux', 'Ubuntu', 'amd64', 'test', 'hash2', ?, ?, ?, ?)`, agentB, nowSec, nowSec, orgB.ID, "site_default")

	var sc Script
	bAdmin.mustJSON("POST", "/api/scripts", Script{Name: "test-task-script", Language: "bash", Body: "echo task"}, &sc)

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_task_a",
		"password":  "TaskPass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_task_a",
		"password": "TaskPass123!",
	}, nil)

	// 1. Scoped tech cannot create task with targets.all = true
	st, _ := bTech.do("POST", "/api/tasks", map[string]any{
		"name": "Global Task", "kind": "script", "script_id": sc.ID,
		"targets": Targets{All: true},
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-007 failure: scoped tech created global task: status %d", st)
	}

	// 2. Scoped tech cannot target agent in Org B
	st, _ = bTech.do("POST", "/api/tasks", map[string]any{
		"name": "Cross Org Task", "kind": "script", "script_id": sc.ID,
		"targets": Targets{Agents: []string{agentB}},
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-007 failure: scoped tech targeted agent in Org B: status %d", st)
	}

	// 3. Scoped tech cannot target Org B
	st, _ = bTech.do("POST", "/api/tasks", map[string]any{
		"name": "Org B Task", "kind": "script", "script_id": sc.ID,
		"targets": Targets{Organizations: []string{orgB.ID}},
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-007 failure: scoped tech targeted Org B: status %d", st)
	}

	// 4. Admin creates task targeting Org B
	var taskB Task
	bAdmin.mustJSON("POST", "/api/tasks", map[string]any{
		"name": "Admin Org B Task", "kind": "script", "script_id": sc.ID,
		"targets": Targets{Organizations: []string{orgB.ID}},
	}, &taskB)

	// Scoped tech cannot see task B in list
	var list []Task
	bTech.mustJSON("GET", "/api/tasks", nil, &list)
	for _, tk := range list {
		if tk.ID == taskB.ID {
			t.Fatalf("VULN-007 failure: tech in Org A saw task for Org B")
		}
	}

	// Scoped tech cannot run task B
	st, _ = bTech.do("POST", fmt.Sprintf("/api/tasks/%d/run", taskB.ID), nil)
	if st != http.StatusForbidden {
		t.Fatalf("VULN-007 failure: tech in Org A ran task for Org B: status %d", st)
	}

	// Scoped tech cannot update task B
	st, _ = bTech.do("PUT", fmt.Sprintf("/api/tasks/%d", taskB.ID), map[string]any{"name": "Hijacked"})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-007 failure: tech in Org A updated task for Org B: status %d", st)
	}

	// Scoped tech cannot delete task B
	st, _ = bTech.do("DELETE", fmt.Sprintf("/api/tasks/%d", taskB.ID), nil)
	if st != http.StatusForbidden {
		t.Fatalf("VULN-007 failure: tech in Org A deleted task for Org B: status %d", st)
	}

	// 5. Scoped tech CAN create task targeting Org A
	var taskA Task
	bTech.mustJSON("POST", "/api/tasks", map[string]any{
		"name": "Org A Task", "kind": "script", "script_id": sc.ID,
		"targets": Targets{Organizations: []string{orgA.ID}},
	}, &taskA)
	if taskA.ID == 0 {
		t.Fatalf("scoped tech failed to create legitimate task targeting Org A")
	}
}

// TestSecurityAudit_VULN008_VULN011_AdminOnlyRoutes verifies that non-admin technicians
// cannot access /api/automations or dispatch updates to all agents (VULN-008 & VULN-011 fix).
func TestSecurityAudit_VULN008_VULN011_AdminOnlyRoutes(t *testing.T) {
	_, ts, bAdmin := newTestServer(t)

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username": "tech_general",
		"password": "TechPassword123!",
		"role":     "tech",
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_general",
		"password": "TechPassword123!",
	}, nil)

	// VULN-011: POST /api/agents/update-all requires admin
	st, _ := bTech.do("POST", "/api/agents/update-all", nil)
	if st != http.StatusForbidden {
		t.Fatalf("VULN-011 failure: non-admin called update-all; status %d", st)
	}

	// VULN-008: /api/automations routes require admin
	st, _ = bTech.do("GET", "/api/automations", nil)
	if st != http.StatusForbidden {
		t.Fatalf("VULN-008 failure: non-admin accessed GET /api/automations; status %d", st)
	}
	st, _ = bTech.do("POST", "/api/automations", map[string]any{
		"name": "auto1", "trigger": "agent_online", "action": "email",
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-008 failure: non-admin created automation; status %d", st)
	}
	st, _ = bTech.do("PUT", "/api/automations/1", map[string]any{"name": "auto-edit"})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-008 failure: non-admin updated automation; status %d", st)
	}
	st, _ = bTech.do("DELETE", "/api/automations/1", nil)
	if st != http.StatusForbidden {
		t.Fatalf("VULN-008 failure: non-admin deleted automation; status %d", st)
	}

	// Admin CAN access both
	st, _ = bAdmin.do("GET", "/api/automations", nil)
	if st != http.StatusOK {
		t.Fatalf("admin could not access GET /api/automations; status %d", st)
	}
	st, _ = bAdmin.do("POST", "/api/agents/update-all", nil)
	if st != http.StatusOK {
		t.Fatalf("admin could not access POST /api/agents/update-all; status %d", st)
	}
}

// TestSecurityAudit_VULN009_BaselineScoping verifies that technicians cannot evaluate,
// preview, or remediate baselines on agents outside their OrgScope (VULN-009 fix).
func TestSecurityAudit_VULN009_BaselineScoping(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org A"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org B"}, &orgB)

	nowSec := now()
	agentA := "ag_base_a"
	agentB := "ag_base_b"
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-a', 'Box A', 'linux', 'Ubuntu', 'amd64', 'test', 'hash1', ?, ?, ?, ?)`, agentA, nowSec, nowSec, orgA.ID, "site_default")
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-b', 'Box B', 'linux', 'Ubuntu', 'amd64', 'test', 'hash2', ?, ?, ?, ?)`, agentB, nowSec, nowSec, orgB.ID, "site_default")

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_base_a",
		"password":  "BasePass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_base_a",
		"password": "BasePass123!",
	}, nil)

	var b Baseline
	bAdmin.mustJSON("POST", "/api/baselines", map[string]any{
		"name": "Audit Baseline", "targets": Targets{All: true},
		"enabled": true,
		"checks":  []map[string]any{{"name": "c1", "kind": "service", "severity": "warning", "params": map[string]any{"name": "ssh", "state": "running"}}},
	}, &b)

	// 1. Preview targeting agent in Org B: status must be error with unknown device
	var prevRes struct {
		Devices []struct {
			AgentID string `json:"agent_id"`
			Status  string `json:"status"`
			Error   string `json:"error"`
		} `json:"devices"`
	}
	bTech.mustJSON("POST", "/api/baselines/preview", map[string]any{
		"spec": map[string]any{
			"name": "preview-test",
			"checks": []map[string]any{{"name": "c1", "kind": "service", "severity": "warning", "params": map[string]any{"name": "ssh", "state": "running"}}},
		},
		"agent_ids": []string{agentB},
	}, &prevRes)
	if len(prevRes.Devices) > 0 && prevRes.Devices[0].Status != "error" {
		t.Fatalf("VULN-009 failure: preview ran on agent B outside org scope: status=%s", prevRes.Devices[0].Status)
	}

	// 2. Evaluate targeting agent in Org B: status must be error
	var evalRes struct {
		Agents []struct {
			AgentID string `json:"agent_id"`
			Status  string `json:"status"`
			Error   string `json:"error"`
		} `json:"agents"`
	}
	bTech.mustJSON("POST", fmt.Sprintf("/api/baselines/%d/evaluate", b.ID), map[string]any{
		"agent_ids": []string{agentB},
	}, &evalRes)
	if len(evalRes.Agents) > 0 && evalRes.Agents[0].Status != "error" {
		t.Fatalf("VULN-009 failure: evaluate ran on agent B outside org scope: status=%s", evalRes.Agents[0].Status)
	}

	// 3. Remediate targeting agent in Org B: must return 404
	st, _ := bTech.do("POST", fmt.Sprintf("/api/baselines/%d/remediate", b.ID), map[string]any{
		"agent_id": agentB,
	})
	if st != http.StatusNotFound {
		t.Fatalf("VULN-009 failure: remediate on agent B returned %d, want 404", st)
	}
}

// TestSecurityAudit_VULN010_AgentOrgSiteTampering verifies that non-admin technicians
// cannot reassign an agent's OrgID or SiteID via PATCH /api/agents/{id} (VULN-010 fix).
func TestSecurityAudit_VULN010_AgentOrgSiteTampering(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org A"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org B"}, &orgB)

	nowSec := now()
	agentA := "ag_tamper_a"
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-a', 'Box A', 'linux', 'Ubuntu', 'amd64', 'test', 'hash1', ?, ?, ?, ?)`, agentA, nowSec, nowSec, orgA.ID, "site_default")

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_tamper",
		"password":  "TamperPass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_tamper",
		"password": "TamperPass123!",
	}, nil)

	// 1. Scoped tech attempts to change agent's org_id -> 403 Forbidden
	st, _ := bTech.do("PATCH", "/api/agents/"+agentA, map[string]any{"org_id": orgB.ID})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-010 failure: tech changed org_id: status %d", st)
	}

	// 2. Scoped tech attempts to change agent's site_id -> 403 Forbidden
	st, _ = bTech.do("PATCH", "/api/agents/"+agentA, map[string]any{"site_id": "site_new"})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-010 failure: tech changed site_id: status %d", st)
	}

	// 3. Scoped tech CAN change display_name
	st, _ = bTech.do("PATCH", "/api/agents/"+agentA, map[string]any{"display_name": "New Box A"})
	if st != http.StatusOK {
		t.Fatalf("tech failed to update display_name: status %d", st)
	}

	// 4. Admin CAN change org_id
	st, _ = bAdmin.do("PATCH", "/api/agents/"+agentA, map[string]any{"org_id": orgB.ID})
	if st != http.StatusOK {
		t.Fatalf("admin failed to change org_id: status %d", st)
	}
}

// TestSecurityAudit_VULN012_PortalRunInspection verifies that a device-authenticated
// portal caller cannot inspect arbitrary administrative runs on the device (VULN-012 fix).
func TestSecurityAudit_VULN012_PortalRunInspection(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	var orgA Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org A"}, &orgA)

	nowSec := now()
	agentID := "ag_portal_run"
	agentKey := "agent_key_portal_123"
	keyHash := hashKey(agentKey)
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'portal-box', 'Portal Box', 'linux', 'Ubuntu', 'amd64', 'test', ?, ?, ?, ?, ?)`, agentID, keyHash, nowSec, nowSec, orgA.ID, "site_default")

	adminRunID := "run_secret_admin"
	s.db.Exec(`INSERT INTO script_runs(id, agent_id, script_name, stdout, stderr, exit_code, status, started_at, run_by, trigger)
		VALUES(?, ?, 'dump-secrets', 'root:$6$secret...', '', 0, 'success', ?, 'admin', 'manual')`,
		adminRunID, agentID, nowSec)

	portalRunID := "run_portal_app"
	s.db.Exec(`INSERT INTO script_runs(id, agent_id, script_name, stdout, stderr, exit_code, status, started_at, run_by, trigger)
		VALUES(?, ?, 'install-vlc', 'Done', '', 0, 'success', ?, 'user', 'client-portal')`,
		portalRunID, agentID, nowSec)

	bDevice := portalBrowser(t, ts.URL, agentKey, "alice", true)

	// 1. Portal user attempting to inspect the admin run -> 404 Not Found
	st, body := bDevice.do("GET", "/api/portal/runs/"+adminRunID, nil)
	if st != http.StatusNotFound {
		t.Fatalf("VULN-012 failure: device portal inspected admin run %s: status %d body %s", adminRunID, st, body)
	}

	// 2. Portal user inspecting legitimate client-portal run -> 200 OK
	st, _ = bDevice.do("GET", "/api/portal/runs/"+portalRunID, nil)
	if st != http.StatusOK {
		t.Fatalf("device portal failed to inspect client-portal run: status %d", st)
	}
}

// TestSecurityAudit_VULN013_ServerSideScanAdmin verifies that server-side network scans
// (where agent_id is omitted) require administrator privileges (VULN-013 fix).
func TestSecurityAudit_VULN013_ServerSideScanAdmin(t *testing.T) {
	_, ts, bAdmin := newTestServer(t)

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username": "tech_scan",
		"password": "ScanPassword123!",
		"role":     "tech",
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_scan",
		"password": "ScanPassword123!",
	}, nil)

	// 1. Tech attempting server-side network scan (omitting agent_id) -> 403 Forbidden
	st, body := bTech.do("POST", "/api/network-scans", map[string]any{
		"subnet": "192.168.1.0/24",
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-013 failure: non-admin triggered server-side scan: status %d, body %s", st, body)
	}

	// 2. Admin CAN trigger server-side scan -> 202 Accepted
	st, _ = bAdmin.do("POST", "/api/network-scans", map[string]any{
		"subnet": "192.168.1.0/24",
	})
	if st != http.StatusAccepted {
		t.Fatalf("admin failed to trigger server-side scan: status %d", st)
	}
}

// TestSecurityAudit_VULN014_SSEStreamTenantIsolation verifies that the GET /api/events
// stream isolates events by tenant org scope (VULN-014 fix).
func TestSecurityAudit_VULN014_SSEStreamTenantIsolation(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org A"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org B"}, &orgB)

	nowSec := now()
	agentA := "ag_sse_a"
	agentB := "ag_sse_b"
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-a', 'Box A', 'linux', 'Ubuntu', 'amd64', 'test', 'hash1', ?, ?, ?, ?)`, agentA, nowSec, nowSec, orgA.ID, "site_default")
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-b', 'Box B', 'linux', 'Ubuntu', 'amd64', 'test', 'hash2', ?, ?, ?, ?)`, agentB, nowSec, nowSec, orgB.ID, "site_default")

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_sse_a",
		"password":  "SSEPass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_sse_a",
		"password": "SSEPass123!",
	}, nil)

	req, _ := http.NewRequest("GET", ts.URL+"/api/events", nil)
	resp, err := bTech.c.Do(req)
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	defer resp.Body.Close()

	time.Sleep(50 * time.Millisecond)

	s.hub.broadcast(hubEvent{Kind: "event", AgentID: agentB, Data: map[string]any{"msg": "LEAK_SECRET_B"}})
	s.hub.broadcast(hubEvent{Kind: "event", AgentID: agentA, Data: map[string]any{"msg": "LEGIT_EVENT_A"}})

	buf := make([]byte, 4096)
	nChan := make(chan int, 1)
	errChan := make(chan error, 1)
	go func() {
		n, err := resp.Body.Read(buf)
		if err != nil {
			errChan <- err
			return
		}
		nChan <- n
	}()

	select {
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE event")
	case n := <-nChan:
		streamData := string(buf[:n])
		if strings.Contains(streamData, "LEAK_SECRET_B") {
			t.Fatalf("VULN-014 failure: tenant scoped to Org A received SSE event for Org B: %s", streamData)
		}
		if !strings.Contains(streamData, "LEGIT_EVENT_A") {
			n2, _ := resp.Body.Read(buf[n:])
			totalData := string(buf[:n+n2])
			if strings.Contains(totalData, "LEAK_SECRET_B") {
				t.Fatalf("VULN-014 failure: tenant scoped to Org A received SSE event for Org B: %s", totalData)
			}
			if !strings.Contains(totalData, "LEGIT_EVENT_A") {
				t.Fatalf("expected to receive Org A event in SSE stream, got: %s", totalData)
			}
		}
	}
}

// TestSecurityAudit_VULN015_PatchPolicyTargetScoping verifies that scoped technicians
// cannot create, update, or delete patch policies targeting devices outside their scope (VULN-015 fix).
func TestSecurityAudit_VULN015_PatchPolicyTargetScoping(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org A"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org B"}, &orgB)

	nowSec := now()
	agentA := "ag_pol_a"
	agentB := "ag_pol_b"
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-a', 'Box A', 'linux', 'Ubuntu', 'amd64', 'test', 'hash1', ?, ?, ?, ?)`, agentA, nowSec, nowSec, orgA.ID, "site_default")
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-b', 'Box B', 'linux', 'Ubuntu', 'amd64', 'test', 'hash2', ?, ?, ?, ?)`, agentB, nowSec, nowSec, orgB.ID, "site_default")

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_pol_a",
		"password":  "PolPass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_pol_a",
		"password": "PolPass123!",
	}, nil)

	// 1. Scoped tech cannot create patch policy with targets.all = true
	st, _ := bTech.do("POST", "/api/patch-policies", map[string]any{
		"name": "Global Policy", "targets": Targets{All: true},
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-015 failure: scoped tech created global patch policy: status %d", st)
	}

	// 2. Scoped tech cannot target agent in Org B
	st, _ = bTech.do("POST", "/api/patch-policies", map[string]any{
		"name": "Cross Org Policy", "targets": Targets{Agents: []string{agentB}},
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-015 failure: scoped tech targeted agent B: status %d", st)
	}

	// 3. Admin creates policy targeting Org B
	var polB PatchPolicy
	bAdmin.mustJSON("POST", "/api/patch-policies", map[string]any{
		"name": "Org B Policy", "targets": Targets{Organizations: []string{orgB.ID}},
	}, &polB)

	// Scoped tech cannot see policy B in list
	var list []PatchPolicy
	bTech.mustJSON("GET", "/api/patch-policies", nil, &list)
	for _, p := range list {
		if p.ID == polB.ID {
			t.Fatalf("VULN-015 failure: tech in Org A saw patch policy for Org B")
		}
	}

	// Scoped tech cannot update policy B
	st, _ = bTech.do("PUT", fmt.Sprintf("/api/patch-policies/%d", polB.ID), map[string]any{"name": "Hijacked Policy"})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-015 failure: tech in Org A updated patch policy for Org B: status %d", st)
	}

	// Scoped tech cannot delete policy B
	st, _ = bTech.do("DELETE", fmt.Sprintf("/api/patch-policies/%d", polB.ID), nil)
	if st != http.StatusForbidden {
		t.Fatalf("VULN-015 failure: tech in Org A deleted patch policy for Org B: status %d", st)
	}

	// 4. Scoped tech CAN create policy targeting Org A
	var polA PatchPolicy
	bTech.mustJSON("POST", "/api/patch-policies", map[string]any{
		"name": "Org A Policy", "targets": Targets{Organizations: []string{orgA.ID}},
	}, &polA)
	if polA.ID == 0 {
		t.Fatalf("scoped tech failed to create legitimate patch policy targeting Org A")
	}
}

// TestSecurityAudit_VULN016_AlertRuleTargetScoping verifies that scoped technicians
// cannot create, update, or delete alert rules targeting devices outside their scope (VULN-016 fix).
func TestSecurityAudit_VULN016_AlertRuleTargetScoping(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org A"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Org B"}, &orgB)

	nowSec := now()
	agentA := "ag_alert_a"
	agentB := "ag_alert_b"
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-a', 'Box A', 'linux', 'Ubuntu', 'amd64', 'test', 'hash1', ?, ?, ?, ?)`, agentA, nowSec, nowSec, orgA.ID, "site_default")
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-b', 'Box B', 'linux', 'Ubuntu', 'amd64', 'test', 'hash2', ?, ?, ?, ?)`, agentB, nowSec, nowSec, orgB.ID, "site_default")

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_alert_a",
		"password":  "AlertPass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_alert_a",
		"password": "AlertPass123!",
	}, nil)

	// 1. Scoped tech cannot create alert rule with targets.all = true
	st, _ := bTech.do("POST", "/api/alert-rules", map[string]any{
		"name": "Global Alert Rule", "kind": "offline", "targets": Targets{All: true},
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-016 failure: scoped tech created global alert rule: status %d", st)
	}

	// 2. Scoped tech cannot target agent in Org B
	st, _ = bTech.do("POST", "/api/alert-rules", map[string]any{
		"name": "Cross Org Rule", "kind": "offline", "targets": Targets{Agents: []string{agentB}},
	})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-016 failure: scoped tech targeted agent B in alert rule: status %d", st)
	}

	// 3. Admin creates rule targeting Org B
	var ruleB AlertRule
	bAdmin.mustJSON("POST", "/api/alert-rules", map[string]any{
		"name": "Org B Alert Rule", "kind": "offline", "targets": Targets{Organizations: []string{orgB.ID}},
	}, &ruleB)

	// Scoped tech cannot see rule B in list
	var list []AlertRule
	bTech.mustJSON("GET", "/api/alert-rules", nil, &list)
	for _, r := range list {
		if r.ID == ruleB.ID {
			t.Fatalf("VULN-016 failure: tech in Org A saw alert rule for Org B")
		}
	}

	// Scoped tech cannot update rule B
	st, _ = bTech.do("PUT", fmt.Sprintf("/api/alert-rules/%d", ruleB.ID), map[string]any{"name": "Hijacked Rule"})
	if st != http.StatusForbidden {
		t.Fatalf("VULN-016 failure: tech in Org A updated alert rule for Org B: status %d", st)
	}

	// Scoped tech cannot delete rule B
	st, _ = bTech.do("DELETE", fmt.Sprintf("/api/alert-rules/%d", ruleB.ID), nil)
	if st != http.StatusForbidden {
		t.Fatalf("VULN-016 failure: tech in Org A deleted alert rule for Org B: status %d", st)
	}

	// 4. Scoped tech CAN create rule targeting Org A
	var ruleA AlertRule
	bTech.mustJSON("POST", "/api/alert-rules", map[string]any{
		"name": "Org A Rule", "kind": "offline", "targets": Targets{Organizations: []string{orgA.ID}},
	}, &ruleA)
	if ruleA.ID == 0 {
		t.Fatalf("scoped tech failed to create legitimate alert rule targeting Org A")
	}
}

// TestSecurityAudit_VULN007_TaskTagBypassAndDynamicFleet verifies that scoped technicians
// cannot bypass organization scoping using tags/groups combined with specific agents,
// and that dynamic fleet tag assignments never cause a task to execute on out-of-scope devices.
func TestSecurityAudit_VULN007_TaskTagBypassAndDynamicFleet(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	var orgA, orgB Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Fleet Org A"}, &orgA)
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Fleet Org B"}, &orgB)

	nowSec := now()
	agentA := "ag_dyn_a"
	agentB := "ag_dyn_b"
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-a', 'Box A', 'linux', 'Ubuntu', 'amd64', 'test', 'hash1', ?, ?, ?, ?)`, agentA, nowSec, nowSec, orgA.ID, "site_default")
	s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'box-b', 'Box B', 'linux', 'Ubuntu', 'amd64', 'test', 'hash2', ?, ?, ?, ?)`, agentB, nowSec, nowSec, orgB.ID, "site_default")

	var sc Script
	bAdmin.mustJSON("POST", "/api/scripts", Script{Name: "fleet-script", Language: "bash", Body: "echo fleet"}, &sc)

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_fleet_a",
		"password":  "FleetPass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_fleet_a",
		"password": "FleetPass123!",
	}, nil)

	// 1. Scoped tech attempting to use tags without specifying Organizations or Sites must be 403 Forbidden
	st, body := bTech.do("POST", "/api/tasks", map[string]any{
		"name": "Tag Bypass Task", "kind": "script", "script_id": sc.ID,
		"targets": Targets{Agents: []string{agentA}, Tags: []string{"web"}},
	})
	if st != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when specifying tags without organization scope, got %d (body: %s)", st, body)
	}

	// 2. Scoped tech attempting to use groups without specifying Organizations or Sites must be 403 Forbidden
	st, body = bTech.do("POST", "/api/tasks", map[string]any{
		"name": "Group Bypass Task", "kind": "script", "script_id": sc.ID,
		"targets": Targets{Agents: []string{agentA}, Groups: []int64{1}},
	})
	if st != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when specifying groups without organization scope, got %d (body: %s)", st, body)
	}

	// 3. Scoped tech creating task with explicit organization scope succeeds
	var legitTask Task
	bTech.mustJSON("POST", "/api/tasks", map[string]any{
		"name": "Legit Scoped Task", "kind": "script", "script_id": sc.ID,
		"targets": Targets{Organizations: []string{orgA.ID}, Tags: []string{"web"}},
	}, &legitTask)
	if legitTask.ID == 0 {
		t.Fatal("failed to create legitimate scoped task")
	}

	// 4. Now tag BOTH Agent A and Agent B with tag 'web'
	bAdmin.mustJSON("PATCH", "/api/agents/"+agentA, map[string]any{"tags": []string{"web"}}, nil)
	bAdmin.mustJSON("PATCH", "/api/agents/"+agentB, map[string]any{"tags": []string{"web"}}, nil)

	// Verify ResolveTargets for legitTask ONLY matches Agent A, never Agent B
	matchedAgents, err := s.db.ResolveTargets(legitTask.Targets)
	if err != nil {
		t.Fatalf("ResolveTargets error: %v", err)
	}
	for _, m := range matchedAgents {
		if m.ID == agentB {
			t.Fatalf("CRITICAL: dynamic fleet change caused Org A task to match Agent B in Org B!")
		}
	}
	if len(matchedAgents) != 1 || matchedAgents[0].ID != agentA {
		t.Fatalf("expected only agent A to match, got %d agents", len(matchedAgents))
	}
}

// TestSecurityAudit_VULN015_VULN016_TagBypassPrevention verifies that patch policies and
// alert rules reject tag/group selectors that omit organization or site scoping.
func TestSecurityAudit_VULN015_VULN016_TagBypassPrevention(t *testing.T) {
	_, ts, bAdmin := newTestServer(t)

	var orgA Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Tag Org A"}, &orgA)

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_tag_a",
		"password":  "TagPass123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_tag_a",
		"password": "TagPass123!",
	}, nil)

	// 1. Patch policy with tags but no organization/site -> 403 Forbidden
	st, body := bTech.do("POST", "/api/patch-policies", map[string]any{
		"name":    "Tag Bypass Policy",
		"targets": Targets{Tags: []string{"servers"}},
	})
	if st != http.StatusForbidden {
		t.Fatalf("expected 403 for patch policy tags without org scope, got %d (body: %s)", st, body)
	}

	// 2. Alert rule with tags but no organization/site -> 403 Forbidden
	st, body = bTech.do("POST", "/api/alert-rules", map[string]any{
		"name":    "Tag Bypass Rule",
		"kind":    "offline",
		"targets": Targets{Tags: []string{"servers"}},
	})
	if st != http.StatusForbidden {
		t.Fatalf("expected 403 for alert rule tags without org scope, got %d (body: %s)", st, body)
	}
}

// TestSecurityAudit_VULN014_UnscopedAgentEventsDropped verifies that agent-level SSE events
// missing both AgentID and OrgID are never delivered to scoped non-admin users.
func TestSecurityAudit_VULN014_UnscopedAgentEventsDropped(t *testing.T) {
	s, ts, bAdmin := newTestServer(t)

	var orgA Organization
	bAdmin.mustJSON("POST", "/api/organizations", map[string]string{"name": "SSE Leak Org"}, &orgA)

	bAdmin.mustJSON("POST", "/api/users", map[string]any{
		"username":  "tech_sse_leak",
		"password":  "SSEPassLeak123!",
		"role":      "tech",
		"org_scope": []string{orgA.ID},
	}, nil)

	bTech := newBrowser(t, ts)
	bTech.mustJSON("POST", "/api/auth/login", map[string]string{
		"username": "tech_sse_leak",
		"password": "SSEPassLeak123!",
	}, nil)

	req, _ := http.NewRequest("GET", ts.URL+"/api/events", nil)
	resp, err := bTech.c.Do(req)
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	defer resp.Body.Close()

	time.Sleep(50 * time.Millisecond)

	// Broadcast an event without AgentID or OrgID containing a sensitive secret
	s.hub.broadcast(hubEvent{Kind: "event", Data: map[string]any{"msg": "UNSCOPED_SECRET_LEAK"}})
	// Broadcast legitimate Org A event
	s.hub.broadcast(hubEvent{Kind: "event", OrgID: orgA.ID, Data: map[string]any{"msg": "LEGIT_ORG_A_EVENT"}})

	buf := make([]byte, 4096)
	nChan := make(chan int, 1)
	errChan := make(chan error, 1)
	go func() {
		n, err := resp.Body.Read(buf)
		if err != nil {
			errChan <- err
			return
		}
		nChan <- n
	}()

	select {
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE stream")
	case n := <-nChan:
		streamData := string(buf[:n])
		if strings.Contains(streamData, "UNSCOPED_SECRET_LEAK") {
			t.Fatalf("VULN-014 failure: scoped tech received unscoped agent event: %s", streamData)
		}
		if !strings.Contains(streamData, "LEGIT_ORG_A_EVENT") {
			n2, _ := resp.Body.Read(buf[n:])
			totalData := string(buf[:n+n2])
			if strings.Contains(totalData, "UNSCOPED_SECRET_LEAK") {
				t.Fatalf("VULN-014 failure: scoped tech received unscoped agent event: %s", totalData)
			}
			if !strings.Contains(totalData, "LEGIT_ORG_A_EVENT") {
				t.Fatalf("expected legitimate Org A event in SSE stream, got: %s", totalData)
			}
		}
	}
}


