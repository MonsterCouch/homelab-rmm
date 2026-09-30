package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// portalSession signs a device user in to the portal directly, as a pass
// the device's agent asked for would.
func portalSession(s *Server, agentID, user string, workgroup bool) *http.Cookie {
	tok, _ := s.portal.redeem(s.portal.issuePass(portalIdentity{AgentID: agentID, User: user, IsWorkgroup: workgroup}))
	return &http.Cookie{Name: portalCookie, Value: tok}
}

// portalReq is a portal request carrying a sign-in cookie.
func portalReq(method, url, body string, c *http.Cookie) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, url, nil)
	} else {
		req = httptest.NewRequest(method, url, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Requested-With", "fetch")
	req.AddCookie(c)
	return req
}

// Written along with the portal. It originally proved scoping with
// identities put in the query string, which is the hole portal_auth.go
// closes, so it now signs in the way the portal requires.
func TestPortalEndpointsScopingAndSecurity(t *testing.T) {
	s, _, _ := newTestServer(t)

	// 1. Create an agent with installed software
	agentID := "agent_portal_01"
	orgID := "org_acme"
	nowSec := now()
	if _, err := s.db.Exec(`INSERT INTO organizations(id, name, created_at) VALUES(?, 'Acme', ?)`, orgID, nowSec); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	_, err := s.db.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id, site_id)
		VALUES(?, 'WS-FINANCE-01', 'Finance Workstation', 'windows', 'Windows 11 Enterprise', 'amd64', '1.0.0', 'hash_test', ?, ?, ?, ?)`,
		agentID, nowSec, nowSec, orgID, "site_default")
	if err != nil {
		t.Fatalf("insert agent: %v", err)
	}

	// Save inventory with 7-Zip installed
	err = s.db.saveInventory(agentID, &protocol.Inventory{
		Hostname: "WS-FINANCE-01",
		Software: []protocol.Software{
			{Name: "7-Zip 23.01 (x64)", Version: "23.01", Publisher: "Igor Pavlov"},
		},
	})
	if err != nil {
		t.Fatalf("failed to save inventory: %v", err)
	}

	alice := portalSession(s, agentID, "CORP\\alice", false)

	// 2. Test GET /api/portal/config
	req := portalReq("GET", "/api/portal/config", "", alice)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/portal/config status = %d, want 200", w.Code)
	}
	var cfg PortalConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("unmarshal config response: %v", err)
	}
	if cfg.AgentID != agentID || cfg.OrgID != orgID || cfg.DomainUser != "CORP\\alice" {
		t.Errorf("unexpected config response: %+v", cfg)
	}

	// 3. Test GET /api/portal/software (detects 7-Zip installed)
	req = portalReq("GET", "/api/portal/software", "", alice)
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/portal/software status = %d, want 200", w.Code)
	}
	var swList []PortalSoftwareItem
	if err := json.Unmarshal(w.Body.Bytes(), &swList); err != nil {
		t.Fatalf("unmarshal software response: %v", err)
	}
	found7Zip := false
	for _, it := range swList {
		if it.Name == "7-Zip" {
			found7Zip = true
			if !it.Installed {
				t.Errorf("expected 7-Zip to be installed on agent")
			}
			if it.InstalledVersion != "23.01" {
				t.Errorf("got installed version %s, want 23.01", it.InstalledVersion)
			}
		}
	}
	if !found7Zip {
		t.Errorf("7-Zip catalog item not returned")
	}

	// 4. Create Tickets: One user ticket, one domain user ticket, one automated internal ticket
	userTicket, err := s.db.CreateTicket(&Ticket{
		AgentID:             agentID,
		OrgID:               orgID,
		Subject:             "Alice Keyboard Broken",
		Description:         "Keys sticking",
		RequesterName:       "Alice Smith",
		RequesterEmail:      "alice@corp.lan",
		RequesterDomainUser: "CORP\\alice",
		IsInternal:          false,
		Source:              "portal",
	})
	if err != nil {
		t.Fatalf("create user ticket: %v", err)
	}

	bobTicket, err := s.db.CreateTicket(&Ticket{
		AgentID:             agentID,
		OrgID:               orgID,
		Subject:             "Bob Printer Issue",
		Description:         "Printer offline",
		RequesterName:       "Bob Jones",
		RequesterEmail:      "bob@corp.lan",
		RequesterDomainUser: "CORP\\bob",
		IsInternal:          false,
		Source:              "portal",
	})
	if err != nil {
		t.Fatalf("create bob ticket: %v", err)
	}

	internalTicket, err := s.db.CreateTicket(&Ticket{
		AgentID:     agentID,
		OrgID:       orgID,
		Subject:     "Automated Alert: CPU Drift",
		Description: "CPU spike threshold exceeded",
		IsInternal:  true,
		Source:      "alert",
	})
	if err != nil {
		t.Fatalf("create internal ticket: %v", err)
	}

	// Add comments to Alice's ticket: 1 public, 1 internal technician note
	s.db.CreateTicketComment(&TicketComment{
		TicketID:   userTicket.ID,
		Author:     "Tech John",
		IsInternal: false,
		Body:       "We have ordered a replacement keyboard.",
	})
	s.db.CreateTicketComment(&TicketComment{
		TicketID:   userTicket.ID,
		Author:     "Tech John",
		IsInternal: true,
		Body:       "INTERNAL NOTE: User spilled coffee. Do not bill hardware warranty.",
	})

	// 5. Test Scoping for Domain User Alice:
	req = portalReq("GET", "/api/portal/tickets", "", alice)
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/portal/tickets status = %d, want 200", w.Code)
	}
	var aliceTickets []Ticket
	if err := json.Unmarshal(w.Body.Bytes(), &aliceTickets); err != nil {
		t.Fatalf("unmarshal tickets: %v", err)
	}
	if len(aliceTickets) != 1 || aliceTickets[0].ID != userTicket.ID {
		t.Errorf("Alice domain user expected 1 ticket (Alice Keyboard), got %d tickets", len(aliceTickets))
	}

	// Verify Alice viewing her ticket: internal comment MUST BE STRIPPED
	req = portalReq("GET", fmt.Sprintf("/api/portal/tickets/%d", userTicket.ID), "", alice)
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/portal/tickets/%d status = %d, want 200", userTicket.ID, w.Code)
	}
	var twc TicketWithComments
	if err := json.Unmarshal(w.Body.Bytes(), &twc); err != nil {
		t.Fatalf("unmarshal ticket detail: %v", err)
	}
	if len(twc.Comments) != 1 {
		t.Fatalf("expected exactly 1 public comment, got %d comments", len(twc.Comments))
	}
	if twc.Comments[0].IsInternal || strings.Contains(twc.Comments[0].Body, "INTERNAL NOTE") {
		t.Errorf("internal technician comment was leaked to client portal!")
	}

	// 6. Verify Alice CANNOT view Bob's ticket (even naming Bob in the query)
	// or the internal alert ticket. Both answer 404 so ticket numbers
	// cannot be probed.
	req = portalReq("GET", fmt.Sprintf("/api/portal/tickets/%d?domain_user=CORP%%5Cbob", bobTicket.ID), "", alice)
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Alice accessing Bob ticket returned status %d, want 404", w.Code)
	}

	req = portalReq("GET", fmt.Sprintf("/api/portal/tickets/%d", internalTicket.ID), "", alice)
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Accessing internal alert ticket returned status %d, want 404", w.Code)
	}

	// 7. Test WORKGROUP scoping:
	// A local account is scoped to the tickets filed from its device.
	req = portalReq("GET", "/api/portal/tickets", "", portalSession(s, agentID, "frontdesk", true))
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("WORKGROUP tickets status = %d, want 200", w.Code)
	}
	var wgTickets []Ticket
	if err := json.Unmarshal(w.Body.Bytes(), &wgTickets); err != nil {
		t.Fatalf("unmarshal wg tickets: %v", err)
	}
	// Should see both Alice and Bob tickets (since both are from this workstation), but NEVER internal alert ticket
	if len(wgTickets) != 2 {
		t.Errorf("WORKGROUP expected 2 non-internal tickets from workstation, got %d", len(wgTickets))
	}
	for _, tk := range wgTickets {
		if tk.IsInternal {
			t.Errorf("internal alert ticket appeared in WORKGROUP tickets!")
		}
	}

	// 8. Test Authorized POC Scoping:
	// Create an Authorized POC user for "org_acme"
	pocUID, err := s.db.CreateUserWithScope("poc_manager", "Password123!", RoleContact, "manager@acme.com", []string{orgID})
	if err != nil {
		t.Fatalf("create POC user: %v", err)
	}
	pocToken, err := s.db.createSession(pocUID, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("create POC session: %v", err)
	}

	req = portalReq("GET", "/api/portal/tickets", "", &http.Cookie{Name: sessionCookie, Value: pocToken})
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POC list tickets status = %d, want 200", w.Code)
	}
	var pocTickets []Ticket
	if err := json.Unmarshal(w.Body.Bytes(), &pocTickets); err != nil {
		t.Fatalf("unmarshal poc tickets: %v", err)
	}
	// POC can see ALL business tickets (Alice & Bob), but NEVER internal alert tickets!
	if len(pocTickets) != 2 {
		t.Errorf("POC expected 2 business tickets, got %d", len(pocTickets))
	}
	for _, tk := range pocTickets {
		if tk.IsInternal {
			t.Errorf("POC saw internal alert ticket! Violation of POC scoping.")
		}
	}

	// 9. Test POST /api/portal/tickets. The requester is whoever is signed
	// in; a requester_domain_user in the body is ignored.
	createBody := `{
		"subject": "Need Headset",
		"description": "Mic not working on Zoom",
		"requester_name": "Charlie",
		"requester_domain_user": "CORP\\ceo",
		"priority": "normal"
	}`
	req = portalReq("POST", "/api/portal/tickets", createBody, portalSession(s, agentID, "CORP\\charlie", false))
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create ticket status = %d, want 201. Body: %s", w.Code, w.Body.String())
	}
	var createdResp map[string]any
	json.Unmarshal(w.Body.Bytes(), &createdResp)
	createdID := int64(createdResp["id"].(float64))

	// Verify created ticket
	newTk, err := s.db.GetTicket(createdID)
	if err != nil {
		t.Fatalf("get created ticket: %v", err)
	}
	if newTk.IsInternal {
		t.Errorf("created ticket has is_internal = true, expected false")
	}
	if newTk.Source != "portal" || newTk.OrgID != orgID || newTk.AgentID != agentID || newTk.RequesterDomainUser != "CORP\\charlie" {
		t.Errorf("unexpected ticket fields: %+v", newTk)
	}

	// 10. Test POST /api/portal/software/action (agent is offline in this mock test, returns 409)
	actBody := `{
		"software_id": "sw_7zip_win",
		"action": "install"
	}`
	req = portalReq("POST", "/api/portal/software/action", actBody, alice)
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("software action status = %d, want 409 (agent offline). Body: %s", w.Code, w.Body.String())
	}
}
