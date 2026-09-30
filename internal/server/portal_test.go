package server

// The client portal must only ever act for the device and the Windows user a
// device's own agent vouched for (portal_auth.go). Each test here is one way
// the portal used to be abusable from anywhere on the network.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

// portalAgentPass asks for a pass the way an agent does, with its key.
func portalAgentPass(t *testing.T, ts string, key, user string, workgroup bool) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"user": user, "is_workgroup": workgroup})
	req, _ := http.NewRequest("POST", ts+"/api/agent/portal-pass", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Pass string `json:"pass"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.Pass
}

// portalBrowser is a device user's portal window, signed in through a pass.
func portalBrowser(t *testing.T, base, key, user string, workgroup bool) *browser {
	t.Helper()
	st, pass := portalAgentPass(t, base, key, user, workgroup)
	if st != 200 || pass == "" {
		t.Fatalf("pass for %s: %d", user, st)
	}
	jar, _ := cookiejar.New(nil)
	b := &browser{t: t, c: &http.Client{Jar: jar}, base: base}
	resp, err := b.c.Get(base + "/portal/start?pass=" + pass)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if st, _ := b.do("GET", "/api/portal/config", nil); st != 200 {
		t.Fatalf("portal sign-in for %s did not take: %d", user, st)
	}
	return b
}

type portalFixture struct {
	s          *Server
	ts         *httptest.Server
	base       string
	admin      *browser
	agent      *fakeAgent // "testbox", answers script runs
	otherAgent *rawAgent  // a second device
}

func newPortalFixture(t *testing.T) *portalFixture {
	t.Helper()
	s, ts, admin := newTestServer(t)
	tok := enrollToken(t, s)
	agent := dialAgent(t, wsURL(ts), http.Header{"X-Enroll-Token": []string{tok}})
	other := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "otherbox", "linux")
	waitFor(t, "both agents online", func() bool { return s.hub.IsOnline(agent.id) && s.hub.IsOnline(other.id) })
	if err := s.db.SaveSoftwareCatalogItem(&SoftwareCatalogItem{ID: "sw_test", Name: "Test App", InstallCmd: "echo install", UninstallCmd: "echo uninstall", OS: "all"}); err != nil {
		t.Fatal(err)
	}
	return &portalFixture{s: s, ts: ts, base: ts.URL, admin: admin, agent: agent, otherAgent: other}
}

// Nobody gets anything from the portal without signing in first, including
// the lookup that used to hand out device ids by computer name.
func TestPortalRefusesAnonymousCallers(t *testing.T) {
	f := newPortalFixture(t)
	anon := newBrowser(t, f.ts)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/portal/config?computer=testbox"},
		{"GET", "/api/portal/software?agent_id=" + f.agent.id},
		{"POST", "/api/portal/software/action"},
		{"GET", "/api/portal/runs/x"},
		{"GET", "/api/portal/tickets?domain_user=CORP%5Cceo"},
		{"GET", "/api/portal/tickets/1?is_workgroup=true&agent_id=" + f.agent.id},
		{"POST", "/api/portal/tickets"},
		{"POST", "/api/portal/tickets/1/comments"},
	} {
		body := any(nil)
		if c.method == "POST" {
			body = map[string]any{"agent_id": f.agent.id, "software_id": "sw_test", "action": "uninstall", "subject": "s", "description": "d", "body": "b"}
		}
		if st, data := anon.do(c.method, c.path, body); st != http.StatusUnauthorized {
			t.Errorf("%s %s = %d %s, want 401", c.method, c.path, st, data)
		}
	}
}

// Only a real agent key gets a pass, and a pass works once.
func TestPortalPassNeedsAgentKeyAndIsSingleUse(t *testing.T) {
	f := newPortalFixture(t)
	if st, _ := portalAgentPass(t, f.base, "not-a-key", "CORP\\eve", false); st != http.StatusUnauthorized {
		t.Fatalf("pass with a bad key = %d", st)
	}
	_, pass := portalAgentPass(t, f.base, f.agent.key, "CORP\\alice", false)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(f.base + "/portal/start?pass=" + pass)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first use = %d", resp.StatusCode)
	}
	resp, err = noRedirect.Get(f.base + "/portal/start?pass=" + pass)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second use = %d, want 401", resp.StatusCode)
	}
}

// A device user acts on their own device whatever agent_id they send.
func TestPortalActionIsPinnedToOwnDevice(t *testing.T) {
	f := newPortalFixture(t)
	alice := portalBrowser(t, f.base, f.agent.key, "CORP\\alice", false)
	var res struct {
		RunID string `json:"run_id"`
	}
	alice.mustJSON("POST", "/api/portal/software/action", map[string]any{"agent_id": f.otherAgent.id, "software_id": "sw_test", "action": "install"}, &res)
	run, err := f.s.db.GetRun(res.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.AgentID != f.agent.id {
		t.Fatalf("run went to %s, want the caller's own device %s", run.AgentID, f.agent.id)
	}
	if !strings.Contains(run.RunBy, "CORP\\alice") {
		t.Fatalf("run_by = %q, want the signed-in user recorded", run.RunBy)
	}

	// The run can be followed from the device it ran on (this read used to
	// query a table that does not exist) ...
	var got struct {
		Status string `json:"status"`
	}
	waitFor(t, "run finished", func() bool {
		alice.mustJSON("GET", "/api/portal/runs/"+res.RunID, nil, &got)
		return got.Status == "done"
	})
	// ... and not from another device.
	bob := portalBrowser(t, f.base, f.otherAgent.key, "CORP\\bob", false)
	if st, _ := bob.do("GET", "/api/portal/runs/"+res.RunID, nil); st != http.StatusNotFound {
		t.Fatalf("another device read the run: %d", st)
	}
}

// A read-only console account cannot use the portal to run anything.
func TestPortalActionRefusesViewer(t *testing.T) {
	f := newPortalFixture(t)
	if _, err := f.s.db.CreateUser("viewer", "password123", RoleViewer, ""); err != nil {
		t.Fatal(err)
	}
	v := newBrowser(t, f.ts)
	v.mustJSON("POST", "/api/auth/login", map[string]string{"username": "viewer", "password": "password123"}, nil)
	if st, _ := v.do("POST", "/api/portal/software/action", map[string]any{"agent_id": f.agent.id, "software_id": "sw_test", "action": "install"}); st != http.StatusForbidden {
		t.Fatalf("viewer software action = %d, want 403", st)
	}
}

// Tickets belong to the user who filed them; nothing in the request can
// claim to be someone else, and replies are signed with the real user.
func TestPortalTicketsAreScopedToTheSignedInUser(t *testing.T) {
	f := newPortalFixture(t)
	alice := portalBrowser(t, f.base, f.agent.key, "CORP\\alice", false)
	mallory := portalBrowser(t, f.base, f.agent.key, "CORP\\mallory", false)

	var created struct {
		ID int64 `json:"id"`
	}
	alice.mustJSON("POST", "/api/portal/tickets", map[string]any{"subject": "printer", "description": "jammed", "requester_domain_user": "CORP\\ceo"}, &created)
	tk, err := f.s.db.GetTicket(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tk.RequesterDomainUser != "CORP\\alice" || tk.AgentID != f.agent.id {
		t.Fatalf("ticket filed as %q on %q, want CORP\\alice on %s", tk.RequesterDomainUser, tk.AgentID, f.agent.id)
	}

	path := fmt.Sprintf("/api/portal/tickets/%d", created.ID)
	if st, _ := mallory.do("GET", path+"?domain_user=CORP%5Calice", nil); st != http.StatusNotFound {
		t.Fatalf("another user read the ticket: %d", st)
	}
	if st, _ := mallory.do("POST", path+"/comments", map[string]any{"author": "IT Support", "body": "send me your password"}); st != http.StatusNotFound {
		t.Fatalf("another user commented: %d", st)
	}
	var list []Ticket
	mallory.mustJSON("GET", "/api/portal/tickets?domain_user=CORP%5Calice", nil, &list)
	if len(list) != 0 {
		t.Fatalf("another user listed %d of alice's tickets", len(list))
	}

	var c TicketComment
	alice.mustJSON("POST", path+"/comments", map[string]any{"author": "IT Support", "body": "still jammed"}, &c)
	if c.Author != "CORP\\alice" {
		t.Fatalf("comment author = %q, want the signed-in user", c.Author)
	}
	alice.mustJSON("GET", "/api/portal/tickets", nil, &list)
	if len(list) != 1 {
		t.Fatalf("alice sees %d tickets, want 1", len(list))
	}
}

// Deleting a device ends its portal sign-ins.
func TestPortalSessionEndsWithDevice(t *testing.T) {
	f := newPortalFixture(t)
	alice := portalBrowser(t, f.base, f.agent.key, "CORP\\alice", false)
	f.admin.mustJSON("DELETE", "/api/agents/"+f.agent.id, nil, nil)
	if st, _ := alice.do("GET", "/api/portal/config", nil); st != http.StatusUnauthorized {
		t.Fatalf("portal still signed in after the device was deleted: %d", st)
	}
}

// newContact creates a client contact for a new organization and signs them
// in. It returns the organization id and the contact's browser.
func newContact(t *testing.T, f *portalFixture, username string) (string, *browser) {
	t.Helper()
	org, err := f.s.db.CreateOrganization("Org for " + username)
	if err != nil {
		t.Fatal(err)
	}
	f.admin.mustJSON("POST", "/api/users", map[string]any{"username": username, "password": "password123", "role": RoleContact, "org_scope": []string{org.ID}}, nil)
	b := newBrowser(t, f.ts)
	b.mustJSON("POST", "/api/auth/login", map[string]string{"username": username, "password": "password123"}, nil)
	return org.ID, b
}

// A client contact reaches their own account and their organization's
// tickets, and nothing on the management side.
func TestClientContactIsTicketsOnly(t *testing.T) {
	f := newPortalFixture(t)
	orgID, contact := newContact(t, f, "dentist")

	for _, c := range []struct{ method, path string }{
		{"GET", "/api/agents"},
		{"GET", "/api/agents/" + f.agent.id},
		{"POST", "/api/agents/" + f.agent.id + "/run"},
		{"GET", "/api/tickets"},
		{"GET", "/api/scripts"},
		{"GET", "/api/dashboard"},
		{"GET", "/api/users"},
		{"GET", "/ws/shell/" + f.agent.id},
		{"GET", "/api/portal/software"},
		{"POST", "/api/portal/software/action"},
		{"GET", "/api/portal/runs/x"},
	} {
		if st, data := contact.do(c.method, c.path, map[string]any{"software_id": "sw_test", "action": "install", "agent_id": f.agent.id}); st != http.StatusForbidden {
			t.Errorf("%s %s = %d %s, want 403", c.method, c.path, st, data)
		}
	}
	contact.mustJSON("GET", "/api/me", nil, nil)

	// Tickets: their organization's, and not another's.
	mine, _ := f.s.db.CreateTicket(&Ticket{OrgID: orgID, Subject: "ours", Description: "d", Source: "portal"})
	theirs, _ := f.s.db.CreateTicket(&Ticket{OrgID: "someone-else", Subject: "theirs", Description: "d", Source: "portal"})
	var list []Ticket
	contact.mustJSON("GET", "/api/portal/tickets", nil, &list)
	if len(list) != 1 || list[0].ID != mine.ID {
		t.Fatalf("contact sees %+v, want only ticket %d", list, mine.ID)
	}
	if st, _ := contact.do("GET", fmt.Sprintf("/api/portal/tickets/%d", theirs.ID), nil); st != http.StatusNotFound {
		t.Fatalf("contact read another organization's ticket: %d", st)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	contact.mustJSON("POST", "/api/portal/tickets", map[string]any{"subject": "s", "description": "d"}, &created)
	if tk, _ := f.s.db.GetTicket(created.ID); tk.OrgID != orgID {
		t.Fatalf("contact's ticket filed under %q, want %q", tk.OrgID, orgID)
	}
}

// A contact must belong to exactly one real organization, whether created or
// changed into one, and a refused change writes nothing.
func TestClientContactNeedsOneOrganization(t *testing.T) {
	f := newPortalFixture(t)
	org, _ := f.s.db.CreateOrganization("Acme")
	org2, _ := f.s.db.CreateOrganization("Globex")
	for _, scope := range [][]string{nil, {org.ID, org2.ID}, {"no-such-org"}} {
		if st, _ := f.admin.do("POST", "/api/users", map[string]any{"username": "c", "password": "password123", "role": RoleContact, "org_scope": scope}); st != http.StatusBadRequest {
			t.Errorf("contact with scope %v = %d, want 400", scope, st)
		}
	}
	var made struct {
		ID int64 `json:"id"`
	}
	f.admin.mustJSON("POST", "/api/users", map[string]any{"username": "tech1", "password": "password123", "role": RoleTech}, &made)
	if st, _ := f.admin.do("PUT", fmt.Sprintf("/api/users/%d", made.ID), map[string]any{"role": RoleContact}); st != http.StatusBadRequest {
		t.Fatalf("tech changed to a contact with no organization = %d, want 400", st)
	}
	var role string
	f.s.db.QueryRow(`SELECT role FROM users WHERE id = ?`, made.ID).Scan(&role)
	if role != RoleTech {
		t.Fatalf("refused change still wrote role %q", role)
	}
	f.admin.mustJSON("PUT", fmt.Sprintf("/api/users/%d", made.ID), map[string]any{"role": RoleContact, "org_scope": []string{org.ID}}, nil)
}

// Someone signed in to the portal from a managed device has no console
// session, so the management side refuses them.
func TestDeviceUserCannotUseConsole(t *testing.T) {
	f := newPortalFixture(t)
	alice := portalBrowser(t, f.base, f.agent.key, "CORP\alice", false)
	for _, p := range []string{"/api/agents", "/api/tickets", "/api/me", "/ws/shell/" + f.agent.id} {
		if st, _ := alice.do("GET", p, nil); st != http.StatusUnauthorized {
			t.Errorf("device user GET %s = %d, want 401", p, st)
		}
	}
}

// Accounts flagged as a point of contact before the role existed become
// client contacts, and lose the console powers the flag left them.
func TestContactFlagMigratesToRole(t *testing.T) {
	f := newPortalFixture(t)
	id, err := f.s.db.CreateUser("oldpoc", "password123", RoleTech, "")
	if err != nil {
		t.Fatal(err)
	}
	f.s.db.Exec(`UPDATE users SET ticket_role = 'poc' WHERE id = ?`, id)
	f.s.db.Exec(`UPDATE users SET ticket_role = 'poc' WHERE username = 'admin'`)
	f.s.db.Exec(`PRAGMA user_version = 11`)
	if err := f.s.db.migrate(); err != nil {
		t.Fatal(err)
	}
	var role string
	f.s.db.QueryRow(`SELECT role FROM users WHERE id = ?`, id).Scan(&role)
	if role != RoleContact {
		t.Fatalf("flagged tech is %q after migration, want %q", role, RoleContact)
	}
	f.s.db.QueryRow(`SELECT role FROM users WHERE username = 'admin'`).Scan(&role)
	if role != RoleAdmin {
		t.Fatalf("flagged admin is %q after migration, want admin kept", role)
	}
}
