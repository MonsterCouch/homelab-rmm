package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// roleFixture is a server with an administrator and a way to make accounts
// with a given role.
type roleFixture struct {
	t     *testing.T
	s     *Server
	ts    *httptest.Server
	admin *browser
	n     int
}

func newRoleFixture(t *testing.T) *roleFixture {
	s, ts, admin := newTestServerWith(t, Config{})
	return &roleFixture{t: t, s: s, ts: ts, admin: admin}
}

// role creates a custom role and returns its id.
func (f *roleFixture) role(body map[string]any) string {
	f.t.Helper()
	var out struct{ ID string }
	f.admin.mustJSON("POST", "/api/roles", body, &out)
	if out.ID == "" {
		f.t.Fatal("role created without an id")
	}
	return out.ID
}

// as signs in a new account with the role (and organization scope).
func (f *roleFixture) as(role string, scope ...string) *browser {
	f.t.Helper()
	f.n++
	name := fmt.Sprintf("user%d", f.n)
	f.admin.mustJSON("POST", "/api/users", map[string]any{"username": name, "password": "password123", "role": role, "org_scope": scope}, nil)
	b := newBrowser(f.t, f.ts)
	b.mustJSON("POST", "/api/auth/login", map[string]string{"username": name, "password": "password123"}, nil)
	return b
}

// gated reports whether a route refuses the account outright. A body the
// handler rejects still means the gate let the request through.
func gated(b *browser, method, path string) bool {
	st, _ := b.do(method, path, map[string]any{})
	return st == http.StatusForbidden
}

var automationBody = map[string]any{"name": "note", "trigger": "agent_online", "action": "email", "enabled": false}

// An installation that never creates a role behaves as it did: the built-in
// roles keep exactly the rights their routes required before.
func TestBuiltinRolesKeepTheirRights(t *testing.T) {
	f := newRoleFixture(t)
	tech, viewer := f.as(RoleTech), f.as(RoleViewer)
	edits := []struct{ method, path string }{
		{"POST", "/api/baselines"}, {"PUT", "/api/baselines/1"}, {"DELETE", "/api/baselines/1"},
		{"POST", "/api/scripts"}, {"PUT", "/api/scripts/1"}, {"DELETE", "/api/scripts/1"},
		{"POST", "/api/groups"}, {"PUT", "/api/groups/1"}, {"DELETE", "/api/groups/1"},
		{"POST", "/api/tasks"}, {"PUT", "/api/tasks/1"}, {"DELETE", "/api/tasks/1"},
		{"POST", "/api/alert-rules"}, {"PUT", "/api/alert-rules/1"}, {"DELETE", "/api/alert-rules/1"},
		{"POST", "/api/patch-policies"}, {"PUT", "/api/patch-policies/1"}, {"DELETE", "/api/patch-policies/1"},
	}
	for _, e := range edits {
		if gated(tech, e.method, e.path) {
			t.Errorf("a technician is refused %s %s", e.method, e.path)
		}
		if !gated(viewer, e.method, e.path) {
			t.Errorf("a viewer is allowed %s %s", e.method, e.path)
		}
		if gated(f.admin, e.method, e.path) {
			t.Errorf("an administrator is refused %s %s", e.method, e.path)
		}
	}
	for _, b := range []*browser{tech, viewer} {
		if st, _ := b.do("GET", "/api/automations", nil); st != http.StatusForbidden {
			t.Errorf("GET /api/automations for a built-in non-admin = %d, want 403", st)
		}
		if st, _ := b.do("GET", "/api/roles", nil); st != http.StatusForbidden {
			t.Errorf("GET /api/roles for a non-admin = %d, want 403", st)
		}
	}
	f.admin.mustJSON("POST", "/api/automations", automationBody, nil)

	var me struct {
		Role        string          `json:"role"`
		RoleName    string          `json:"role_name"`
		Base        string          `json:"base_role"`
		Permissions map[string]bool `json:"permissions"`
		Automations json.RawMessage `json:"automation_scope"`
	}
	tech.mustJSON("GET", "/api/me", nil, &me)
	if me.Role != RoleTech || me.Base != RoleTech || me.RoleName != "Technician" || !me.Permissions[PermBaselinesEdit] || me.Permissions[PermAutomationsEdit] || string(me.Automations) != "[]" {
		t.Fatalf("technician /api/me = %+v (automations %s)", me, me.Automations)
	}
	f.admin.mustJSON("GET", "/api/me", nil, &me)
	if me.Base != RoleAdmin || !me.Permissions[PermAutomationsEdit] || string(me.Automations) != `"all"` {
		t.Fatalf("administrator /api/me = %+v (automations %s)", me, me.Automations)
	}
}

// A custom role starts with what its parent has and then grants or denies.
// What it says nothing about follows the parent, including later changes.
func TestCustomRoleInheritsAndOverrides(t *testing.T) {
	f := newRoleFixture(t)
	junior := f.role(map[string]any{"name": "Junior Tech", "parent": RoleTech, "grants": map[string]bool{PermBaselinesEdit: false, PermScriptsEdit: false}})
	if junior != "junior-tech" {
		t.Fatalf("role id = %q", junior)
	}
	// The child gets scripts back and says nothing about baselines.
	lead := f.role(map[string]any{"name": "Shift lead", "parent": junior, "grants": map[string]bool{PermScriptsEdit: true}})

	j, l := f.as(junior), f.as(lead)
	check := func(who string, b *browser, perm string, path string, want bool) {
		t.Helper()
		if got := !gated(b, "POST", path); got != want {
			t.Errorf("%s: %s allowed = %v, want %v", who, perm, got, want)
		}
	}
	check("junior", j, PermBaselinesEdit, "/api/baselines", false)
	check("junior", j, PermScriptsEdit, "/api/scripts", false)
	check("junior", j, PermGroupsEdit, "/api/groups", true) // untouched: from Technician
	check("lead", l, PermBaselinesEdit, "/api/baselines", false)
	check("lead", l, PermScriptsEdit, "/api/scripts", true)
	// Still a technician where no permission is involved.
	if gated(j, "POST", "/api/enroll") {
		t.Error("a technician-based role lost the base role's rights")
	}
	var me struct {
		Role     string `json:"role"`
		RoleName string `json:"role_name"`
		Base     string `json:"base_role"`
	}
	l.mustJSON("GET", "/api/me", nil, &me)
	if me.Role != lead || me.RoleName != "Shift lead" || me.Base != RoleTech {
		t.Fatalf("lead /api/me = %+v", me)
	}

	// Changing the parent reaches the child at once, without a new sign-in.
	f.admin.mustJSON("PUT", "/api/roles/"+junior, map[string]any{"name": "Junior Tech", "parent": RoleTech, "grants": map[string]bool{PermScriptsEdit: false}}, nil)
	check("junior after edit", j, PermBaselinesEdit, "/api/baselines", true)
	check("lead after edit", l, PermBaselinesEdit, "/api/baselines", true)

	// A viewer-based role is read-only except for what it is granted.
	helper := f.as(f.role(map[string]any{"name": "Group keeper", "parent": RoleViewer, "grants": map[string]bool{PermGroupsEdit: true}}))
	check("group keeper", helper, PermGroupsEdit, "/api/groups", true)
	check("group keeper", helper, PermBaselinesEdit, "/api/baselines", false)
	if !gated(helper, "POST", "/api/enroll") {
		t.Error("a viewer-based role can do what only the technician base may")
	}
}

// Automations are admin-only unless a role is given them: all of them, or a
// named few. A role with a list can change those and cannot see the others.
func TestAutomationPermissionAndScope(t *testing.T) {
	f := newRoleFixture(t)
	var a1, a2 struct{ ID int64 }
	f.admin.mustJSON("POST", "/api/automations", map[string]any{"name": "one", "trigger": "agent_online", "action": "email"}, &a1)
	f.admin.mustJSON("POST", "/api/automations", map[string]any{"name": "two", "trigger": "agent_offline", "action": "email"}, &a2)

	some := f.as(f.role(map[string]any{"name": "Automation editor", "parent": RoleTech, "grants": map[string]bool{PermAutomationsEdit: true}, "automations": []int64{a1.ID}}))
	var list []Automation
	some.mustJSON("GET", "/api/automations", nil, &list)
	if len(list) != 1 || list[0].ID != a1.ID {
		t.Fatalf("a role listing one automation sees %+v", list)
	}
	some.mustJSON("PUT", fmt.Sprintf("/api/automations/%d", a1.ID), map[string]any{"name": "one, renamed", "trigger": "agent_online", "action": "email", "enabled": true}, nil)
	if st, _ := some.do("PUT", fmt.Sprintf("/api/automations/%d", a2.ID), automationBody); st != http.StatusNotFound {
		t.Errorf("changing an automation outside the role's list = %d, want 404", st)
	}
	if st, _ := some.do("POST", "/api/automations", automationBody); st != http.StatusForbidden {
		t.Errorf("creating an automation with a listed scope = %d, want 403", st)
	}
	if st, _ := some.do("DELETE", fmt.Sprintf("/api/automations/%d", a1.ID), nil); st != http.StatusForbidden {
		t.Errorf("deleting a listed automation = %d, want 403", st)
	}
	var name string
	f.s.db.QueryRow(`SELECT name FROM automations WHERE id = ?`, a2.ID).Scan(&name)
	if name != "two" {
		t.Fatalf("the automation outside the list was changed to %q", name)
	}

	// The permission without a scope of its own inherits Technician's: none.
	none := f.as(f.role(map[string]any{"name": "No scope", "parent": RoleTech, "grants": map[string]bool{PermAutomationsEdit: true}}))
	none.mustJSON("GET", "/api/automations", nil, &list)
	if len(list) != 0 {
		t.Fatalf("a role with no automation scope sees %d automations", len(list))
	}

	all := f.role(map[string]any{"name": "Automation owner", "parent": RoleTech, "grants": map[string]bool{PermAutomationsEdit: true}, "automations": "all"})
	owner := f.as(all)
	owner.mustJSON("GET", "/api/automations", nil, &list)
	if len(list) != 2 {
		t.Fatalf("a role with all automations sees %d, want 2", len(list))
	}
	var a3 struct{ ID int64 }
	owner.mustJSON("POST", "/api/automations", automationBody, &a3)
	owner.mustJSON("DELETE", fmt.Sprintf("/api/automations/%d", a3.ID), nil, nil)

	// A child that says nothing about automations inherits the scope.
	heir := f.as(f.role(map[string]any{"name": "Heir", "parent": all}))
	heir.mustJSON("GET", "/api/automations", nil, &list)
	if len(list) != 2 {
		t.Fatalf("an inheriting role sees %d automations, want 2", len(list))
	}

	// Automations act on every organization, so an account limited to some
	// cannot hold the right whatever its role says.
	var org struct{ ID string }
	f.admin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Client"}, &org)
	scoped := f.as(all, org.ID)
	st, body := scoped.do("GET", "/api/automations", nil)
	if st != http.StatusForbidden || !strings.Contains(string(body), "organization") {
		t.Fatalf("a scoped account with the automation role = %d %s, want 403 naming the reason", st, body)
	}
}

func TestRoleManagementRules(t *testing.T) {
	f := newRoleFixture(t)
	bad := func(why string, body map[string]any) {
		t.Helper()
		if st, data := f.admin.do("POST", "/api/roles", body); st != http.StatusBadRequest {
			t.Errorf("%s: POST /api/roles = %d %s, want 400", why, st, data)
		}
	}
	bad("no name", map[string]any{"name": " ", "parent": RoleTech})
	bad("admin parent", map[string]any{"name": "Almost admin", "parent": RoleAdmin})
	bad("contact parent", map[string]any{"name": "Contact plus", "parent": RoleContact})
	bad("missing parent", map[string]any{"name": "Orphan", "parent": "nope"})
	bad("no parent", map[string]any{"name": "Orphan"})
	bad("unknown permission", map[string]any{"name": "Typo", "parent": RoleTech, "grants": map[string]bool{"baselines.eidt": true}})
	bad("unknown automation", map[string]any{"name": "Ghost list", "parent": RoleTech, "automations": []int64{999}})
	bad("bad automation scope", map[string]any{"name": "Bad scope", "parent": RoleTech, "automations": "some"})

	a := f.role(map[string]any{"name": "A", "parent": RoleTech})
	b := f.role(map[string]any{"name": "B", "parent": a})
	// Two roles may share a name; their ids stay distinct, and never shadow
	// a built-in role.
	if id := f.role(map[string]any{"name": "A", "parent": RoleTech}); id == a {
		t.Fatalf("a second role named A reused the id %q", id)
	}
	if id := f.role(map[string]any{"name": "Admin", "parent": RoleTech}); id == RoleAdmin {
		t.Fatal("a custom role took the id of the built-in administrator")
	}
	// No loops: A cannot inherit from its own descendant, or from itself.
	for _, parent := range []string{b, a} {
		if st, _ := f.admin.do("PUT", "/api/roles/"+a, map[string]any{"name": "A", "parent": parent}); st != http.StatusBadRequest {
			t.Errorf("making A inherit from %s = %d, want 400", parent, st)
		}
	}
	// Built-in roles are fixed.
	for _, id := range []string{RoleAdmin, RoleTech, RoleViewer, RoleContact} {
		if st, _ := f.admin.do("PUT", "/api/roles/"+id, map[string]any{"name": "x", "parent": RoleTech}); st != http.StatusBadRequest {
			t.Errorf("changing built-in %s = %d, want 400", id, st)
		}
		if st, _ := f.admin.do("DELETE", "/api/roles/"+id, nil); st != http.StatusBadRequest {
			t.Errorf("deleting built-in %s = %d, want 400", id, st)
		}
	}
	// A role with children or accounts cannot be deleted from under them.
	if st, _ := f.admin.do("DELETE", "/api/roles/"+a, nil); st != http.StatusConflict {
		t.Errorf("deleting a role others inherit from = %d, want 409", st)
	}
	f.as(b)
	if st, _ := f.admin.do("DELETE", "/api/roles/"+b, nil); st != http.StatusConflict {
		t.Errorf("deleting a role in use = %d, want 409", st)
	}
	if st, _ := f.admin.do("POST", "/api/users", map[string]any{"username": "x", "password": "password123", "role": "no-such-role"}); st != http.StatusBadRequest {
		t.Errorf("creating a user with an unknown role = %d, want 400", st)
	}

	var listing struct {
		Permissions []Permission `json:"permissions"`
		Roles       []struct {
			ID        string `json:"id"`
			Builtin   bool   `json:"builtin"`
			Users     int    `json:"users"`
			Effective struct {
				Base        string          `json:"base"`
				Permissions map[string]bool `json:"permissions"`
			} `json:"effective"`
		} `json:"roles"`
	}
	f.admin.mustJSON("GET", "/api/roles", nil, &listing)
	if len(listing.Permissions) != len(permissionCatalog) || len(listing.Roles) != 4+4 {
		t.Fatalf("listing has %d permissions and %d roles", len(listing.Permissions), len(listing.Roles))
	}
	for _, r := range listing.Roles {
		if r.ID == b && (r.Builtin || r.Users != 1 || r.Effective.Base != RoleTech || !r.Effective.Permissions[PermBaselinesEdit]) {
			t.Fatalf("listing for B = %+v", r)
		}
	}
}

// An account whose role no longer resolves may only look. A damaged roles
// table must never turn into access.
func TestUnresolvableRoleIsReadOnly(t *testing.T) {
	f := newRoleFixture(t)
	b := f.as(f.role(map[string]any{"name": "Doomed", "parent": RoleTech}))
	if gated(b, "POST", "/api/enroll") {
		t.Fatal("fixture: the role does not work before it is damaged")
	}
	if _, err := f.s.db.Exec(`DELETE FROM roles`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/enroll", "/api/baselines", "/api/groups"} {
		if !gated(b, "POST", path) {
			t.Errorf("an account with a role that no longer exists is allowed POST %s", path)
		}
	}
	if st, _ := b.do("GET", "/api/users", nil); st != http.StatusForbidden {
		t.Errorf("... and can read the user list (%d)", st)
	}
	if st, _ := b.do("GET", "/api/me", nil); st != http.StatusOK {
		t.Errorf("... but should still be signed in (%d)", st)
	}
	if f.s.db.signerIsLive("anything", "user1") {
		t.Error("an unresolvable role counts as a live signer")
	}
}

// Taking the technician base away from a role ends what its accounts have
// open, the same as demoting them one by one would.
func TestRoleChangeEndsOpenTerminal(t *testing.T) {
	f := newRoleFixture(t)
	var tok struct{ Token string }
	f.admin.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	agent := newShellAgent(t, f.ts, tok.Token, "rolebox", "")
	waitFor(t, "agent online", func() bool { return f.s.hub.IsOnline(agent.id) })

	role := f.role(map[string]any{"name": "Operators", "parent": RoleTech})
	op := f.as(role)
	term, _, err := websocket.DefaultDialer.Dial(wsURL(f.ts)+"/ws/shell/"+agent.id, wsCookies(t, f.ts, op))
	if err != nil {
		t.Fatalf("terminal dial: %v", err)
	}
	defer term.Close()
	term.WriteJSON(map[string]any{"t": "open", "shell": "powershell", "cols": 80, "rows": 24})
	if m := readShell(t, term); m["t"] != "opened" {
		t.Fatalf("expected opened, got %v", m)
	}

	f.admin.mustJSON("PUT", "/api/roles/"+role, map[string]any{"name": "Operators", "parent": RoleViewer}, nil)

	term.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, _, err := term.ReadMessage(); err != nil {
			var ce *websocket.CloseError
			if !errors.As(err, &ce) || ce.Code != websocket.ClosePolicyViolation {
				t.Fatalf("terminal ended with %v, want a policy close", err)
			}
			break
		}
	}
}
