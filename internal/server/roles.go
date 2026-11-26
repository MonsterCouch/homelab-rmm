package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// Roles.
//
// There are four built-in roles: admin, tech, viewer and poc. They are code,
// not rows, and they do not change. An administrator can add custom roles on
// top of them. A custom role has one parent - tech, viewer or another custom
// role - and starts with everything the parent has; it then grants or denies
// individual permissions, and names the automations it may change. A role's
// "base" is the built-in at the root of its chain, and the base is what the
// broad gates (requireWrite, requireAdmin, the portal rules) go by. So a
// custom role can never be more than a technician where a permission is not
// involved, and admin stays what it was: everything, always.
//
// Permissions cover the fleet-wide objects whose rights an organization
// wants to hand out separately: who may change baselines, the script
// library, groups, scheduled tasks, alert rules, patch policies and
// automations. What is not listed here stays with the base role.

// Permission is one right a role can be given or denied.
type Permission struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Help  string `json:"help"`
	// Tech is the built-in technician's setting, and so what a role
	// inheriting from tech starts with. The built-in viewer has none.
	Tech bool `json:"tech"`
}

const (
	PermBaselinesEdit     = "baselines.edit"
	PermScriptsEdit       = "scripts.edit"
	PermGroupsEdit        = "groups.edit"
	PermTasksEdit         = "tasks.edit"
	PermAlertRulesEdit    = "alert_rules.edit"
	PermPatchPoliciesEdit = "patch_policies.edit"
	PermAutomationsEdit   = "automations.edit"
)

// permissionCatalog is every permission, in the order the console shows them.
// The technician defaults are what each route required before roles existed,
// so an installation that never creates a role behaves exactly as it did.
var permissionCatalog = []Permission{
	{PermBaselinesEdit, "Change baselines", "Create, change and delete baselines. Evaluating and remediating one stays with the base role.", true},
	{PermScriptsEdit, "Change the script library", "Create, change and delete library scripts. Running a script stays with the base role.", true},
	{PermGroupsEdit, "Change groups", "Create, rename and delete device groups.", true},
	{PermTasksEdit, "Change scheduled tasks", "Create, change and delete scheduled tasks. Running one now stays with the base role.", true},
	{PermAlertRulesEdit, "Change alert rules", "Create, change and delete alert rules.", true},
	{PermPatchPoliciesEdit, "Change patch policies", "Create, change and delete patch policies.", true},
	{PermAutomationsEdit, "Change automations", "See and change automations: all of them, or only the ones the role lists. Creating and deleting one needs all of them.", false},
}

func knownPermission(key string) bool {
	return slices.ContainsFunc(permissionCatalog, func(p Permission) bool { return p.Key == key })
}

// maxRoleDepth bounds a role chain. It is far more than anyone needs and
// keeps a damaged table from being walked forever.
const maxRoleDepth = 8

func isBuiltinRole(id string) bool {
	return id == RoleAdmin || id == RoleTech || id == RoleViewer || id == RoleContact
}

// builtinRoleNames are the built-in roles as the console lists them.
var builtinRoleNames = map[string]string{
	RoleAdmin:   "Administrator",
	RoleTech:    "Technician",
	RoleViewer:  "Viewer",
	RoleContact: "Client contact",
}

// automationScope is which automations a role may change: all of them, or a
// list. set is false when a custom role says nothing and inherits.
type automationScope struct {
	set bool
	all bool
	ids []int64
}

func (a automationScope) MarshalJSON() ([]byte, error) {
	switch {
	case !a.set:
		return []byte("null"), nil
	case a.all:
		return []byte(`"all"`), nil
	}
	ids := a.ids
	if ids == nil {
		ids = []int64{}
	}
	return json.Marshal(ids)
}

func (a *automationScope) UnmarshalJSON(b []byte) error {
	*a = automationScope{}
	s := strings.TrimSpace(string(b))
	switch s {
	case "", "null":
		return nil
	case `"all"`:
		a.set, a.all = true, true
		return nil
	}
	var ids []int64
	if err := json.Unmarshal(b, &ids); err != nil {
		return errors.New(`automations must be "all", a list of automation ids, or null to inherit`)
	}
	slices.Sort(ids)
	a.set, a.ids = true, slices.Compact(ids)
	return nil
}

// Role is a custom role as stored, or a built-in one as listed.
type Role struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Parent  string `json:"parent"`
	Builtin bool   `json:"builtin"`
	// Grants are this role's own decisions: true grants a permission, false
	// denies it, and a permission that is absent is inherited.
	Grants      map[string]bool `json:"grants"`
	Automations automationScope `json:"automations"`
	CreatedAt   int64           `json:"created_at"`
}

// effectiveRole is a role with its chain applied: what an account that has
// it can actually do.
type effectiveRole struct {
	Base        string          `json:"base"`
	Permissions map[string]bool `json:"permissions"`
	Automations automationScope `json:"automation_scope"`
	name        string
}

func builtinEffective(id string) effectiveRole {
	e := effectiveRole{Base: id, Permissions: map[string]bool{}, Automations: automationScope{set: true}, name: builtinRoleNames[id]}
	for _, p := range permissionCatalog {
		e.Permissions[p.Key] = id == RoleAdmin || (id == RoleTech && p.Tech)
	}
	e.Automations.all = id == RoleAdmin
	return e
}

func (d *DB) getRole(id string) (*Role, error) {
	var r Role
	var grants, autos string
	err := d.QueryRow(`SELECT id, name, parent, grants, automations, created_at FROM roles WHERE id = ?`, id).
		Scan(&r.ID, &r.Name, &r.Parent, &grants, &autos, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Grants = map[string]bool{}
	_ = json.Unmarshal([]byte(grants), &r.Grants)
	_ = r.Automations.UnmarshalJSON([]byte(autos))
	return &r, nil
}

func (d *DB) listRoles() ([]Role, error) {
	rows, err := d.Query(`SELECT id, name, parent, grants, automations, created_at FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var r Role
		var grants, autos string
		if err := rows.Scan(&r.ID, &r.Name, &r.Parent, &grants, &autos, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Grants = map[string]bool{}
		_ = json.Unmarshal([]byte(grants), &r.Grants)
		_ = r.Automations.UnmarshalJSON([]byte(autos))
		out = append(out, r)
	}
	return out, rows.Err()
}

// roleChain is id and its ancestors, the role itself first and the built-in
// root last. It fails for a role that does not exist, a chain that does not
// end in a built-in, and one that loops or is too deep.
func (d *DB) roleChain(id string) (root string, chain []*Role, err error) {
	seen := map[string]bool{}
	for cur := id; ; {
		if isBuiltinRole(cur) {
			return cur, chain, nil
		}
		if seen[cur] || len(chain) >= maxRoleDepth {
			return "", nil, fmt.Errorf("role %q has a parent chain that loops or is too deep", id)
		}
		seen[cur] = true
		r, err := d.getRole(cur)
		if err != nil {
			return "", nil, fmt.Errorf("role %q does not exist", cur)
		}
		chain = append(chain, r)
		cur = r.Parent
	}
}

// resolveRole applies a role's chain from the built-in root down. A role
// that cannot be resolved comes back with no base and no permissions, which
// every gate reads as "may only look": a damaged roles table must not turn
// into access.
func (d *DB) resolveRole(id string) effectiveRole {
	if isBuiltinRole(id) {
		return builtinEffective(id)
	}
	root, chain, err := d.roleChain(id)
	if err != nil {
		return effectiveRole{Permissions: map[string]bool{}, Automations: automationScope{set: true}}
	}
	e := builtinEffective(root)
	for i := len(chain) - 1; i >= 0; i-- {
		r := chain[i]
		for k, v := range r.Grants {
			if knownPermission(k) {
				e.Permissions[k] = v
			}
		}
		if r.Automations.set {
			e.Automations = r.Automations
		}
	}
	e.name = chain[0].Name
	return e
}

// roleExists is what makes a string usable as an account's role.
func (d *DB) roleExists(id string) bool {
	if isBuiltinRole(id) {
		return true
	}
	_, _, err := d.roleChain(id)
	return err == nil
}

// fillRole sets what an account's role works out to. Everything that hands
// out a *User calls it, so the gates never see a role that was not resolved.
func (d *DB) fillRole(u *User) {
	e := d.resolveRole(u.Role)
	u.Base, u.RoleName, u.Permissions, u.AutomationScope = e.Base, e.name, e.Permissions, e.Automations
	if u.RoleName == "" {
		u.RoleName = u.Role
	}
}

// base is the built-in role the account's role comes down to. A User built
// by hand with only Role set (the tests do) still answers for a built-in.
func (u *User) base() string {
	switch {
	case u == nil:
		return ""
	case u.Base != "":
		return u.Base
	case isBuiltinRole(u.Role):
		return u.Role
	}
	return ""
}

// Can reports whether the account holds a permission. An administrator
// holds all of them.
func (u *User) Can(perm string) bool {
	if u == nil {
		return false
	}
	if u.IsAdmin() {
		return true
	}
	if u.Permissions == nil && isBuiltinRole(u.Role) {
		return builtinEffective(u.Role).Permissions[perm]
	}
	return u.Permissions[perm]
}

// CanAutomations reports whether the account may see and change automations
// at all. Automations act on whatever device their trigger matches, in every
// organization, so an account limited to some organizations cannot hold this
// however its role is set.
func (u *User) CanAutomations() bool {
	if u.IsAdmin() {
		return true
	}
	return u.Can(PermAutomationsEdit) && len(u.OrgScope) == 0
}

// AllAutomations reports whether the account may create and delete
// automations, which takes access to all of them.
func (u *User) AllAutomations() bool {
	return u.IsAdmin() || (u.CanAutomations() && u.AutomationScope.all)
}

// CanAutomation reports whether the account may change one automation.
func (u *User) CanAutomation(id int64) bool {
	if u.AllAutomations() {
		return true
	}
	return u.CanAutomations() && slices.Contains(u.AutomationScope.ids, id)
}

// requirePerm gates a route on one permission.
func (s *Server) requirePerm(perm string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r.Context()).Can(perm) {
			writeErr(w, http.StatusForbidden, "your role does not allow this")
			return
		}
		next(w, r)
	}
}

// requireAutomations gates the automation routes. Which automation is
// checked in the handler, where the id is known.
func (s *Server) requireAutomations(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r.Context())
		if !u.CanAutomations() {
			msg := "your role does not allow this"
			if u.Can(PermAutomationsEdit) {
				msg = "automations act on every organization, so an account limited to some organizations cannot change them"
			}
			writeErr(w, http.StatusForbidden, msg)
			return
		}
		next(w, r)
	}
}

// ---- role management (admin only) ----

type roleView struct {
	Role
	Effective effectiveRole `json:"effective"`
	Users     int           `json:"users"`
}

func (d *DB) roleUserCounts() (map[string]int, error) {
	rows, err := d.Query(`SELECT role, COUNT(*) FROM users GROUP BY role`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var role string
		var n int
		if err := rows.Scan(&role, &n); err != nil {
			return nil, err
		}
		out[role] = n
	}
	return out, rows.Err()
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	custom, err := s.db.listRoles()
	if err != nil {
		fail(w, err)
		return
	}
	counts, err := s.db.roleUserCounts()
	if err != nil {
		fail(w, err)
		return
	}
	views := []roleView{}
	for _, id := range []string{RoleAdmin, RoleTech, RoleViewer, RoleContact} {
		views = append(views, roleView{
			Role:      Role{ID: id, Name: builtinRoleNames[id], Builtin: true, Grants: map[string]bool{}},
			Effective: builtinEffective(id), Users: counts[id],
		})
	}
	for _, c := range custom {
		views = append(views, roleView{Role: c, Effective: s.db.resolveRole(c.ID), Users: counts[c.ID]})
	}
	writeJSON(w, 200, map[string]any{"permissions": permissionCatalog, "roles": views})
}

type roleInput struct {
	Name        string          `json:"name"`
	Parent      string          `json:"parent"`
	Grants      map[string]bool `json:"grants"`
	Automations automationScope `json:"automations"`
}

// roleSlug turns a display name into the id stored on accounts.
func roleSlug(name string) string {
	var b strings.Builder
	dash := true
	for _, c := range strings.ToLower(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
			dash = false
		case !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	return s
}

// checkRoleInput validates what an administrator sent for the role with
// this id ("" when it is being created).
func (s *Server) checkRoleInput(id string, in *roleInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 60 {
		return errors.New("a role needs a name of at most 60 characters")
	}
	// Administrators are not a starting point: a role built on admin would
	// be an administrator whatever it denied. Client contacts have no
	// console rights to adjust.
	if in.Parent == RoleAdmin || in.Parent == RoleContact {
		return errors.New("a role inherits from Technician, Viewer or another custom role")
	}
	root, chain, err := s.db.roleChain(in.Parent)
	if err != nil {
		return errors.New("the parent role does not exist")
	}
	if root != RoleTech && root != RoleViewer {
		return errors.New("a role inherits from Technician, Viewer or another custom role")
	}
	if len(chain)+1 > maxRoleDepth {
		return fmt.Errorf("roles can be nested at most %d deep", maxRoleDepth)
	}
	for _, anc := range chain {
		if id != "" && anc.ID == id {
			return errors.New("a role cannot inherit from itself, directly or through another role")
		}
	}
	for k := range in.Grants {
		if !knownPermission(k) {
			return fmt.Errorf("unknown permission %q", k)
		}
	}
	if in.Automations.set && !in.Automations.all {
		for _, aid := range in.Automations.ids {
			var one int
			if err := s.db.QueryRow(`SELECT 1 FROM automations WHERE id = ?`, aid).Scan(&one); err != nil {
				return fmt.Errorf("automation %d does not exist", aid)
			}
		}
	}
	return nil
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var in roleInput
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if err := s.checkRoleInput("", &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	base := roleSlug(in.Name)
	if base == "" {
		writeErr(w, http.StatusBadRequest, "a role name needs at least one letter or digit")
		return
	}
	id := base
	for n := 2; isBuiltinRole(id) || s.roleIDTaken(id); n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	grants, _ := json.Marshal(in.Grants)
	autos, _ := in.Automations.MarshalJSON()
	if _, err := s.db.Exec(`INSERT INTO roles(id, name, parent, grants, automations, created_at) VALUES(?,?,?,?,?,?)`,
		id, in.Name, in.Parent, string(grants), string(autos), now()); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "role.create", id, map[string]any{"name": in.Name, "parent": in.Parent, "grants": in.Grants, "automations": in.Automations})
	writeJSON(w, 201, map[string]any{"id": id})
}

func (s *Server) roleIDTaken(id string) bool {
	var one int
	return s.db.QueryRow(`SELECT 1 FROM roles WHERE id = ?`, id).Scan(&one) == nil
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if isBuiltinRole(id) {
		writeErr(w, http.StatusBadRequest, "built-in roles cannot be changed; create a role that inherits from one")
		return
	}
	if _, err := s.db.getRole(id); err != nil {
		writeErr(w, http.StatusNotFound, "role not found")
		return
	}
	var in roleInput
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if err := s.checkRoleInput(id, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	grants, _ := json.Marshal(in.Grants)
	autos, _ := in.Automations.MarshalJSON()
	if _, err := s.db.Exec(`UPDATE roles SET name = ?, parent = ?, grants = ?, automations = ? WHERE id = ?`,
		in.Name, in.Parent, string(grants), string(autos), id); err != nil {
		fail(w, err)
		return
	}
	// The role's accounts, and those of every role under it, may have just
	// lost the right to something they have open.
	s.recheckStreams()
	s.audit(r, "role.update", id, map[string]any{"name": in.Name, "parent": in.Parent, "grants": in.Grants, "automations": in.Automations})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if isBuiltinRole(id) {
		writeErr(w, http.StatusBadRequest, "built-in roles cannot be deleted")
		return
	}
	if _, err := s.db.getRole(id); err != nil {
		writeErr(w, http.StatusNotFound, "role not found")
		return
	}
	// Deleting a role in use would leave its accounts, or the roles built on
	// it, with a role that resolves to nothing.
	var users int
	s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ?`, id).Scan(&users)
	if users > 0 {
		writeErr(w, http.StatusConflict, fmt.Sprintf("%d account(s) have this role: give them another role first", users))
		return
	}
	rows, err := s.db.Query(`SELECT name FROM roles WHERE parent = ? ORDER BY name`, id)
	if err != nil {
		fail(w, err)
		return
	}
	var children []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			children = append(children, n)
		}
	}
	rows.Close()
	if len(children) > 0 {
		sort.Strings(children)
		writeErr(w, http.StatusConflict, "other roles inherit from this one: "+strings.Join(children, ", "))
		return
	}
	if _, err := s.db.Exec(`DELETE FROM roles WHERE id = ?`, id); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "role.delete", id, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}
