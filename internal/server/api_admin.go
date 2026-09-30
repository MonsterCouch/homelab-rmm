package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Settings is the admin-editable configuration stored in the settings table.
type Settings struct {
	PublicURL     string               `json:"public_url"`
	SMTP          MailSettings         `json:"smtp"`
	AgentDefaults protocol.AgentConfig `json:"agent_defaults"`
	Retention     struct {
		MetricsDays int `json:"metrics_days"`
		RunsDays    int `json:"runs_days"`
		AuditDays   int `json:"audit_days"`
		EventsDays  int `json:"events_days"`
	} `json:"retention"`
}

func (s *Server) loadSettings() Settings {
	var st Settings
	st.PublicURL = s.db.Setting("public_url", "")
	st.SMTP = s.mail.settings()
	st.AgentDefaults = protocol.AgentConfig{MetricsIntervalSec: 30, InventoryIntervalSec: 3600, PatchScanIntervalSec: 6 * 3600}
	s.db.SettingJSON("agent_defaults", &st.AgentDefaults)
	// agent_defaults is an operator-editable blob unmarshalled into the same
	// struct the agent config is built from. Baselines are resolved per device
	// from their targets and must never travel through here: a set frozen into
	// this row would be pushed to every device whatever its targets say.
	st.AgentDefaults.Baselines = nil
	st.Retention.MetricsDays, st.Retention.RunsDays, st.Retention.AuditDays, st.Retention.EventsDays = 30, 90, 365, 30
	s.db.SettingJSON("retention", &st.Retention)
	return st
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	st := s.loadSettings()
	if st.SMTP.Password != "" {
		st.SMTP.Password = "********"
	}
	writeJSON(w, 200, st)
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	cur := s.loadSettings()
	var in Settings
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if in.SMTP.Password == "********" {
		in.SMTP.Password = cur.SMTP.Password
	}
	// Normalise the same way mail.settings() does when reading, so a saved
	// value reads back identically: without this every save "changed"
	// smtp.port 587->0 and wrote an audit row for a form nobody edited.
	if in.SMTP.Port == 0 {
		in.SMTP.Port = 587
	}
	if in.SMTP.TLSMode == "" {
		in.SMTP.TLSMode = "starttls"
	}
	if in.AgentDefaults.MetricsIntervalSec < 5 {
		in.AgentDefaults.MetricsIntervalSec = 5
	}
	if in.AgentDefaults.InventoryIntervalSec < 60 {
		in.AgentDefaults.InventoryIntervalSec = 60
	}
	if in.AgentDefaults.PatchScanIntervalSec < 0 {
		in.AgentDefaults.PatchScanIntervalSec = 0
	}
	// A retention of zero (or a field the caller left out) means "keep what is
	// configured", never "delete everything at the next purge" - which is what
	// PUT /api/settings with a partial body used to arm.
	for _, f := range []struct{ in, cur *int }{
		{&in.Retention.MetricsDays, &cur.Retention.MetricsDays},
		{&in.Retention.RunsDays, &cur.Retention.RunsDays},
		{&in.Retention.AuditDays, &cur.Retention.AuditDays},
		{&in.Retention.EventsDays, &cur.Retention.EventsDays},
	} {
		if *f.in <= 0 {
			*f.in = *f.cur
		}
	}
	in.PublicURL = strings.TrimRight(strings.TrimSpace(in.PublicURL), "/")
	changes := settingsDiff(cur, in)
	s.db.SetSetting("public_url", in.PublicURL)
	s.db.SetSettingJSON("smtp", in.SMTP)
	in.AgentDefaults.Baselines = nil // never stored in settings; see loadSettings
	s.db.SetSettingJSON("agent_defaults", in.AgentDefaults)
	s.db.SetSettingJSON("retention", in.Retention)
	// The audit log is the one place that answers "who changed what", and a
	// row with an empty Target and empty Details answered neither. A save
	// that changed nothing writes no row at all, so repeated saves of an
	// unedited form stop burying the rows that matter.
	if len(changes) > 0 {
		s.audit(r, "settings.update", strings.Join(changedKeys(changes), ","), strings.Join(changes, "; "))
	}
	// public_url is what install commands and email links embed, and the
	// certificate's SANs were fixed when it was generated.
	s.checkCertHost()
	// push new intervals to every connected agent
	for _, id := range s.hub.OnlineIDs() {
		s.pushAgentConfig(id)
	}
	s.handleGetSettings(w, r)
}

// settingsDiff describes what a save changed, as "key old->new" phrases.
// The SMTP password is never written out, only reported as changed.
func settingsDiff(before, after Settings) []string {
	var out []string
	add := func(key string, b, a any) {
		bs, as := fmt.Sprint(b), fmt.Sprint(a)
		if bs != as {
			out = append(out, fmt.Sprintf("%s %s->%s", key, quoteIfEmpty(bs), quoteIfEmpty(as)))
		}
	}
	add("public_url", before.PublicURL, after.PublicURL)
	add("smtp.enabled", before.SMTP.Enabled, after.SMTP.Enabled)
	add("smtp.host", before.SMTP.Host, after.SMTP.Host)
	add("smtp.port", before.SMTP.Port, after.SMTP.Port)
	add("smtp.tls", before.SMTP.TLSMode, after.SMTP.TLSMode)
	add("smtp.username", before.SMTP.Username, after.SMTP.Username)
	add("smtp.from", before.SMTP.From, after.SMTP.From)
	add("smtp.to", strings.Join(before.SMTP.To, " "), strings.Join(after.SMTP.To, " "))
	if before.SMTP.Password != after.SMTP.Password {
		out = append(out, "smtp.password ***->***")
	}
	add("agent_defaults.metrics_interval_sec", before.AgentDefaults.MetricsIntervalSec, after.AgentDefaults.MetricsIntervalSec)
	add("agent_defaults.inventory_interval_sec", before.AgentDefaults.InventoryIntervalSec, after.AgentDefaults.InventoryIntervalSec)
	add("agent_defaults.patch_scan_interval_sec", before.AgentDefaults.PatchScanIntervalSec, after.AgentDefaults.PatchScanIntervalSec)
	add("retention.metrics_days", before.Retention.MetricsDays, after.Retention.MetricsDays)
	add("retention.runs_days", before.Retention.RunsDays, after.Retention.RunsDays)
	add("retention.audit_days", before.Retention.AuditDays, after.Retention.AuditDays)
	add("retention.events_days", before.Retention.EventsDays, after.Retention.EventsDays)
	return out
}

func quoteIfEmpty(v string) string {
	if v == "" {
		return `""`
	}
	return v
}

// changedKeys is the key half of each diff phrase, for the audit Target
// column (which is what the console's list shows without opening the row).
func changedKeys(changes []string) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		if i := strings.IndexByte(c, ' '); i > 0 {
			out = append(out, c[:i])
		}
	}
	return out
}

func (s *Server) handleTestMail(w http.ResponseWriter, r *http.Request) {
	cur := s.loadSettings()
	var in MailSettings
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if in.Host == "" {
		in = cur.SMTP
	} else if in.Password == "********" {
		in.Password = cur.SMTP.Password
	}
	in.Enabled = true
	if err := sendMail(in, "[RMM] Test message", "Email from Homelab RMM is working.\n\nServer: "+s.PublicURL()); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- users ----

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	u, err := s.db.ListUsers()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, u)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		Role     string   `json:"role"`
		Email    string   `json:"email"`
		OrgScope []string `json:"org_scope"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if in.Role == "" {
		in.Role = RoleTech
	}
	id, err := s.db.CreateUserWithScope(in.Username, in.Password, in.Role, in.Email, in.OrgScope)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "user.create", in.Username, map[string]any{"role": in.Role, "org_scope": in.OrgScope})
	writeJSON(w, 201, map[string]any{"id": id})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	var in struct {
		Role      string    `json:"role"`
		Email     *string   `json:"email"`
		OrgScope  *[]string `json:"org_scope"`
		Password  string    `json:"password"`
		ResetTOTP bool      `json:"reset_totp"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	var curRole, curScope string
	if err := s.db.QueryRow(`SELECT role, org_scope FROM users WHERE id = ?`, id).Scan(&curRole, &curScope); err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	// Check everything before writing anything, against the role and
	// organizations the account will have once this lands.
	role, scope := curRole, parseOrgScope(curScope)
	me := userFrom(r.Context())
	if in.Role != "" {
		if !validRole(in.Role) {
			writeErr(w, 400, "invalid role")
			return
		}
		if id == me.ID && in.Role != RoleAdmin {
			writeErr(w, 400, "you cannot demote yourself")
			return
		}
		role = in.Role
	}
	if in.OrgScope != nil {
		scope = *in.OrgScope
	}
	if err := s.db.checkRoleScope(role, scope); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.Password != "" && len(in.Password) < 8 {
		writeErr(w, 400, "password must be at least 8 characters")
		return
	}

	if in.Role != "" {
		s.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, in.Role, id)
	}
	if in.Email != nil {
		s.db.Exec(`UPDATE users SET email = ? WHERE id = ?`, *in.Email, id)
	}
	if in.OrgScope != nil {
		b, _ := json.Marshal(*in.OrgScope)
		s.db.Exec(`UPDATE users SET org_scope = ? WHERE id = ?`, string(b), id)
	}
	if in.Password != "" {
		h, err := hashPassword(in.Password)
		if err != nil {
			fail(w, err)
			return
		}
		s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, h, id)
		s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, id)
	}
	if in.ResetTOTP {
		s.db.disableTOTP(id)
	}
	s.audit(r, "user.update", strconv.FormatInt(id, 10), map[string]any{
		"role":           in.Role,
		"org_scope":      in.OrgScope,
		"password_reset": in.Password != "",
		"reset_totp":     in.ResetTOTP,
	})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	if id == userFrom(r.Context()).ID {
		writeErr(w, 400, "you cannot delete yourself")
		return
	}
	s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	s.audit(r, "user.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

var _ = json.Marshal
