package server

import (
	"encoding/json"
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
	if in.AgentDefaults.MetricsIntervalSec < 5 {
		in.AgentDefaults.MetricsIntervalSec = 5
	}
	if in.AgentDefaults.InventoryIntervalSec < 60 {
		in.AgentDefaults.InventoryIntervalSec = 60
	}
	if in.AgentDefaults.PatchScanIntervalSec < 0 {
		in.AgentDefaults.PatchScanIntervalSec = 0
	}
	s.db.SetSetting("public_url", strings.TrimRight(strings.TrimSpace(in.PublicURL), "/"))
	s.db.SetSettingJSON("smtp", in.SMTP)
	s.db.SetSettingJSON("agent_defaults", in.AgentDefaults)
	s.db.SetSettingJSON("retention", in.Retention)
	s.audit(r, "settings.update", "", nil)
	// push new intervals to every connected agent
	for _, id := range s.hub.OnlineIDs() {
		s.pushAgentConfig(id)
	}
	s.handleGetSettings(w, r)
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
	var in struct{ Username, Password, Role, Email string }
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if in.Role == "" {
		in.Role = RoleTech
	}
	id, err := s.db.CreateUser(in.Username, in.Password, in.Role, in.Email)
	if err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "user.create", in.Username, map[string]string{"role": in.Role})
	writeJSON(w, 201, map[string]any{"id": id})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	var in struct {
		Role      string  `json:"role"`
		Email     *string `json:"email"`
		Password  string  `json:"password"`
		ResetTOTP bool    `json:"reset_totp"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if in.Role != "" {
		if in.Role != RoleAdmin && in.Role != RoleTech && in.Role != RoleViewer {
			writeErr(w, 400, "invalid role")
			return
		}
		if id == me.ID && in.Role != RoleAdmin {
			writeErr(w, 400, "you cannot demote yourself")
			return
		}
		s.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, in.Role, id)
	}
	if in.Email != nil {
		s.db.Exec(`UPDATE users SET email = ? WHERE id = ?`, *in.Email, id)
	}
	if in.Password != "" {
		if len(in.Password) < 8 {
			writeErr(w, 400, "password must be at least 8 characters")
			return
		}
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
	s.audit(r, "user.update", strconv.FormatInt(id, 10), map[string]any{"role": in.Role, "password_reset": in.Password != "", "reset_totp": in.ResetTOTP})
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
