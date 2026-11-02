package server

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SoftwareCatalogItem struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Publisher    string `json:"publisher"`
	Version      string `json:"version"`
	Category     string `json:"category"`
	Icon         string `json:"icon"`
	InstallCmd   string `json:"install_cmd"`
	UninstallCmd string `json:"uninstall_cmd"`
	UpdateCmd    string `json:"update_cmd"`
	OS           string `json:"os"` // windows, linux, all
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

func (d *DB) ListSoftwareCatalog(osFilter string) ([]SoftwareCatalogItem, error) {
	q := `SELECT id, name, description, publisher, version, category, icon, install_cmd, uninstall_cmd, COALESCE(update_cmd, ''), os, created_at, updated_at FROM software_catalog`
	var args []any
	if osFilter != "" && osFilter != "all" {
		q += ` WHERE os = ? OR os = 'all'`
		args = append(args, osFilter)
	}
	q += ` ORDER BY category, name`

	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SoftwareCatalogItem{}
	for rows.Next() {
		var it SoftwareCatalogItem
		if err := rows.Scan(&it.ID, &it.Name, &it.Description, &it.Publisher, &it.Version, &it.Category, &it.Icon, &it.InstallCmd, &it.UninstallCmd, &it.UpdateCmd, &it.OS, &it.CreatedAt, &it.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (d *DB) GetSoftwareCatalogItem(id string) (*SoftwareCatalogItem, error) {
	var it SoftwareCatalogItem
	err := d.QueryRow(`SELECT id, name, description, publisher, version, category, icon, install_cmd, uninstall_cmd, COALESCE(update_cmd, ''), os, created_at, updated_at FROM software_catalog WHERE id = ?`, id).
		Scan(&it.ID, &it.Name, &it.Description, &it.Publisher, &it.Version, &it.Category, &it.Icon, &it.InstallCmd, &it.UninstallCmd, &it.UpdateCmd, &it.OS, &it.CreatedAt, &it.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return &it, err
}

func (d *DB) SaveSoftwareCatalogItem(it *SoftwareCatalogItem) error {
	now := time.Now().Unix()
	if it.CreatedAt == 0 {
		it.CreatedAt = now
	}
	it.UpdatedAt = now
	if it.ID == "" {
		it.ID = "sw_" + randomHex(6)
	}
	_, err := d.Exec(`INSERT INTO software_catalog (id, name, description, publisher, version, category, icon, install_cmd, uninstall_cmd, update_cmd, os, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			description = excluded.description,
			publisher = excluded.publisher,
			version = excluded.version,
			category = excluded.category,
			icon = excluded.icon,
			install_cmd = excluded.install_cmd,
			uninstall_cmd = excluded.uninstall_cmd,
			update_cmd = excluded.update_cmd,
			os = excluded.os,
			updated_at = excluded.updated_at`,
		it.ID, it.Name, it.Description, it.Publisher, it.Version, it.Category, it.Icon, it.InstallCmd, it.UninstallCmd, it.UpdateCmd, it.OS, it.CreatedAt, it.UpdatedAt)
	return err
}

func (d *DB) DeleteSoftwareCatalogItem(id string) error {
	_, err := d.Exec(`DELETE FROM software_catalog WHERE id = ?`, id)
	return err
}

func (s *Server) handleListSoftwareCatalog(w http.ResponseWriter, r *http.Request) {
	osFilter := r.URL.Query().Get("os")
	items, err := s.db.ListSoftwareCatalog(osFilter)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, items)
}

func (s *Server) handleGetSoftwareCatalogItem(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	item, err := s.db.GetSoftwareCatalogItem(id)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) handleCreateSoftwareCatalogItem(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if u == nil || !u.IsAdmin() {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	var it SoftwareCatalogItem
	if err := readJSON(r, &it); err != nil {
		fail(w, err)
		return
	}
	if strings.TrimSpace(it.Name) == "" || strings.TrimSpace(it.InstallCmd) == "" {
		writeErr(w, http.StatusBadRequest, "name and install_cmd are required")
		return
	}
	if it.OS == "" {
		it.OS = "all"
	}
	if err := s.db.SaveSoftwareCatalogItem(&it); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "software_catalog.create", it.Name, nil)
	writeJSON(w, 201, it)
}

func (s *Server) handleUpdateSoftwareCatalogItem(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if u == nil || !u.IsAdmin() {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	id := r.PathValue("id")
	existing, err := s.db.GetSoftwareCatalogItem(id)
	if err != nil {
		fail(w, err)
		return
	}
	var it SoftwareCatalogItem
	if err := readJSON(r, &it); err != nil {
		fail(w, err)
		return
	}
	it.ID = existing.ID
	it.CreatedAt = existing.CreatedAt
	if strings.TrimSpace(it.Name) == "" || strings.TrimSpace(it.InstallCmd) == "" {
		writeErr(w, http.StatusBadRequest, "name and install_cmd are required")
		return
	}
	if it.OS == "" {
		it.OS = existing.OS
	}
	if err := s.db.SaveSoftwareCatalogItem(&it); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "software_catalog.update", it.Name, nil)
	writeJSON(w, 200, it)
}

func (s *Server) handleDeleteSoftwareCatalogItem(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if u == nil || !u.IsAdmin() {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	id := r.PathValue("id")
	if err := s.db.DeleteSoftwareCatalogItem(id); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "software_catalog.delete", id, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

type agentSoftwareReq struct {
	CatalogID string `json:"catalog_id"`
	CustomCmd string `json:"custom_cmd,omitempty"`
}

func (s *Server) handleAgentSoftwareInstall(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, agentID)
	if !ok {
		return
	}

	var req agentSoftwareReq
	if err := readJSON(r, &req); err != nil {
		fail(w, err)
		return
	}

	var installCmd string
	var appName string
	if req.CatalogID != "" {
		it, err := s.db.GetSoftwareCatalogItem(req.CatalogID)
		if err != nil {
			fail(w, err)
			return
		}
		installCmd = it.InstallCmd
		appName = it.Name
	} else if req.CustomCmd != "" {
		// Only admins may run custom commands
		u := userFrom(r.Context())
		if u == nil || !u.IsAdmin() {
			writeErr(w, http.StatusForbidden, "custom commands require admin role")
			return
		}
		installCmd = req.CustomCmd
		appName = "Custom Software"
	} else {
		writeErr(w, http.StatusBadRequest, "catalog_id or custom_cmd is required")
		return
	}

	lang := "powershell"
	if a.OS == "linux" || a.OS == "darwin" {
		lang = "bash"
	}

	runReq := RunRequest{
		Language: lang,
		Body:     installCmd,
		Timeout:  600, // 10 minutes max for software installs
		Trigger:  "software-install",
		RunBy:    actor(r),
		Name:     fmt.Sprintf("Install: %s", appName),
	}

	// An operator is present, so this is signed like any script run (the
	// catalog item's standing approval is for the client portal, whose
	// contacts never sign).
	s.startOneRun(w, r, runReq, agentID, a.OrgID, func(w http.ResponseWriter, r *http.Request, runID string, err error) {
		if err != nil {
			fail(w, err)
			return
		}

		s.audit(r, "software.install", fmt.Sprintf("%s on %s", appName, a.DisplayName), map[string]any{
			"agent_id": agentID,
			"app":      appName,
			"run_id":   runID,
		})

		writeJSON(w, 202, map[string]any{
			"run_id":   runID,
			"status":   "started",
			"app_name": appName,
		})
	})
}

func (s *Server) handleAgentSoftwareUninstall(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, agentID)
	if !ok {
		return
	}

	var req agentSoftwareReq
	if err := readJSON(r, &req); err != nil {
		fail(w, err)
		return
	}

	var uninstallCmd string
	var appName string
	if req.CatalogID != "" {
		it, err := s.db.GetSoftwareCatalogItem(req.CatalogID)
		if err != nil {
			fail(w, err)
			return
		}
		if it.UninstallCmd == "" {
			writeErr(w, http.StatusBadRequest, "no uninstall command configured for this catalog item")
			return
		}
		uninstallCmd = it.UninstallCmd
		appName = it.Name
	} else if req.CustomCmd != "" {
		u := userFrom(r.Context())
		if u == nil || !u.IsAdmin() {
			writeErr(w, http.StatusForbidden, "custom commands require admin role")
			return
		}
		uninstallCmd = req.CustomCmd
		appName = "Custom Software"
	} else {
		writeErr(w, http.StatusBadRequest, "catalog_id or custom_cmd is required")
		return
	}

	lang := "powershell"
	if a.OS == "linux" || a.OS == "darwin" {
		lang = "bash"
	}

	runReq := RunRequest{
		Language: lang,
		Body:     uninstallCmd,
		Timeout:  600,
		Trigger:  "software-uninstall",
		RunBy:    actor(r),
		Name:     fmt.Sprintf("Uninstall: %s", appName),
	}

	s.startOneRun(w, r, runReq, agentID, a.OrgID, func(w http.ResponseWriter, r *http.Request, runID string, err error) {
		if err != nil {
			fail(w, err)
			return
		}

		s.audit(r, "software.uninstall", fmt.Sprintf("%s on %s", appName, a.DisplayName), map[string]any{
			"agent_id": agentID,
			"app":      appName,
			"run_id":   runID,
		})

		writeJSON(w, 202, map[string]any{
			"run_id":   runID,
			"status":   "started",
			"app_name": appName,
		})
	})
}
