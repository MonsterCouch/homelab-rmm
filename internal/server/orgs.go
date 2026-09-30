package server

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
)

type Organization struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DeviceCount int    `json:"device_count"`
	SiteCount   int    `json:"site_count"`
	CreatedAt   int64  `json:"created_at"`
}

type Site struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	Name        string `json:"name"`
	DeviceCount int    `json:"device_count"`
	CreatedAt   int64  `json:"created_at"`
}

// ---- DB methods for Organizations ----

func (d *DB) ListOrganizations() ([]Organization, error) {
	rows, err := d.Query(`SELECT o.id, o.name, o.created_at,
		(SELECT COUNT(*) FROM agents a WHERE a.org_id = o.id),
		(SELECT COUNT(*) FROM sites s WHERE s.org_id = o.id)
		FROM organizations o ORDER BY o.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Organization{}
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.CreatedAt, &o.DeviceCount, &o.SiteCount); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (d *DB) CreateOrganization(name string) (Organization, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Organization{}, errors.New("organization name cannot be empty")
	}
	id := "org_" + randomHex(6)
	t := now()
	_, err := d.Exec(`INSERT INTO organizations(id, name, created_at) VALUES(?,?,?)`, id, name, t)
	if err != nil {
		return Organization{}, err
	}
	// Automatically create a default "Main Site" for the new organization
	siteID := "site_" + randomHex(6)
	_, _ = d.Exec(`INSERT INTO sites(id, org_id, name, created_at) VALUES(?,?,?,?)`, siteID, id, "Main Site", t)
	return Organization{ID: id, Name: name, CreatedAt: t, SiteCount: 1}, nil
}

func (d *DB) UpdateOrganization(id, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("organization name cannot be empty")
	}
	res, err := d.Exec(`UPDATE organizations SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("organization not found")
	}
	return nil
}

func (d *DB) DeleteOrganization(id string) error {
	if id == "org_default" {
		return errors.New("cannot delete the default organization")
	}
	// Reassign any agents in this org to default organization and main site
	_, _ = d.Exec(`UPDATE agents SET org_id = 'org_default', site_id = 'site_default' WHERE org_id = ?`, id)
	_, _ = d.Exec(`UPDATE enroll_tokens SET org_id = 'org_default', site_id = 'site_default' WHERE org_id = ?`, id)
	res, err := d.Exec(`DELETE FROM organizations WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("organization not found")
	}
	return nil
}

// ---- DB methods for Sites ----

func (d *DB) ListSites(orgID string) ([]Site, error) {
	var rows *sql.Rows
	var err error
	if orgID != "" {
		rows, err = d.Query(`SELECT s.id, s.org_id, s.name, s.created_at,
			(SELECT COUNT(*) FROM agents a WHERE a.site_id = s.id)
			FROM sites s WHERE s.org_id = ? ORDER BY s.name`, orgID)
	} else {
		rows, err = d.Query(`SELECT s.id, s.org_id, s.name, s.created_at,
			(SELECT COUNT(*) FROM agents a WHERE a.site_id = s.id)
			FROM sites s ORDER BY s.name`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Site{}
	for rows.Next() {
		var s Site
		if err := rows.Scan(&s.ID, &s.OrgID, &s.Name, &s.CreatedAt, &s.DeviceCount); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) CreateSite(orgID, name string) (Site, error) {
	orgID = strings.TrimSpace(orgID)
	name = strings.TrimSpace(name)
	if orgID == "" || name == "" {
		return Site{}, errors.New("org_id and site name cannot be empty")
	}
	// verify org exists
	var exists int
	if err := d.QueryRow(`SELECT 1 FROM organizations WHERE id = ?`, orgID).Scan(&exists); err != nil {
		return Site{}, errors.New("organization does not exist")
	}
	id := "site_" + randomHex(6)
	t := now()
	_, err := d.Exec(`INSERT INTO sites(id, org_id, name, created_at) VALUES(?,?,?,?)`, id, orgID, name, t)
	if err != nil {
		return Site{}, err
	}
	return Site{ID: id, OrgID: orgID, Name: name, CreatedAt: t}, nil
}

func (d *DB) UpdateSite(id, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("site name cannot be empty")
	}
	res, err := d.Exec(`UPDATE sites SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("site not found")
	}
	return nil
}

func (d *DB) DeleteSite(id string) error {
	if id == "site_default" {
		return errors.New("cannot delete the default site")
	}
	// Reassign agents in this site to default site
	_, _ = d.Exec(`UPDATE agents SET site_id = 'site_default' WHERE site_id = ?`, id)
	_, _ = d.Exec(`UPDATE enroll_tokens SET site_id = 'site_default' WHERE site_id = ?`, id)
	res, err := d.Exec(`DELETE FROM sites WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("site not found")
	}
	return nil
}

// ---- HTTP handlers ----

func (s *Server) handleListOrganizations(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.db.ListOrganizations()
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if me != nil && !me.IsAdmin() && len(me.OrgScope) > 0 {
		filtered := []Organization{}
		allowed := make(map[string]bool)
		for _, o := range me.OrgScope {
			allowed[o] = true
		}
		for _, o := range orgs {
			if allowed[o.ID] {
				filtered = append(filtered, o)
			}
		}
		writeJSON(w, 200, filtered)
		return
	}
	writeJSON(w, 200, orgs)
}

func (s *Server) handleCreateOrganization(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	org, err := s.db.CreateOrganization(in.Name)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, "organization.create", org.ID, map[string]string{"name": org.Name})
	writeJSON(w, 201, org)
}

func (s *Server) handleUpdateOrganization(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if err := s.db.UpdateOrganization(id, in.Name); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, "organization.update", id, map[string]string{"name": in.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleDeleteOrganization(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.db.DeleteOrganization(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, "organization.delete", id, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	me := userFrom(r.Context())
	if orgID != "" && !s.canAccessAgent(me, orgID) {
		writeErr(w, http.StatusForbidden, "access denied")
		return
	}
	sites, err := s.db.ListSites(orgID)
	if err != nil {
		fail(w, err)
		return
	}
	if orgID == "" {
		filtered := []Site{}
		for _, site := range sites {
			if s.canAccessAgent(me, site.OrgID) {
				filtered = append(filtered, site)
			}
		}
		writeJSON(w, 200, filtered)
		return
	}
	writeJSON(w, 200, sites)
}

func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	site, err := s.db.CreateSite(orgID, in.Name)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, "site.create", site.ID, map[string]string{"org_id": orgID, "name": site.Name})
	writeJSON(w, 201, site)
}

func (s *Server) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if err := s.db.UpdateSite(id, in.Name); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, "site.update", id, map[string]string{"name": in.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.db.DeleteSite(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, "site.delete", id, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}
