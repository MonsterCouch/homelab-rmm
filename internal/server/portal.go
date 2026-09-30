package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Every handler here runs behind portalGuard: portalCallerFrom is never nil,
// and who the caller is comes from it, never from the request. See
// portal_auth.go.

func stringInSlice(needle string, haystack []string) bool {
	for _, item := range haystack {
		if strings.EqualFold(item, needle) {
			return true
		}
	}
	return false
}

type PortalConfigResponse struct {
	AgentID      string `json:"agent_id"`
	AgentName    string `json:"agent_name"`
	ComputerName string `json:"computer_name"`
	DomainUser   string `json:"domain_user"`
	IsWorkgroup  bool   `json:"is_workgroup"`
	OrgID        string `json:"org_id"`
	OrgName      string `json:"org_name"`
	SiteID       string `json:"site_id"`
	SiteName     string `json:"site_name"`
	OS           string `json:"os"`
	IsPOC        bool   `json:"is_poc"`
	User         *User  `json:"user,omitempty"`
}

type PortalSoftwareItem struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Publisher        string `json:"publisher"`
	Version          string `json:"version"`
	Category         string `json:"category"`
	Icon             string `json:"icon"`
	Installed        bool   `json:"installed"`
	InstalledVersion string `json:"installed_version"`
	HasUpdate        bool   `json:"has_update"`
}

type PortalSoftwareActionReq struct {
	AgentID    string `json:"agent_id"` // console users only; a device user always acts on their own device
	SoftwareID string `json:"software_id"`
	Action     string `json:"action"` // "install", "uninstall", "update"
}

type PortalCreateTicketReq struct {
	AgentID        string `json:"agent_id"` // console users only
	Subject        string `json:"subject"`
	Description    string `json:"description"`
	RequesterName  string `json:"requester_name"`
	RequesterEmail string `json:"requester_email"`
	RequesterPhone string `json:"requester_phone"`
	Priority       string `json:"priority"`
}

type PortalCommentReq struct {
	Body string `json:"body"`
}

// agentOSFamily is "windows", "linux" or "" for anything else.
func agentOSFamily(a *Agent) string {
	low := strings.ToLower(a.OS)
	switch {
	case strings.Contains(low, "windows"):
		return "windows"
	case strings.Contains(low, "linux"):
		return "linux"
	}
	return ""
}

func (s *Server) handlePortalConfig(w http.ResponseWriter, r *http.Request) {
	c := portalCallerFrom(r.Context())
	var resp PortalConfigResponse
	if d := c.Device; d != nil {
		resp.DomainUser = d.User
		resp.IsWorkgroup = d.IsWorkgroup
	} else {
		resp.IsPOC = c.User.IsPOC()
		resp.User = c.User
		if c.User.IsPOC() {
			resp.OrgID = c.User.ContactOrg()
		} else if len(c.User.OrgScope) > 0 {
			resp.OrgID = c.User.OrgScope[0]
		}
	}
	if a, err := s.portalAgent(r, c, r.URL.Query().Get("agent_id")); err == nil {
		resp.AgentID = a.ID
		resp.AgentName = a.DisplayName
		resp.ComputerName = a.Hostname
		resp.OrgID = a.OrgID
		resp.OrgName = a.OrgName
		resp.SiteID = a.SiteID
		resp.SiteName = a.SiteName
		resp.OS = a.OS
	}
	writeJSON(w, http.StatusOK, resp)
}

// errContactTicketsOnly is the answer to a client contact asking for anything
// in the portal but tickets.
const errContactTicketsOnly = "client contacts can only use support tickets"

func (s *Server) handlePortalSoftware(w http.ResponseWriter, r *http.Request) {
	c := portalCallerFrom(r.Context())
	if c.User.IsPOC() {
		writeErr(w, http.StatusForbidden, errContactTicketsOnly)
		return
	}
	a, err := s.portalAgent(r, c, r.URL.Query().Get("agent_id"))
	switch {
	case err == nil:
	case c.User != nil && errors.Is(err, errPortalNoDevice):
		// a console user browsing the catalog without a device in mind
		a = nil
	default:
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}

	osFilter := "all"
	if a != nil {
		if fam := agentOSFamily(a); fam != "" {
			osFilter = fam
		}
	}

	catalog, err := s.db.ListSoftwareCatalog(osFilter)
	if err != nil {
		fail(w, err)
		return
	}

	var installedSoftware []protocol.Software
	if a != nil && a.Inventory != nil && len(a.Inventory.Software) > 0 {
		installedSoftware = a.Inventory.Software
	}

	out := make([]PortalSoftwareItem, 0, len(catalog))
	for _, it := range catalog {
		pItem := PortalSoftwareItem{
			ID:          it.ID,
			Name:        it.Name,
			Description: it.Description,
			Publisher:   it.Publisher,
			Version:     it.Version,
			Category:    it.Category,
			Icon:        it.Icon,
		}

		itName := strings.ToLower(strings.TrimSpace(it.Name))
		itPub := strings.ToLower(strings.TrimSpace(it.Publisher))
		for _, inst := range installedSoftware {
			instName := strings.ToLower(strings.TrimSpace(inst.Name))
			instPub := strings.ToLower(strings.TrimSpace(inst.Publisher))
			match := strings.EqualFold(instName, itName) ||
				strings.Contains(instName, itName) ||
				strings.Contains(itName, instName) ||
				(itPub != "" && instPub != "" && strings.EqualFold(instPub, itPub) && (strings.Contains(instName, itName) || strings.Contains(itName, instName)))
			if match {
				pItem.Installed = true
				pItem.InstalledVersion = inst.Version
				if it.Version != "" && !strings.EqualFold(it.Version, "Latest") && !strings.EqualFold(it.Version, inst.Version) {
					pItem.HasUpdate = true
				}
				break
			}
		}

		out = append(out, pItem)
	}

	writeJSON(w, http.StatusOK, out)
}

func ensureWinGetFlags(cmd, action string) string {
	if !strings.Contains(cmd, "winget") {
		return cmd
	}
	if !strings.Contains(cmd, "--disable-interactivity") {
		cmd += " --disable-interactivity"
	}
	if !strings.Contains(cmd, "--silent") && !strings.Contains(cmd, "-h") {
		cmd += " --silent"
	}
	if action == "install" || action == "update" {
		if !strings.Contains(cmd, "--scope") {
			cmd += " --scope machine"
		}
		if !strings.Contains(cmd, "--accept-source-agreements") {
			cmd += " --accept-source-agreements"
		}
		if !strings.Contains(cmd, "--accept-package-agreements") {
			cmd += " --accept-package-agreements"
		}
	}
	return strings.TrimSpace(cmd)
}

func (s *Server) handlePortalSoftwareAction(w http.ResponseWriter, r *http.Request) {
	c := portalCallerFrom(r.Context())
	if c.User.IsPOC() {
		writeErr(w, http.StatusForbidden, errContactTicketsOnly)
		return
	}
	if c.User != nil && !c.User.CanWrite() {
		writeErr(w, http.StatusForbidden, "read-only account")
		return
	}

	var req PortalSoftwareActionReq
	if err := readJSON(r, &req); err != nil {
		fail(w, err)
		return
	}

	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	if req.Action != "install" && req.Action != "uninstall" && req.Action != "update" {
		writeErr(w, http.StatusBadRequest, "action must be install, uninstall, or update")
		return
	}

	a, err := s.portalAgent(r, c, req.AgentID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}

	item, err := s.db.GetSoftwareCatalogItem(req.SoftwareID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "software item not found in catalog")
		return
	}

	// The catalog item's commands are written for one system. Sending a
	// winget line to a Linux device, or a shell line to Windows, only fails
	// on the device after the user has been told it started.
	fam := agentOSFamily(a)
	if item.OS != "" && item.OS != "all" && item.OS != fam {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("%s is not available for this device's operating system", item.Name))
		return
	}
	isWin := fam == "windows"
	lang := "powershell"
	if !isWin {
		lang = "bash"
	}

	var cmd string
	switch req.Action {
	case "install":
		cmd = item.InstallCmd
		if cmd == "" && isWin {
			cmd = fmt.Sprintf("winget install --id %s -e --silent --accept-source-agreements --accept-package-agreements --disable-interactivity", item.Name)
		}
	case "uninstall":
		cmd = item.UninstallCmd
		if cmd == "" && isWin {
			cmd = fmt.Sprintf("winget uninstall --id %s -e --silent --disable-interactivity", item.Name)
		}
	case "update":
		cmd = item.UpdateCmd
		if cmd == "" {
			if strings.Contains(item.InstallCmd, "winget install") {
				cmd = strings.Replace(item.InstallCmd, "winget install", "winget upgrade", 1)
			} else {
				cmd = item.InstallCmd
			}
		}
		if cmd == "" && isWin {
			cmd = fmt.Sprintf("winget upgrade --id %s -e --silent --accept-source-agreements --accept-package-agreements --disable-interactivity", item.Name)
		}
	}

	if strings.TrimSpace(cmd) == "" {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("no %s command available for %s", req.Action, item.Name))
		return
	}

	if isWin {
		cmd = ensureWinGetFlags(cmd, req.Action)
	}

	who := ""
	if c.Device != nil {
		who = c.Device.User
	} else {
		who = c.User.Username
	}
	runReq := RunRequest{
		Language: lang,
		Body:     cmd,
		Timeout:  600,
		Trigger:  "client-portal",
		RunBy:    fmt.Sprintf("portal:%s:%s", req.Action, who),
		Name:     fmt.Sprintf("Self-Service: %s %s", strings.Title(req.Action), item.Name),
	}

	runID, err := s.runs.Start(a.ID, runReq)
	if err != nil {
		fail(w, err)
		return
	}

	s.hub.broadcast(hubEvent{
		Kind:    "event",
		AgentID: a.ID,
		Data: map[string]any{
			"ts":      time.Now().Unix(),
			"kind":    "software",
			"message": fmt.Sprintf("Self-service %s of %s requested by %s", req.Action, item.Name, who),
			"fields": map[string]any{
				"software": item.Name,
				"action":   req.Action,
				"source":   "client-portal",
				"user":     who,
				"run_id":   runID,
			},
		},
	})

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":       true,
		"run_id":   runID,
		"status":   "started",
		"app_name": item.Name,
		"message":  fmt.Sprintf("%s initiated for %s", strings.Title(req.Action), item.Name),
	})
}

// handlePortalGetRun reports on a run the portal started. A device user sees
// runs on their own device only; a console user, runs on devices they can see.
func (s *Server) handlePortalGetRun(w http.ResponseWriter, r *http.Request) {
	c := portalCallerFrom(r.Context())
	if c.User.IsPOC() {
		writeErr(w, http.StatusForbidden, errContactTicketsOnly)
		return
	}
	run, err := s.db.GetRun(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "run not found")
		return
	}
	allowed := false
	if c.Device != nil {
		allowed = run.AgentID == c.Device.AgentID && run.Trigger == "client-portal"
	} else if a, err := s.db.GetAgent(run.AgentID); err == nil {
		allowed = s.canAccessAgent(c.User, a.OrgID)
	}
	if !allowed {
		writeErr(w, http.StatusNotFound, "run not found")
		return
	}
	if so, se, ok := s.runs.Live(run.ID); ok {
		run.Stdout, run.Stderr = so, se
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          run.ID,
		"status":      run.Status,
		"exit_code":   run.ExitCode,
		"stdout":      run.Stdout,
		"stderr":      run.Stderr,
		"started_at":  run.StartedAt,
		"finished_at": run.FinishedAt,
	})
}

func (s *Server) handlePortalListTickets(w http.ResponseWriter, r *http.Request) {
	c := portalCallerFrom(r.Context())
	filter := TicketFilter{
		Status:          r.URL.Query().Get("status"),
		Query:           r.URL.Query().Get("q"),
		IncludeInternal: false, // End users & POCs NEVER see internal alert tickets!
	}

	switch {
	case c.Device != nil:
		a, err := s.db.GetAgent(c.Device.AgentID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "device not found")
			return
		}
		if c.Device.IsWorkgroup {
			// a local account: the tickets submitted from this device
			filter.AgentID = a.ID
		} else {
			// a domain account: that user's tickets at this organization
			filter.RequesterDomainUser = c.Device.User
			filter.OrgID = a.OrgID
		}
	case c.User.IsPOC():
		// A client's point of contact sees every non-internal ticket for
		// their organization, and nothing without one.
		if c.User.ContactOrg() == "" {
			writeJSON(w, http.StatusOK, []Ticket{})
			return
		}
		filter.OrgID = c.User.ContactOrg()
	default:
		// A technician looking at the portal for one device.
		a, err := s.portalAgent(r, c, r.URL.Query().Get("agent_id"))
		if err != nil {
			writeJSON(w, http.StatusOK, []Ticket{})
			return
		}
		filter.AgentID = a.ID
	}

	tickets, err := s.db.ListTicketsFiltered(filter)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tickets)
}

func (s *Server) handlePortalGetTicket(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	twc, err := s.db.GetTicket(id)
	// one answer for missing and forbidden, so ticket numbers cannot be probed
	if err != nil || !s.portalCanSeeTicket(portalCallerFrom(r.Context()), &twc.Ticket) {
		writeErr(w, http.StatusNotFound, "ticket not found")
		return
	}

	// Filter out internal comments
	publicComments := make([]TicketComment, 0, len(twc.Comments))
	for _, c := range twc.Comments {
		if !c.IsInternal {
			publicComments = append(publicComments, c)
		}
	}
	twc.Comments = publicComments

	writeJSON(w, http.StatusOK, twc)
}

func (s *Server) handlePortalCreateTicket(w http.ResponseWriter, r *http.Request) {
	c := portalCallerFrom(r.Context())
	var req PortalCreateTicketReq
	if err := readJSON(r, &req); err != nil {
		fail(w, err)
		return
	}

	if strings.TrimSpace(req.Subject) == "" || strings.TrimSpace(req.Description) == "" {
		writeErr(w, http.StatusBadRequest, "subject and description are required")
		return
	}

	ticket := Ticket{
		Subject:        strings.TrimSpace(req.Subject),
		Description:    strings.TrimSpace(req.Description),
		RequesterName:  strings.TrimSpace(req.RequesterName),
		RequesterEmail: strings.TrimSpace(req.RequesterEmail),
		RequesterPhone: strings.TrimSpace(req.RequesterPhone),
		Priority:       req.Priority,
		IsInternal:     false,
		Source:         "portal",
		Status:         "open",
	}

	if ticket.Priority == "" {
		ticket.Priority = "normal"
	}

	if c.Device != nil {
		ticket.RequesterDomainUser = c.Device.User
		if ticket.RequesterName == "" {
			ticket.RequesterName = c.Device.User
		}
	} else {
		if ticket.RequesterName == "" {
			ticket.RequesterName = c.User.Username
		}
		if ticket.RequesterEmail == "" {
			ticket.RequesterEmail = c.User.Email
		}
	}

	if a, err := s.portalAgent(r, c, req.AgentID); err == nil {
		ticket.AgentID = a.ID
		ticket.OrgID = a.OrgID
		ticket.SiteID = a.SiteID
	} else if c.Device != nil {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	} else if c.User.IsPOC() {
		if ticket.OrgID = c.User.ContactOrg(); ticket.OrgID == "" {
			writeErr(w, http.StatusForbidden, "this account is not linked to an organization")
			return
		}
	}

	created, err := s.db.CreateTicket(&ticket)
	if err != nil {
		fail(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"ok": true,
		"id": created.ID,
	})
}

func (s *Server) handlePortalAddComment(w http.ResponseWriter, r *http.Request) {
	c := portalCallerFrom(r.Context())
	id, err := pathInt(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	twc, err := s.db.GetTicket(id)
	if err != nil || !s.portalCanSeeTicket(c, &twc.Ticket) {
		writeErr(w, http.StatusNotFound, "ticket not found")
		return
	}

	var req PortalCommentReq
	if err := readJSON(r, &req); err != nil {
		fail(w, err)
		return
	}

	if strings.TrimSpace(req.Body) == "" {
		writeErr(w, http.StatusBadRequest, "comment body cannot be empty")
		return
	}

	// The author is whoever is signed in, never a name the request carries.
	author := ""
	if c.Device != nil {
		author = c.Device.User
	} else {
		author = c.User.Username
	}

	comment := TicketComment{
		TicketID:   id,
		Author:     author,
		IsInternal: false,
		Body:       strings.TrimSpace(req.Body),
	}

	created, err := s.db.CreateTicketComment(&comment)
	if err != nil {
		fail(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, created)
}
