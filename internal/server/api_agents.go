package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const (
	quickTimeout = 30 * time.Second
	longTimeout  = 20 * time.Minute
)

// canAccessAgent reports whether the user is permitted to view or manage the agent
// under their assigned multi-tenant scope. Admins and unscoped users may access any agent.
func (s *Server) canAccessAgent(u *User, agentOrgID string) bool {
	if u == nil {
		return false
	}
	// A client contact reaches their own organization's devices only, and
	// never "all of them" by having no scope.
	if u.IsPOC() {
		return agentOrgID != "" && agentOrgID == u.ContactOrg()
	}
	if u.IsAdmin() || len(u.OrgScope) == 0 {
		return true
	}
	for _, o := range u.OrgScope {
		if agentOrgID == o {
			return true
		}
	}
	return false
}

// getScopedAgent fetches an agent by ID and ensures the requesting user has permission
// to access it under their multi-tenant OrgScope.
func (s *Server) getScopedAgent(w http.ResponseWriter, r *http.Request, agentID string) (*Agent, bool) {
	a, err := s.db.GetAgent(agentID)
	if err != nil {
		fail(w, err)
		return nil, false
	}
	u := userFrom(r.Context())
	if !s.canAccessAgent(u, a.OrgID) {
		writeErr(w, http.StatusNotFound, "agent not found")
		return nil, false
	}
	return a, true
}

// validateTargetsScope checks whether user u is permitted to target the devices specified by t.
// Administrators can target anything.
// Scoped technicians and users cannot target globally (Targets.All), cannot target without specifying
// an organization scope, and cannot target organizations, sites, or agents outside their assigned OrgScope.
func (s *Server) validateTargetsScope(u *User, t Targets) error {
	if u == nil {
		return errors.New("unauthenticated")
	}
	if u.IsAdmin() {
		return nil
	}
	// Global targeting requires administrator privileges
	if t.All && len(t.Organizations) == 0 && len(t.Sites) == 0 {
		return errors.New("global targeting requires administrator privileges")
	}
	// Tags and groups are fleet-wide selectors; non-administrators must bind them to an organization or site within scope
	if (len(t.Tags) > 0 || len(t.Groups) > 0) && len(t.Organizations) == 0 && len(t.Sites) == 0 {
		return errors.New("targeting by tags or groups requires specifying an organization or site within your scope")
	}
	// Non-admin technicians must not leave targets unscoped (which would match all organizations)
	if len(t.Organizations) == 0 && len(t.Agents) == 0 && len(t.Sites) == 0 {
		return errors.New("targets must be scoped to your assigned organization or devices")
	}
	// Verify each specified organization is within user's scope
	for _, org := range t.Organizations {
		if !s.canAccessAgent(u, org) {
			return errors.New("targets outside assigned organization scope")
		}
	}
	// Verify each specified agent is within user's scope
	for _, agentID := range t.Agents {
		var orgID string
		if err := s.db.QueryRow(`SELECT org_id FROM agents WHERE id = ?`, agentID).Scan(&orgID); err != nil {
			return errors.New("target agent not found")
		}
		if !s.canAccessAgent(u, orgID) {
			return errors.New("targets outside assigned organization scope")
		}
	}
	// Verify each specified site belongs to an organization within user's scope
	for _, siteID := range t.Sites {
		var orgID string
		if err := s.db.QueryRow(`SELECT org_id FROM sites WHERE id = ?`, siteID).Scan(&orgID); err != nil {
			return errors.New("target site not found")
		}
		if !s.canAccessAgent(u, orgID) {
			return errors.New("targets outside assigned organization scope")
		}
	}
	// Verify that any currently matching devices are all within user's scope
	matched, err := s.db.ResolveTargets(t)
	if err != nil {
		return err
	}
	for _, a := range matched {
		if !s.canAccessAgent(u, a.OrgID) {
			return errors.New("targets match devices outside assigned organization scope")
		}
	}
	return nil
}

// canAccessTargets reports whether user u has permission to access or run an entity targeting t.
func (s *Server) canAccessTargets(u *User, t Targets) bool {
	return s.validateTargetsScope(u, t) == nil
}

// agentRow is a device as the device list and detail endpoints return it: the
// stored Agent plus how it is connected right now. Transport is only the hub's
// to know, so it is stamped here rather than stored; it is absent for a device
// that is offline.
type agentRow struct {
	*Agent
	Transport string `json:"transport,omitempty"` // "websocket" or "quic"
}

func (s *Server) agentRowFor(a *Agent) agentRow {
	row := agentRow{Agent: a}
	if ac, ok := s.hub.get(a.ID); ok {
		row.Transport = ac.transportName()
	}
	return row
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.agentsWithLiveness()
	if err != nil {
		fail(w, err)
		return
	}
	reqOrg := r.URL.Query().Get("org_id")
	reqSite := r.URL.Query().Get("site_id")
	me := userFrom(r.Context())

	filtered := make([]*Agent, 0, len(agents))
	for _, a := range agents {
		if !s.canAccessAgent(me, a.OrgID) {
			continue
		}
		if reqOrg != "" && a.OrgID != reqOrg {
			continue
		}
		if reqSite != "" && a.SiteID != reqSite {
			continue
		}
		filtered = append(filtered, a)
	}
	rows := make([]agentRow, len(filtered))
	for i, a := range filtered {
		rows[i] = s.agentRowFor(a)
	}
	writeJSON(w, 200, rows)
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	a, ok := s.getScopedAgent(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	a.Online = s.hub.IsOnline(a.ID)
	writeJSON(w, 200, s.agentRowFor(a))
}

func (s *Server) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in AgentUpdate
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if err := in.Validate(); err != nil {
		fail(w, err)
		return
	}
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	u := userFrom(r.Context())
	if !u.IsAdmin() && (in.OrgID != nil || in.SiteID != nil) {
		writeErr(w, http.StatusForbidden, "only administrators can change organization or site")
		return
	}
	// A group or tag change moves the device in and out of target sets, so
	// the baselines it matches change with it. Snapshot before the write.
	membership := in.GroupID != nil || in.ClearGroup || in.Tags != nil
	var before map[int64]bool
	if membership {
		before = s.assignedBaselineIDs(id)
	}
	if err := s.db.UpdateAgent(id, in); err != nil {
		fail(w, err)
		return
	}
	switch {
	case membership:
		// Cleans up the baselines the device no longer matches AND pushes the
		// new config; a device that kept evaluating an unassigned baseline
		// would keep reporting drift nothing can resolve.
		s.agentMembershipChanged(id, before)
	case in.MonitoredServices != nil:
		s.pushAgentConfig(id)
	}
	s.audit(r, "agent.update", id, in)
	s.handleGetAgent(w, r)
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	s.hub.Disconnect(id)
	s.portal.dropAgent(id)
	if err := s.db.DeleteAgent(id); err != nil {
		fail(w, err)
		return
	}
	// Results, state and alerts cascade with the row; the baseline engine's
	// in-memory counters for the device do not, so drop them here.
	s.baselines.forgetAgent(id)
	s.audit(r, "agent.delete", id, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleAgentMetrics(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	to := queryInt(r, "to", now())
	from := queryInt(r, "from", to-3600)
	rows, err := s.db.MetricsRange(id, from, to, int(queryInt(r, "points", 400)))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, rows)
}

func (s *Server) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	rows, err := s.db.Query(`SELECT id, ts, kind, message, fields FROM agent_events WHERE agent_id = ? ORDER BY ts DESC LIMIT ?`, id, queryInt(r, "limit", 100))
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	type ev struct {
		ID      int64          `json:"id"`
		TS      int64          `json:"ts"`
		Kind    string         `json:"kind"`
		Message string         `json:"message"`
		Fields  map[string]any `json:"fields"`
	}
	out := []ev{}
	for rows.Next() {
		var e ev
		var f string
		rows.Scan(&e.ID, &e.TS, &e.Kind, &e.Message, &f)
		json.Unmarshal([]byte(f), &e.Fields)
		out = append(out, e)
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleAgentRefresh(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := s.hub.Request(ctx, id, protocol.ReqInventoryRefresh, nil, nil); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- processes ----

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
	defer cancel()
	var out []protocol.Process
	if err := s.hub.Request(ctx, id, protocol.ReqProcList, nil, &out); err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []protocol.Process{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleProcKill(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}
	var in protocol.ProcKill
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	s.runSigned(w, r, signedAction{
		Org: a.OrgID, Op: protocol.ReqProcKill, Targets: []string{id}, Payload: in,
		Summary: fmt.Sprintf("Kill process %d on %s", in.PID, agentLabel(a)),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
			defer cancel()
			if err := s.hub.RequestA(ctx, id, protocol.ReqProcKill, in, nil, auth); err != nil {
				// A refusal is audited too. "Nobody tried" and "someone tried and the
				// device said no" are different answers to the question this log is
				// read to answer, and the attempt is fully attributed right here.
				s.audit(r, "process.kill", id, auditFailure(map[string]any{"pid": in.PID}, err))
				fail(w, err)
				return
			}
			s.audit(r, "process.kill", id, in)
			writeJSON(w, 200, map[string]any{"ok": true})
		},
	})
}

// agentLabel is how a device is named in what an operator is asked to sign.
func agentLabel(a *Agent) string {
	if a.DisplayName != "" {
		return a.DisplayName
	}
	return a.Hostname
}

// ---- services ----

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
	defer cancel()
	var out []protocol.Service
	if err := s.hub.Request(ctx, id, protocol.ReqSvcList, nil, &out); err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []protocol.Service{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}
	var in protocol.SvcAction
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	s.runSigned(w, r, signedAction{
		Org: a.OrgID, Op: protocol.ReqSvcAction, Targets: []string{id}, Payload: in,
		Summary: fmt.Sprintf("%s service %q on %s", in.Action, in.Name, agentLabel(a)),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
			defer cancel()
			var out protocol.Service
			if err := s.hub.RequestA(ctx, id, protocol.ReqSvcAction, in, &out, auth); err != nil {
				// Audited on the way out as well: a stop the SCM denied is exactly
				// what somebody probing which security services they can turn off
				// looks like, and only the failure path sees it.
				s.audit(r, "service."+in.Action, id, auditFailure(map[string]any{"name": in.Name}, err))
				fail(w, err)
				return
			}
			s.audit(r, "service."+in.Action, id, in.Name)
			writeJSON(w, 200, out)
		},
	})
}

// auditFailure labels an audit detail as an attempt that did not happen and
// says why. Successful entries keep their existing shape; the "outcome" key
// is what tells the two apart.
func auditFailure(details map[string]any, err error) map[string]any {
	details["outcome"] = "failed"
	details["error"] = err.Error()
	return details
}

// ---- event log ----

func (s *Server) handleEventLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	q := protocol.EventLogQuery{
		Log:     r.URL.Query().Get("log"),
		Level:   r.URL.Query().Get("level"),
		Limit:   int(queryInt(r, "limit", 200)),
		Search:  r.URL.Query().Get("search"),
		SinceTS: queryInt(r, "since", 0),
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	var out []protocol.EventLogEntry
	if err := s.hub.Request(ctx, id, protocol.ReqEventLogQuery, q, &out); err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []protocol.EventLogEntry{}
	}
	writeJSON(w, 200, out)
}

// ---- files ----

func (s *Server) handleFsList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	auth, deny := s.grantAuth(r, id, protocol.ReqFsList)
	if deny != "" {
		writeErr(w, http.StatusForbidden, deny)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
	defer cancel()
	var out protocol.FsListResult
	if err := s.hub.RequestA(ctx, id, protocol.ReqFsList, protocol.FsList{Path: r.URL.Query().Get("path")}, &out, auth); err != nil {
		fail(w, err)
		return
	}
	if out.Entries == nil {
		out.Entries = []protocol.FsEntry{}
	}
	writeJSON(w, 200, out)
}

const fsChunk = 4 << 20

// handleFsDownload streams a remote file to the browser in chunks so a large
// file never sits in server memory whole.
func (s *Server) handleFsDownload(w http.ResponseWriter, r *http.Request) {
	id, p := r.PathValue("id"), r.URL.Query().Get("path")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	if p == "" {
		writeErr(w, 400, "path required")
		return
	}
	auth, deny := s.grantAuth(r, id, protocol.ReqFsRead)
	if deny != "" {
		writeErr(w, http.StatusForbidden, deny)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), longTimeout)
	defer cancel()
	var first protocol.FsReadResult
	if err := s.hub.RequestA(ctx, id, protocol.ReqFsRead, protocol.FsRead{Path: p, Offset: 0, Length: fsChunk}, &first, auth); err != nil {
		// A download the device refused is exactly what someone sweeping for
		// SAM, a KeePass database or an .ssh key produces, so record it.
		s.audit(r, "file.download", id, auditFailure(map[string]any{"path": p}, err))
		fail(w, err)
		return
	}
	s.audit(r, "file.download", id, p)
	name := path.Base(strings.ReplaceAll(p, `\`, "/"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, strings.ReplaceAll(name, `"`, "")))
	w.Header().Set("Content-Length", strconv.FormatInt(first.Size, 10))
	w.Write(first.Data)
	off := int64(len(first.Data))
	for !first.EOF && off < first.Size {
		var chunk protocol.FsReadResult
		if err := s.hub.RequestA(ctx, id, protocol.ReqFsRead, protocol.FsRead{Path: p, Offset: off, Length: fsChunk}, &chunk, auth); err != nil {
			return
		}
		if len(chunk.Data) == 0 {
			return
		}
		if _, err := w.Write(chunk.Data); err != nil {
			return
		}
		off += int64(len(chunk.Data))
		first.EOF = chunk.EOF
	}
}

func (s *Server) handleFsUpload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}
	dest := r.URL.Query().Get("path")
	if dest == "" {
		writeErr(w, 400, "path required")
		return
	}
	if s.activeBundle(a.OrgID) != nil {
		// Devices in this organisation check signatures: stage the bytes and
		// have the operator sign the commit (uploads.go).
		s.stageUpload(w, r, a, dest)
		return
	}
	body := io.Reader(r.Body)
	ctx, cancel := context.WithTimeout(r.Context(), longTimeout)
	defer cancel()
	buf := make([]byte, fsChunk)
	first := true
	var total int64
	for {
		n, err := io.ReadFull(body, buf)
		if n > 0 {
			req := protocol.FsWrite{Path: dest, Data: buf[:n], Append: !first}
			if err := s.hub.Request(ctx, id, protocol.ReqFsWrite, req, nil); err != nil {
				fail(w, err)
				return
			}
			first = false
			total += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			fail(w, err)
			return
		}
	}
	if first { // empty file
		if err := s.hub.Request(ctx, id, protocol.ReqFsWrite, protocol.FsWrite{Path: dest}, nil); err != nil {
			fail(w, err)
			return
		}
	}
	s.audit(r, "file.upload", id, map[string]any{"path": dest, "bytes": total})
	writeJSON(w, 200, map[string]any{"ok": true, "bytes": total})
}

func (s *Server) fsSimple(w http.ResponseWriter, r *http.Request, typ, action string) {
	id := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}
	var in json.RawMessage
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	s.runSigned(w, r, signedAction{
		Org: a.OrgID, Op: typ, Targets: []string{id}, Payload: in,
		Summary: fmt.Sprintf("%s on %s: %s", typ, agentLabel(a), clip(string(in), 300)),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
			defer cancel()
			if err := s.hub.RequestA(ctx, id, typ, in, nil, auth); err != nil {
				// Audit the attempt, not only the success: probing a fleet for paths
				// that cannot be read or removed otherwise leaves no trace at all.
				s.audit(r, action, id, auditFailure(map[string]any{"request": string(in)}, err))
				fail(w, err)
				return
			}
			s.audit(r, action, id, string(in))
			writeJSON(w, 200, map[string]any{"ok": true})
		},
	})
}

func (s *Server) handleFsDelete(w http.ResponseWriter, r *http.Request) {
	s.fsSimple(w, r, protocol.ReqFsDelete, "file.delete")
}
func (s *Server) handleFsMkdir(w http.ResponseWriter, r *http.Request) {
	s.fsSimple(w, r, protocol.ReqFsMkdir, "file.mkdir")
}
func (s *Server) handleFsRename(w http.ResponseWriter, r *http.Request) {
	s.fsSimple(w, r, protocol.ReqFsRename, "file.rename")
}

// ---- power / WoL ----

// validPowerActions mirrors the agent's own switch. Validating here keeps 400
// for "you sent a bad action" and leaves 502 to mean "the device refused",
// which the console could not tell apart when both came back as 400.
var validPowerActions = map[string]bool{
	"reboot": true, "shutdown": true, "poweroff": true, "halt": true,
	"lock": true, "logoff": true, "logout": true,
}

func (s *Server) handlePower(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}
	var in protocol.Power
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	in.Action = strings.ToLower(strings.TrimSpace(in.Action))
	if !validPowerActions[in.Action] {
		writeErr(w, http.StatusBadRequest, "unknown power action "+strconv.Quote(in.Action)+" (reboot, shutdown, lock or logoff)")
		return
	}
	if in.Delay < 0 {
		in.Delay = 0
	}
	s.runSigned(w, r, signedAction{
		Org: a.OrgID, Op: protocol.ReqPower, Targets: []string{id}, Payload: in,
		Summary: fmt.Sprintf("%s %s", strings.ToUpper(in.Action[:1])+in.Action[1:], agentLabel(a)),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			// Audited BEFORE dispatch: a destructive request must be on record
			// whatever happens next, and a delay_sec=0 reboot can take the device down
			// before it answers, which used to be recorded as nothing at all.
			s.audit(r, "power.requested", id, in)
			ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
			defer cancel()
			if err := s.hub.RequestA(ctx, id, protocol.ReqPower, in, nil, auth); err != nil {
				s.audit(r, "power.failed", id, map[string]any{"action": in.Action, "error": err.Error()})
				if errors.Is(err, ErrAgentOffline) {
					fail(w, err)
					return
				}
				// the request was well formed; the device could not carry it out
				writeErr(w, http.StatusBadGateway, err.Error())
				return
			}
			s.audit(r, "power."+in.Action, id, in)
			writeJSON(w, 200, map[string]any{"ok": true})
		},
	})
}

// handleWakeOnLan sends the magic packet from another online agent on the
// same subnet, because the server may be on a different network than the
// sleeping device. Query "via" picks the sender; default is any online agent
// that shares a /24 with one of the target's known addresses.
func (s *Server) handleWakeOnLan(w http.ResponseWriter, r *http.Request) {
	target, ok := s.getScopedAgent(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var macs []string
	var targetNets []string
	if target.Inventory != nil {
		for _, n := range target.Inventory.Network {
			if n.MAC != "" && n.MAC != "00:00:00:00:00:00" {
				macs = append(macs, n.MAC)
			}
			for _, ip := range n.IPs {
				if strings.Count(ip, ".") == 3 {
					targetNets = append(targetNets, ip[:strings.LastIndex(ip, ".")])
				}
			}
		}
	}
	if len(macs) == 0 {
		writeErr(w, 400, "no MAC address known for this device; refresh its inventory while it is online")
		return
	}
	via := r.URL.Query().Get("via")
	if via == "" {
		agents, _ := s.agentsWithLiveness()
		for _, a := range agents {
			// No Inventory check here: ListAgents scans without the inventory
			// column, so a.Inventory is nil for EVERY row and this loop used
			// to skip every candidate. GetAgent below is what loads it.
			if a.ID == target.ID || !s.hub.IsOnline(a.ID) {
				continue
			}
			full, err := s.db.GetAgent(a.ID)
			if err != nil || full.Inventory == nil {
				continue
			}
		outer:
			for _, n := range full.Inventory.Network {
				for _, ip := range n.IPs {
					for _, tn := range targetNets {
						if strings.HasPrefix(ip, tn+".") {
							via = a.ID
							break outer
						}
					}
				}
			}
			if via != "" {
				break
			}
		}
	}
	if via == "" {
		writeErr(w, 409, "no online agent on the same subnet to send the packet from")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
	defer cancel()
	for _, mac := range macs {
		if err := s.hub.Request(ctx, via, protocol.ReqWakeOnLan, protocol.WakeOnLan{MAC: mac}, nil); err != nil {
			fail(w, err)
			return
		}
	}
	s.audit(r, "wol", target.ID, map[string]any{"via": via, "macs": macs})
	writeJSON(w, 200, map[string]any{"ok": true, "via": via, "macs": macs})
}

// ---- groups ----

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	g, err := s.db.ListGroups()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, g)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var in Group
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Name) == "" {
		writeErr(w, 400, "name required")
		return
	}
	res, err := s.db.Exec(`INSERT INTO groups(name, description, created_at) VALUES(?,?,?)`, strings.TrimSpace(in.Name), in.Description, now())
	if err != nil {
		fail(w, err)
		return
	}
	in.ID, _ = res.LastInsertId()
	s.audit(r, "group.create", in.Name, nil)
	writeJSON(w, 201, in)
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	var in Group
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Name) == "" {
		writeErr(w, 400, "name required")
		return
	}
	if _, err := s.db.Exec(`UPDATE groups SET name = ?, description = ? WHERE id = ?`, strings.TrimSpace(in.Name), in.Description, id); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "group.update", in.Name, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	// agents.group_id is ON DELETE SET NULL, so every member leaves the group
	// (and every baseline targeting it) the moment this runs. Snapshot what
	// they were assigned first, then clean up and re-push.
	members := map[string]map[int64]bool{}
	if agents, err := s.db.ListAgents(); err == nil {
		for _, a := range agents {
			if a.GroupID != nil && *a.GroupID == id {
				members[a.ID] = s.assignedBaselineIDs(a.ID)
			}
		}
	}
	s.db.Exec(`DELETE FROM groups WHERE id = ?`, id)
	for agentID, before := range members {
		s.agentMembershipChanged(agentID, before)
	}
	s.audit(r, "group.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- enrollment ----

func (s *Server) handleListEnroll(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.db.ListEnrollTokens()
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	filtered := make([]EnrollToken, 0, len(tokens))
	for _, tok := range tokens {
		if s.canAccessAgent(me, tok.OrgID) {
			filtered = append(filtered, tok)
		}
	}
	writeJSON(w, 200, map[string]any{"tokens": filtered, "public_url": s.PublicURL(), "fingerprint": s.PinFingerprint(), "cert_fingerprint": s.Fingerprint()})
}

func (s *Server) handleCreateEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string  `json:"name"`
		GroupID  *int64  `json:"group_id"`
		OrgID    *string `json:"org_id"`
		SiteID   *string `json:"site_id"`
		Uses     int     `json:"uses"`
		TTLHours int     `json:"ttl_hours"`
	}
	readJSON(r, &in)
	// uses_left is {-1} + [1..]: -1 is unlimited and anything else non-positive
	// is exhausted. Storing a caller's -7 verbatim used to mint a token that
	// never ran out by count, which is a far bigger grant than the form offers.
	switch {
	case in.Uses == 0:
		in.Uses = 1
	case in.Uses < 0:
		in.Uses = -1
	}
	if in.TTLHours <= 0 {
		in.TTLHours = 24
	}
	me := userFrom(r.Context())
	orgID := "org_default"
	if in.OrgID != nil && *in.OrgID != "" {
		orgID = *in.OrgID
	} else if me != nil && !me.IsAdmin() && len(me.OrgScope) > 0 {
		orgID = me.OrgScope[0]
	}
	if !s.canAccessAgent(me, orgID) {
		writeErr(w, http.StatusForbidden, "unauthorized organization for enrollment token")
		return
	}
	siteID := "site_default"
	if in.SiteID != nil && *in.SiteID != "" {
		siteID = *in.SiteID
	}
	tok := randomToken(24)
	res, err := s.db.Exec(`INSERT INTO enroll_tokens(token, name, group_id, org_id, site_id, uses_left, expires_at, created_by, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		tok, in.Name, in.GroupID, orgID, siteID, in.Uses, time.Now().Add(time.Duration(in.TTLHours)*time.Hour).Unix(), actor(r), now())
	if err != nil {
		fail(w, err)
		return
	}
	id, _ := res.LastInsertId()
	s.audit(r, "enroll.create", in.Name, map[string]any{"uses": in.Uses, "ttl_hours": in.TTLHours, "org_id": orgID, "site_id": siteID})
	writeJSON(w, 201, map[string]any{
		"id": id, "token": tok,
		"org_id":  orgID,
		"site_id": siteID,
		"windows": s.installCommandWindows(tok),
		"linux":   s.installCommandLinux(tok),
	})
}

func (s *Server) handleDeleteEnroll(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	var orgID string
	if err := s.db.QueryRow(`SELECT org_id FROM enroll_tokens WHERE id = ?`, id).Scan(&orgID); err != nil {
		writeErr(w, 404, "enroll token not found")
		return
	}
	me := userFrom(r.Context())
	if !s.canAccessAgent(me, orgID) {
		writeErr(w, 404, "enroll token not found")
		return
	}
	s.db.Exec(`DELETE FROM enroll_tokens WHERE id = ?`, id)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// installCommandWindows is the one-liner shown in the UI. It runs the install
// script served by the server, which downloads the agent binary from the
// server and registers it as a service. The fingerprint pins the certificate.
func (s *Server) installCommandWindows(token string) string {
	return fmt.Sprintf(`[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; iex ((New-Object Net.WebClient).DownloadString('%s/install/%s?os=windows'))`, s.PublicURL(), token)
}

func (s *Server) installCommandLinux(token string) string {
	return fmt.Sprintf(`curl -fsSk '%s/install/%s?os=linux' | sudo bash`, s.PublicURL(), token)
}

func (s *Server) handleIsolateAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}
	var in struct {
		Isolate bool `json:"isolate"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	user := userFrom(r.Context())
	username := ""
	if user != nil {
		username = user.Username
	}

	serverURL := s.PublicURL()
	serverHost := ""
	serverPort := 443
	if u, err := url.Parse(serverURL); err == nil {
		serverHost = u.Hostname()
		if p := u.Port(); p != "" {
			if pi, err := strconv.Atoi(p); err == nil {
				serverPort = pi
			}
		} else if u.Scheme == "http" {
			serverPort = 80
		}
	}

	reqPayload := protocol.DeviceIsolate{
		Isolate:    in.Isolate,
		ServerHost: serverHost,
		ServerPort: serverPort,
	}

	actionName := "device.isolate"
	if !in.Isolate {
		actionName = "device.release"
	}

	verb := "Isolate"
	if !in.Isolate {
		verb = "Release"
	}
	s.runSigned(w, r, signedAction{
		Org: target.OrgID, Op: protocol.ReqDeviceIsolate, Targets: []string{id}, Payload: reqPayload,
		Summary: fmt.Sprintf("%s %s from the network", verb, agentLabel(target)),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()

			var res protocol.DeviceIsolateResult
			err := s.hub.RequestA(ctx, id, protocol.ReqDeviceIsolate, reqPayload, &res, auth)
			if err != nil && !errors.Is(err, ErrAgentOffline) {
				writeErr(w, http.StatusBadGateway, err.Error())
				return
			}

			if err := s.db.SetAgentIsolated(id, in.Isolate, username); err != nil {
				fail(w, err)
				return
			}

			s.audit(r, actionName, id, map[string]any{"isolated": in.Isolate, "by": username, "target": target.DisplayName})
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":       true,
				"isolated": in.Isolate,
			})
		},
	})
}
