package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.agentsWithLiveness()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, agents)
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	a, err := s.db.GetAgent(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	a.Online = s.hub.IsOnline(a.ID)
	writeJSON(w, 200, a)
}

func (s *Server) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in AgentUpdate
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	if _, err := s.db.GetAgent(id); err != nil {
		fail(w, err)
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
	s.hub.Disconnect(id)
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
	rows, err := s.db.Query(`SELECT id, ts, kind, message, fields FROM agent_events WHERE agent_id = ? ORDER BY ts DESC LIMIT ?`, r.PathValue("id"), queryInt(r, "limit", 100))
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	type ev struct {
		ID      int64             `json:"id"`
		TS      int64             `json:"ts"`
		Kind    string            `json:"kind"`
		Message string            `json:"message"`
		Fields  map[string]string `json:"fields"`
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
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := s.hub.Request(ctx, r.PathValue("id"), protocol.ReqInventoryRefresh, nil, nil); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- processes ----

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
	defer cancel()
	var out []protocol.Process
	if err := s.hub.Request(ctx, r.PathValue("id"), protocol.ReqProcList, nil, &out); err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []protocol.Process{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleProcKill(w http.ResponseWriter, r *http.Request) {
	var in protocol.ProcKill
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
	defer cancel()
	if err := s.hub.Request(ctx, r.PathValue("id"), protocol.ReqProcKill, in, nil); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "process.kill", r.PathValue("id"), in)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- services ----

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
	defer cancel()
	var out []protocol.Service
	if err := s.hub.Request(ctx, r.PathValue("id"), protocol.ReqSvcList, nil, &out); err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []protocol.Service{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	var in protocol.SvcAction
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	var out protocol.Service
	if err := s.hub.Request(ctx, r.PathValue("id"), protocol.ReqSvcAction, in, &out); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "service."+in.Action, r.PathValue("id"), in.Name)
	writeJSON(w, 200, out)
}

// ---- event log ----

func (s *Server) handleEventLog(w http.ResponseWriter, r *http.Request) {
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
	if err := s.hub.Request(ctx, r.PathValue("id"), protocol.ReqEventLogQuery, q, &out); err != nil {
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
	ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
	defer cancel()
	var out protocol.FsListResult
	if err := s.hub.Request(ctx, r.PathValue("id"), protocol.ReqFsList, protocol.FsList{Path: r.URL.Query().Get("path")}, &out); err != nil {
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
	if p == "" {
		writeErr(w, 400, "path required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), longTimeout)
	defer cancel()
	var first protocol.FsReadResult
	if err := s.hub.Request(ctx, id, protocol.ReqFsRead, protocol.FsRead{Path: p, Offset: 0, Length: fsChunk}, &first); err != nil {
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
		if err := s.hub.Request(ctx, id, protocol.ReqFsRead, protocol.FsRead{Path: p, Offset: off, Length: fsChunk}, &chunk); err != nil {
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
	dest := r.URL.Query().Get("path")
	if dest == "" {
		writeErr(w, 400, "path required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), longTimeout)
	defer cancel()
	buf := make([]byte, fsChunk)
	first := true
	var total int64
	for {
		n, err := io.ReadFull(r.Body, buf)
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
	var in json.RawMessage
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
	defer cancel()
	if err := s.hub.Request(ctx, r.PathValue("id"), typ, in, nil); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, action, r.PathValue("id"), string(in))
	writeJSON(w, 200, map[string]any{"ok": true})
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
	// Audited BEFORE dispatch: a destructive request must be on record
	// whatever happens next, and a delay_sec=0 reboot can take the device down
	// before it answers, which used to be recorded as nothing at all.
	s.audit(r, "power.requested", id, in)
	ctx, cancel := context.WithTimeout(r.Context(), quickTimeout)
	defer cancel()
	if err := s.hub.Request(ctx, id, protocol.ReqPower, in, nil); err != nil {
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
}

// handleWakeOnLan sends the magic packet from another online agent on the
// same subnet, because the server may be on a different network than the
// sleeping device. Query "via" picks the sender; default is any online agent
// that shares a /24 with one of the target's known addresses.
func (s *Server) handleWakeOnLan(w http.ResponseWriter, r *http.Request) {
	target, err := s.db.GetAgent(r.PathValue("id"))
	if err != nil {
		fail(w, err)
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

// ---- enrolment ----

func (s *Server) handleListEnroll(w http.ResponseWriter, r *http.Request) {
	t, err := s.db.ListEnrollTokens()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tokens": t, "public_url": s.PublicURL(), "fingerprint": s.fingerprint})
}

func (s *Server) handleCreateEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		GroupID  *int64 `json:"group_id"`
		Uses     int    `json:"uses"`
		TTLHours int    `json:"ttl_hours"`
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
	tok := randomToken(24)
	res, err := s.db.Exec(`INSERT INTO enroll_tokens(token, name, group_id, uses_left, expires_at, created_by, created_at) VALUES(?,?,?,?,?,?,?)`,
		tok, in.Name, in.GroupID, in.Uses, time.Now().Add(time.Duration(in.TTLHours)*time.Hour).Unix(), actor(r), now())
	if err != nil {
		fail(w, err)
		return
	}
	id, _ := res.LastInsertId()
	s.audit(r, "enroll.create", in.Name, map[string]any{"uses": in.Uses, "ttl_hours": in.TTLHours})
	writeJSON(w, 201, map[string]any{
		"id": id, "token": tok,
		"windows": s.installCommandWindows(tok),
		"linux":   s.installCommandLinux(tok),
	})
}

func (s *Server) handleDeleteEnroll(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
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
