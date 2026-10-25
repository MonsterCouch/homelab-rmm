package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func (s *Server) handleListScripts(w http.ResponseWriter, r *http.Request) {
	sc, err := s.db.ListScripts()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, sc)
}

func (s *Server) handleGetScript(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	sc, err := s.db.GetScript(id)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, sc)
}

func (s *Server) handleCreateScript(w http.ResponseWriter, r *http.Request) {
	var sc Script
	if err := readJSON(r, &sc); err != nil {
		fail(w, err)
		return
	}
	sc.ID = 0
	if err := s.db.SaveScript(&sc); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "script.create", sc.Name, nil)
	writeJSON(w, 201, sc)
}

func (s *Server) handleUpdateScript(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	if _, err := s.db.GetScript(id); err != nil {
		fail(w, err)
		return
	}
	var sc Script
	if err := readJSON(r, &sc); err != nil {
		fail(w, err)
		return
	}
	sc.ID = id
	if err := s.db.SaveScript(&sc); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "script.update", sc.Name, nil)
	writeJSON(w, 200, sc)
}

func (s *Server) handleDeleteScript(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	s.db.Exec(`DELETE FROM scripts WHERE id = ?`, id)
	s.audit(r, "script.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// runScriptInput is shared by the library run and the per-agent ad hoc run.
type runScriptInput struct {
	ScriptID *int64            `json:"script_id"`
	Language string            `json:"language"`
	Body     string            `json:"body"`
	Args     []string          `json:"args"`
	Env      map[string]string `json:"env"`
	Timeout  int               `json:"timeout_sec"`
	Targets  Targets           `json:"targets"`
	AgentIDs []string          `json:"agent_ids"`
}

// runPlan is a script run resolved against its targets: who will really
// receive it, and what exactly they will be sent.
type runPlan struct {
	req     RunRequest
	out     map[string]string // outcomes decided before anything starts
	targets []string          // devices a run will be started on
}

func (s *Server) planRuns(r *http.Request, in runScriptInput, agentIDs []string) (*runPlan, error) {
	req := RunRequest{Language: in.Language, Body: in.Body, Args: in.Args, Env: in.Env, Timeout: in.Timeout, Trigger: "manual", RunBy: actor(r)}
	if in.ScriptID != nil {
		sc, err := s.db.GetScript(*in.ScriptID)
		if err != nil {
			return nil, err
		}
		req.Script = sc
	}
	me := userFrom(r.Context())
	pl := &runPlan{req: req, out: map[string]string{}}
	// Whether an organization signs actions, looked up once per organization
	// rather than once per device: a bulk run names thousands.
	signs := map[string]bool{}
	orgSigns := func(org string) bool {
		v, ok := signs[org]
		if !ok {
			v = s.activeBundle(org) != nil
			signs[org] = v
		}
		return v
	}
	for _, id := range agentIDs {
		a, err := s.db.GetAgent(id)
		if err != nil {
			pl.out[id] = "error: agent not found"
			continue
		}
		if !s.canAccessAgent(me, a.OrgID) {
			pl.out[id] = "error: agent not found"
			continue
		}
		if req.Script != nil && req.Script.OSFilter != "" {
			if a.OS != req.Script.OSFilter {
				pl.out[id] = "skipped: os mismatch"
				continue
			}
		}
		if !s.hub.IsOnline(id) && orgSigns(a.OrgID) {
			// Nothing can be sent, so do not ask the operator to sign for a
			// device that cannot receive it. Ad hoc bodies are never queued
			// and keep their usual answer, as in startOneRun.
			if req.Script == nil {
				pl.out[id] = "error: " + ErrAgentOffline.Error()
			} else {
				pl.out[id] = "error: " + ErrSignedRunOffline.Error()
			}
			continue
		}
		pl.targets = append(pl.targets, id)
	}
	return pl, nil
}

// signedScriptPayload is the script.run payload a manifest carries: what the
// agent will execute, without the run_id that differs per device (each agent
// takes its own run_id from its envelope). One device: the payload is exactly
// what that device is sent, device environment included. Several: a manifest
// is one document for all of them, so only the operator's own env is signed.
func (s *Server) signedScriptPayload(pl *runPlan) (json.RawMessage, string, error) {
	req := pl.req
	lang, body, timeout, name, _, err := resolveRun(&req)
	if err != nil {
		return nil, "", err
	}
	env := map[string]string{}
	if len(pl.targets) == 1 {
		env = s.runs.deviceEnv(pl.targets[0], req.Trigger, req.RunBy)
	}
	for k, v := range req.Env {
		env[k] = v
	}
	sr := protocol.ScriptRun{Language: lang, Body: body, Args: req.Args, Env: env, Timeout: timeout}
	raw, err := json.Marshal(sr)
	if err != nil {
		return nil, "", err
	}
	var m map[string]json.RawMessage
	json.Unmarshal(raw, &m)
	delete(m, "run_id")
	raw, _ = json.Marshal(m)
	return raw, fmt.Sprintf("Run %s script %q: %s", lang, name, clip(body, 300)), nil
}

// runScripts plans a run, takes it through the signing flow and starts it.
// respond writes the handler's own response from the per-device outcomes.
func (s *Server) runScripts(w http.ResponseWriter, r *http.Request, in runScriptInput, agentIDs []string, respond func(w http.ResponseWriter, r *http.Request, out map[string]string)) {
	pl, err := s.planRuns(r, in, agentIDs)
	if err != nil {
		fail(w, err)
		return
	}
	run := func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
		respond(w, r, s.startPlanned(pl, auth))
	}
	payload, summary, perr := s.signedScriptPayload(pl)
	if perr != nil || len(pl.targets) == 0 {
		// Nothing valid to start (bad language, no usable device): the
		// per-device errors are the answer, and nothing is dispatched.
		run(w, r, nil)
		return
	}
	s.runSigned(w, r, signedAction{
		Op: protocol.ReqScriptRun, Targets: pl.targets, Payload: payload,
		Summary: summary + " " + summaryDevices(len(pl.targets), pl.targets[0]),
		Run:     run,
	})
}

// startOneRun takes a single-device run through the signing flow. respond
// writes the handler's response from the outcome of Start.
func (s *Server) startOneRun(w http.ResponseWriter, r *http.Request, req RunRequest, agentID, orgID string, respond func(w http.ResponseWriter, r *http.Request, runID string, err error)) {
	if s.activeBundle(orgID) != nil && !s.hub.IsOnline(agentID) {
		// Nothing can be sent, so nothing is worth signing for. Ad hoc
		// bodies are never queued and keep their usual answer.
		if req.Script == nil {
			respond(w, r, "", ErrAgentOffline)
		} else {
			respond(w, r, "", ErrSignedRunOffline)
		}
		return
	}
	run := func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
		req := req
		req.Auth = auth
		runID, err := s.runs.Start(agentID, req)
		respond(w, r, runID, err)
	}
	payload, summary, err := s.signedScriptPayload(&runPlan{req: req, out: map[string]string{}, targets: []string{agentID}})
	if err != nil {
		run(w, r, nil) // an invalid request: Start reports why, nothing is sent
		return
	}
	s.runSigned(w, r, signedAction{
		Org: orgID, Op: protocol.ReqScriptRun, Targets: []string{agentID}, Payload: payload, Summary: summary, Run: run,
	})
}

func (s *Server) startRuns(r *http.Request, in runScriptInput, agentIDs []string) (map[string]string, error) {
	pl, err := s.planRuns(r, in, agentIDs)
	if err != nil {
		return nil, err
	}
	return s.startPlanned(pl, nil), nil
}

func (s *Server) startPlanned(pl *runPlan, auth *protocol.ActionAuth) map[string]string {
	req := pl.req
	req.Auth = auth
	out := pl.out
	for _, id := range pl.targets {
		runID, err := s.runs.Start(id, req)
		if err != nil {
			out[id] = "error: " + err.Error()
			continue
		}
		out[id] = runID
	}
	return out
}

// handleRunScript runs a library script or an ad hoc body on a target set.
func (s *Server) handleRunScript(w http.ResponseWriter, r *http.Request) {
	var in runScriptInput
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	ids := in.AgentIDs
	if len(ids) == 0 {
		agents, err := s.db.ResolveTargets(in.Targets)
		if err != nil {
			fail(w, err)
			return
		}
		for _, a := range agents {
			ids = append(ids, a.ID)
		}
	}
	if len(ids) == 0 {
		writeErr(w, 400, "no target devices")
		return
	}
	s.runScripts(w, r, in, ids, func(w http.ResponseWriter, r *http.Request, out map[string]string) {
		s.audit(r, "script.run", strings.Join(ids, ","), map[string]any{"script_id": in.ScriptID, "language": in.Language})
		writeJSON(w, 200, map[string]any{"runs": out})
	})
}

func (s *Server) handleRunScriptOnAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.getScopedAgent(w, r, id); !ok {
		return
	}
	var in runScriptInput
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	s.runScripts(w, r, in, []string{id}, func(w http.ResponseWriter, r *http.Request, out map[string]string) {
		s.respondSingleRun(w, r, id, in, out)
	})
}

func (s *Server) respondSingleRun(w http.ResponseWriter, r *http.Request, id string, in runScriptInput, out map[string]string) {
	s.audit(r, "script.run", id, map[string]any{"script_id": in.ScriptID, "language": in.Language})
	// startRuns encodes each agent's outcome in the map value, and only a real
	// run id may leave here as one: a caller that follows the documented
	// POST .../run -> {run_id} contract would otherwise poll a run that was
	// never created. There is one target, so every other outcome is this
	// request's own error.
	runID := out[id]
	if msg, skipped := strings.CutPrefix(runID, "skipped: "); skipped {
		writeErr(w, 409, "run skipped: "+msg)
		return
	}
	if msg, failed := strings.CutPrefix(runID, "error: "); failed {
		writeErr(w, 409, msg)
		return
	}
	writeJSON(w, 200, map[string]any{"run_id": runID})
}

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	targetAgent := r.URL.Query().Get("agent")
	if targetAgent != "" {
		if _, ok := s.getScopedAgent(w, r, targetAgent); !ok {
			return
		}
	}
	runs, err := s.db.ListRuns(targetAgent, queryInt(r, "limit", 100))
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if me != nil && !me.IsAdmin() && len(me.OrgScope) > 0 {
		filtered := make([]Run, 0, len(runs))
		for _, rn := range runs {
			if a, err := s.db.GetAgent(rn.AgentID); err == nil && s.canAccessAgent(me, a.OrgID) {
				filtered = append(filtered, rn)
			}
		}
		runs = filtered
	}
	writeJSON(w, 200, runs)
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.db.GetRun(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	if a, err := s.db.GetAgent(run.AgentID); err == nil {
		if !s.canAccessAgent(userFrom(r.Context()), a.OrgID) {
			writeErr(w, http.StatusNotFound, "run not found")
			return
		}
	}
	if so, se, ok := s.runs.Live(run.ID); ok {
		run.Stdout, run.Stderr = so, se
	}
	writeJSON(w, 200, run)
}

func (s *Server) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.db.GetRun(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	if a, err := s.db.GetAgent(run.AgentID); err == nil {
		if !s.canAccessAgent(userFrom(r.Context()), a.OrgID) {
			writeErr(w, http.StatusNotFound, "run not found")
			return
		}
	}
	if err := s.runs.Cancel(run.ID); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "run.cancel", run.ID, nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- tasks ----

type Task struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Kind        string          `json:"kind"`
	ScriptID    *int64          `json:"script_id"`
	Args        []string        `json:"args"`
	Targets     Targets         `json:"targets"`
	Schedule    string          `json:"schedule"`
	Enabled     bool            `json:"enabled"`
	TimeoutSec  int             `json:"timeout_sec"`
	Options     json.RawMessage `json:"options"`
	LastRun     int64           `json:"last_run"`
	NextRun     int64           `json:"next_run"`
	CreatedAt   int64           `json:"created_at"`
	UpdatedAt   int64           `json:"updated_at"`
}

var validTaskKinds = map[string]bool{"script": true, "patch_scan": true, "patch_install": true, "reboot": true, "inventory": true}

func (d *DB) ListTasks() ([]Task, error) {
	rows, err := d.Query(`SELECT id, name, description, kind, script_id, args, targets, schedule, enabled, timeout_sec, options, last_run, next_run, created_at, updated_at FROM tasks ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		var t Task
		var sid *int64
		var args, targets, opts string
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.Kind, &sid, &args, &targets, &t.Schedule, &t.Enabled, &t.TimeoutSec, &opts, &t.LastRun, &t.NextRun, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.ScriptID = sid
		t.Args = []string{}
		json.Unmarshal([]byte(args), &t.Args)
		json.Unmarshal([]byte(targets), &t.Targets)
		t.Options = json.RawMessage(opts)
		if len(t.Options) == 0 {
			t.Options = json.RawMessage("{}")
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) GetTask(id int64) (*Task, error) {
	tasks, err := d.ListTasks()
	if err != nil {
		return nil, err
	}
	for i := range tasks {
		if tasks[i].ID == id {
			return &tasks[i], nil
		}
	}
	return nil, errNotFound
}

func (s *Server) saveTask(w http.ResponseWriter, r *http.Request, id int64) {
	var t Task
	if err := readJSON(r, &t); err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if id != 0 {
		existing, err := s.db.GetTask(id)
		if err != nil {
			fail(w, err)
			return
		}
		if !s.canAccessTargets(me, existing.Targets) {
			writeErr(w, http.StatusForbidden, "access denied: task outside organization scope")
			return
		}
	}
	if strings.TrimSpace(t.Name) == "" {
		writeErr(w, 400, "name required")
		return
	}
	if t.Kind == "" {
		t.Kind = "script"
	}
	if !validTaskKinds[t.Kind] {
		writeErr(w, 400, "invalid task kind")
		return
	}
	if t.Kind == "script" && t.ScriptID == nil {
		writeErr(w, 400, "script required")
		return
	}
	if t.Schedule != "" {
		if err := validateCron(t.Schedule); err != nil {
			writeErr(w, 400, "schedule: "+err.Error())
			return
		}
	}
	if t.Args == nil {
		t.Args = []string{}
	}
	if len(t.Options) == 0 {
		t.Options = json.RawMessage("{}")
	}
	if t.TimeoutSec <= 0 {
		t.TimeoutSec = 300
	}
	if err := s.validateTargetsScope(me, t.Targets); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	tsNow := now()
	var err error
	if id == 0 {
		var res interface{ LastInsertId() (int64, error) }
		res, err = s.db.Exec(`INSERT INTO tasks(name, description, kind, script_id, args, targets, schedule, enabled, timeout_sec, options, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			t.Name, t.Description, t.Kind, t.ScriptID, jsonText(t.Args), jsonText(t.Targets), t.Schedule, t.Enabled, t.TimeoutSec, string(t.Options), tsNow, tsNow)
		if err == nil {
			id, _ = res.LastInsertId()
		}
	} else {
		_, err = s.db.Exec(`UPDATE tasks SET name=?, description=?, kind=?, script_id=?, args=?, targets=?, schedule=?, enabled=?, timeout_sec=?, options=?, updated_at=? WHERE id=?`,
			t.Name, t.Description, t.Kind, t.ScriptID, jsonText(t.Args), jsonText(t.Targets), t.Schedule, t.Enabled, t.TimeoutSec, string(t.Options), tsNow, id)
	}
	if err != nil {
		fail(w, err)
		return
	}
	s.sched.reload()
	s.audit(r, "task.save", t.Name, nil)
	saved, _ := s.db.GetTask(id)
	writeJSON(w, 200, saved)
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	t, err := s.db.ListTasks()
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if me != nil && !me.IsAdmin() && len(me.OrgScope) > 0 {
		filtered := make([]Task, 0, len(t))
		for _, item := range t {
			if s.canAccessTargets(me, item.Targets) {
				filtered = append(filtered, item)
			}
		}
		t = filtered
	}
	writeJSON(w, 200, t)
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) { s.saveTask(w, r, 0) }

func (s *Server) handleUpdateTask(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	if _, err := s.db.GetTask(id); err != nil {
		fail(w, err)
		return
	}
	s.saveTask(w, r, id)
}

func (s *Server) handleDeleteTask(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	t, err := s.db.GetTask(id)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if !s.canAccessTargets(me, t.Targets) {
		writeErr(w, http.StatusForbidden, "access denied: task outside organization scope")
		return
	}
	s.db.Exec(`DELETE FROM tasks WHERE id = ?`, id)
	s.sched.reload()
	s.audit(r, "task.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleRunTask(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	t, err := s.db.GetTask(id)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if !s.canAccessTargets(me, t.Targets) {
		writeErr(w, http.StatusForbidden, "access denied: task outside organization scope")
		return
	}
	n := s.sched.runTask(t, actor(r))
	s.audit(r, "task.run", t.Name, nil)
	writeJSON(w, 200, map[string]any{"ok": true, "devices": n})
}

// ---- automations ----

type Automation struct {
	ID           int64           `json:"id"`
	Name         string          `json:"name"`
	Trigger      string          `json:"trigger"`
	Filter       json.RawMessage `json:"filter"`
	Action       string          `json:"action"`
	ActionParams json.RawMessage `json:"action_params"`
	Enabled      bool            `json:"enabled"`
	CreatedAt    int64           `json:"created_at"`
}

// validTriggers gates what an operator may create. drift_detected and
// drift_fixed carry no rule_id, so an automation filtered by rule_ids never
// matches one - the console says so beside the trigger picker.
var validTriggers = map[string]bool{"agent_online": true, "agent_offline": true, "alert_opened": true, "alert_resolved": true, "enrolled": true, "reboot_required": true, "patch_installed": true, "drift_detected": true, "drift_fixed": true}
var validActions = map[string]bool{"run_script": true, "email": true, "webhook": true}

func (d *DB) ListAutomations() ([]Automation, error) {
	rows, err := d.Query(`SELECT id, name, trigger, filter, action, action_params, enabled, created_at FROM automations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Automation{}
	for rows.Next() {
		var a Automation
		var f, p string
		if err := rows.Scan(&a.ID, &a.Name, &a.Trigger, &f, &a.Action, &p, &a.Enabled, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Filter, a.ActionParams = json.RawMessage(f), json.RawMessage(p)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Server) saveAutomation(w http.ResponseWriter, r *http.Request, id int64) {
	var a Automation
	if err := readJSON(r, &a); err != nil {
		fail(w, err)
		return
	}
	if strings.TrimSpace(a.Name) == "" || !validTriggers[a.Trigger] || !validActions[a.Action] {
		writeErr(w, 400, "name, a valid trigger and a valid action are required")
		return
	}
	if len(a.Filter) == 0 {
		a.Filter = json.RawMessage("{}")
	}
	if len(a.ActionParams) == 0 {
		a.ActionParams = json.RawMessage("{}")
	}
	var err error
	if id == 0 {
		var res interface{ LastInsertId() (int64, error) }
		res, err = s.db.Exec(`INSERT INTO automations(name, trigger, filter, action, action_params, enabled, created_at) VALUES(?,?,?,?,?,?,?)`,
			a.Name, a.Trigger, string(a.Filter), a.Action, string(a.ActionParams), a.Enabled, now())
		if err == nil {
			id, _ = res.LastInsertId()
		}
	} else {
		_, err = s.db.Exec(`UPDATE automations SET name=?, trigger=?, filter=?, action=?, action_params=?, enabled=? WHERE id=?`,
			a.Name, a.Trigger, string(a.Filter), a.Action, string(a.ActionParams), a.Enabled, id)
	}
	if err != nil {
		fail(w, err)
		return
	}
	a.ID = id
	s.audit(r, "automation.save", a.Name, nil)
	writeJSON(w, 200, a)
}

func (s *Server) handleListAutomations(w http.ResponseWriter, r *http.Request) {
	a, err := s.db.ListAutomations()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, a)
}
func (s *Server) handleCreateAutomation(w http.ResponseWriter, r *http.Request) {
	s.saveAutomation(w, r, 0)
}
func (s *Server) handleUpdateAutomation(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	s.saveAutomation(w, r, id)
}
func (s *Server) handleDeleteAutomation(w http.ResponseWriter, r *http.Request) {
	id, _ := pathInt(r, "id")
	s.db.Exec(`DELETE FROM automations WHERE id = ?`, id)
	s.audit(r, "automation.delete", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}
