package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
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

func (s *Server) startRuns(r *http.Request, in runScriptInput, agentIDs []string) (map[string]string, error) {
	req := RunRequest{Language: in.Language, Body: in.Body, Args: in.Args, Env: in.Env, Timeout: in.Timeout, Trigger: "manual", RunBy: actor(r)}
	if in.ScriptID != nil {
		sc, err := s.db.GetScript(*in.ScriptID)
		if err != nil {
			return nil, err
		}
		req.Script = sc
	}
	out := map[string]string{}
	for _, id := range agentIDs {
		if req.Script != nil && req.Script.OSFilter != "" {
			if a, err := s.db.GetAgent(id); err == nil && a.OS != req.Script.OSFilter {
				out[id] = "skipped: os mismatch"
				continue
			}
		}
		runID, err := s.runs.Start(id, req)
		if err != nil {
			out[id] = "error: " + err.Error()
			continue
		}
		out[id] = runID
	}
	return out, nil
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
	out, err := s.startRuns(r, in, ids)
	if err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "script.run", strings.Join(ids, ","), map[string]any{"script_id": in.ScriptID, "language": in.Language})
	writeJSON(w, 200, map[string]any{"runs": out})
}

func (s *Server) handleRunScriptOnAgent(w http.ResponseWriter, r *http.Request) {
	var in runScriptInput
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	id := r.PathValue("id")
	out, err := s.startRuns(r, in, []string{id})
	if err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "script.run", id, map[string]any{"script_id": in.ScriptID, "language": in.Language})
	runID := out[id]
	if strings.HasPrefix(runID, "error: ") {
		writeErr(w, 409, strings.TrimPrefix(runID, "error: "))
		return
	}
	writeJSON(w, 200, map[string]any{"run_id": runID})
}

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.db.ListRuns(r.URL.Query().Get("agent"), queryInt(r, "limit", 100))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, runs)
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.db.GetRun(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	if so, se, ok := s.runs.Live(run.ID); ok {
		run.Stdout, run.Stderr = so, se
	}
	writeJSON(w, 200, run)
}

func (s *Server) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	if err := s.runs.Cancel(r.PathValue("id")); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "run.cancel", r.PathValue("id"), nil)
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
