package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Script is the library entry.
type Script struct {
	ID          int64         `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Category    string        `json:"category"`
	Language    string        `json:"language"`
	Body        string        `json:"body"`
	Params      []ScriptParam `json:"params"`
	TimeoutSec  int           `json:"timeout_sec"`
	OSFilter    string        `json:"os_filter"`
	CreatedAt   int64         `json:"created_at"`
	UpdatedAt   int64         `json:"updated_at"`
}

type ScriptParam struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Default     string `json:"default"`
	Required    bool   `json:"required"`
}

// Run is one execution of a script on one device.
type Run struct {
	ID         string   `json:"id"`
	ScriptID   *int64   `json:"script_id"`
	ScriptName string   `json:"script_name"`
	AgentID    string   `json:"agent_id"`
	AgentName  string   `json:"agent_name"`
	TaskID     *int64   `json:"task_id"`
	Trigger    string   `json:"trigger"`
	RunBy      string   `json:"run_by"`
	Args       []string `json:"args"`
	Status     string   `json:"status"`
	ExitCode   int      `json:"exit_code"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	StartedAt  int64    `json:"started_at"`
	FinishedAt int64    `json:"finished_at"`
}

var validLanguages = map[string]bool{"powershell": true, "cmd": true, "bash": true, "sh": true, "python": true}

func (d *DB) ListScripts() ([]Script, error) {
	rows, err := d.Query(`SELECT id, name, description, category, language, body, params, timeout_sec, os_filter, created_at, updated_at FROM scripts ORDER BY category, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Script{}
	for rows.Next() {
		sc, err := scanScript(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sc)
	}
	return out, rows.Err()
}

func scanScript(row interface{ Scan(...any) error }) (*Script, error) {
	var sc Script
	var params string
	if err := row.Scan(&sc.ID, &sc.Name, &sc.Description, &sc.Category, &sc.Language, &sc.Body, &params, &sc.TimeoutSec, &sc.OSFilter, &sc.CreatedAt, &sc.UpdatedAt); err != nil {
		return nil, err
	}
	sc.Params = []ScriptParam{}
	json.Unmarshal([]byte(params), &sc.Params)
	return &sc, nil
}

func (d *DB) GetScript(id int64) (*Script, error) {
	sc, err := scanScript(d.QueryRow(`SELECT id, name, description, category, language, body, params, timeout_sec, os_filter, created_at, updated_at FROM scripts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return sc, err
}

func (d *DB) SaveScript(sc *Script) error {
	if strings.TrimSpace(sc.Name) == "" {
		return errors.New("name required")
	}
	if !validLanguages[sc.Language] {
		return errors.New("language must be powershell, cmd, bash, sh or python")
	}
	if sc.TimeoutSec <= 0 {
		sc.TimeoutSec = 300
	}
	if sc.Params == nil {
		sc.Params = []ScriptParam{}
	}
	sc.UpdatedAt = now()
	if sc.ID == 0 {
		sc.CreatedAt = sc.UpdatedAt
		res, err := d.Exec(`INSERT INTO scripts(name, description, category, language, body, params, timeout_sec, os_filter, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			sc.Name, sc.Description, sc.Category, sc.Language, sc.Body, jsonText(sc.Params), sc.TimeoutSec, sc.OSFilter, sc.CreatedAt, sc.UpdatedAt)
		if err != nil {
			return err
		}
		sc.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := d.Exec(`UPDATE scripts SET name=?, description=?, category=?, language=?, body=?, params=?, timeout_sec=?, os_filter=?, updated_at=? WHERE id=?`,
		sc.Name, sc.Description, sc.Category, sc.Language, sc.Body, jsonText(sc.Params), sc.TimeoutSec, sc.OSFilter, sc.UpdatedAt, sc.ID)
	return err
}

const runCols = `r.id, r.script_id, r.script_name, r.agent_id, COALESCE(NULLIF(a.display_name,''), a.hostname, ''), r.task_id, r.trigger, r.run_by, r.args, r.status, r.exit_code, r.started_at, r.finished_at`

func scanRun(row interface{ Scan(...any) error }, withOutput bool) (*Run, error) {
	var r Run
	var sid, tid sql.NullInt64
	var args string
	dest := []any{&r.ID, &sid, &r.ScriptName, &r.AgentID, &r.AgentName, &tid, &r.Trigger, &r.RunBy, &args, &r.Status, &r.ExitCode, &r.StartedAt, &r.FinishedAt}
	if withOutput {
		dest = append(dest, &r.Stdout, &r.Stderr)
	}
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	if sid.Valid {
		r.ScriptID = &sid.Int64
	}
	if tid.Valid {
		r.TaskID = &tid.Int64
	}
	r.Args = []string{}
	json.Unmarshal([]byte(args), &r.Args)
	return &r, nil
}

func (d *DB) ListRuns(agentID string, limit int64) ([]Run, error) {
	q := `SELECT ` + runCols + ` FROM script_runs r LEFT JOIN agents a ON a.id = r.agent_id`
	args := []any{}
	if agentID != "" {
		q += ` WHERE r.agent_id = ?`
		args = append(args, agentID)
	}
	q += ` ORDER BY r.started_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		r, err := scanRun(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (d *DB) GetRun(id string) (*Run, error) {
	r, err := scanRun(d.QueryRow(`SELECT `+runCols+`, r.stdout, r.stderr FROM script_runs r LEFT JOIN agents a ON a.id = r.agent_id WHERE r.id = ?`, id), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return r, err
}

// runTracker starts script executions and keeps live output for runs in
// flight so the UI can tail them before the final result lands in SQLite.
type runTracker struct {
	s    *Server
	mu   sync.Mutex
	live map[string]*liveRun
}

type liveRun struct {
	stdout, stderr strings.Builder
	agentID        string
	cancel         func()
}

func newRunTracker(s *Server) *runTracker { return &runTracker{s: s, live: map[string]*liveRun{}} }

// RunRequest describes an execution to start.
type RunRequest struct {
	Script   *Script // library script (nil for ad hoc)
	Language string  // ad hoc only
	Body     string  // ad hoc only
	Args     []string
	Env      map[string]string
	Timeout  int
	Trigger  string
	RunBy    string
	TaskID   *int64
	Name     string // display name for ad hoc
}

const maxOutput = 2 << 20

// Start launches the script on one agent. Offline agents get a queued run
// that the scheduler releases when they connect. The returned id is stable
// either way.
func (t *runTracker) Start(agentID string, req RunRequest) (string, error) {
	lang, body, timeout, name := req.Language, req.Body, req.Timeout, req.Name
	var scriptID *int64
	if req.Script != nil {
		lang, body, name = req.Script.Language, req.Script.Body, req.Script.Name
		if timeout <= 0 {
			timeout = req.Script.TimeoutSec
		}
		scriptID = &req.Script.ID
	}
	if !validLanguages[lang] {
		return "", errors.New("invalid language")
	}
	if timeout <= 0 {
		timeout = 300
	}
	if name == "" {
		name = "ad hoc " + lang
	}
	if req.Args == nil {
		req.Args = []string{}
	}
	id := randomHex(8)
	status := "running"
	if !t.s.hub.IsOnline(agentID) {
		if req.Script == nil {
			return "", ErrAgentOffline // ad hoc bodies are not persisted, so they cannot be queued
		}
		status = "queued"
	}
	if _, err := t.s.db.Exec(`INSERT INTO script_runs(id, script_id, script_name, agent_id, task_id, trigger, run_by, args, status, started_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, id, scriptID, name, agentID, req.TaskID, req.Trigger, req.RunBy, jsonText(req.Args), status, now()); err != nil {
		return "", err
	}
	if status == "queued" {
		return id, nil
	}
	t.launch(id, agentID, protocol.ScriptRun{RunID: id, Language: lang, Body: body, Args: req.Args, Env: req.Env, Timeout: timeout})
	return id, nil
}

func (t *runTracker) launch(id, agentID string, sr protocol.ScriptRun) {
	lr := &liveRun{agentID: agentID}
	t.mu.Lock()
	t.live[id] = lr
	t.mu.Unlock()
	t.s.hub.broadcast(hubEvent{Kind: "run", AgentID: agentID, Data: map[string]any{"run_id": id, "status": "running"}})

	_, cancel, err := t.s.hub.Stream(agentID, protocol.ReqScriptRun, sr, func(env protocol.Envelope) {
		switch env.T {
		case protocol.TypeStream:
			var c protocol.ScriptChunk
			if json.Unmarshal(env.D, &c) != nil {
				return
			}
			b := &lr.stdout
			if c.Stream == "stderr" {
				b = &lr.stderr
			}
			if b.Len() < maxOutput {
				b.WriteString(c.Data)
			}
			t.s.hub.broadcast(hubEvent{Kind: "run", AgentID: agentID, Data: map[string]any{"run_id": id, "stream": c.Stream, "data": c.Data}})
		case protocol.TypeReply:
			var res protocol.ScriptResult
			status := "done"
			if env.Err != "" {
				status = "failed"
				res.Error = env.Err
				res.ExitCode = -1
			} else {
				json.Unmarshal(env.D, &res)
				if res.TimedOut {
					status = "timeout"
				} else if res.ExitCode != 0 || res.Error != "" {
					status = "failed"
				}
			}
			t.finish(id, agentID, status, res, lr)
		}
	})
	if err != nil {
		t.finish(id, agentID, "failed", protocol.ScriptResult{Error: err.Error(), ExitCode: -1}, lr)
		return
	}
	lr.cancel = cancel
}

func (t *runTracker) finish(id, agentID, status string, res protocol.ScriptResult, lr *liveRun) {
	t.mu.Lock()
	delete(t.live, id)
	t.mu.Unlock()
	stdout, stderr := res.Stdout, res.Stderr
	if stdout == "" {
		stdout = lr.stdout.String()
	}
	if stderr == "" {
		stderr = lr.stderr.String()
	}
	if res.Error != "" {
		stderr = strings.TrimSpace(stderr + "\n[agent] " + res.Error)
	}
	if len(stdout) > maxOutput {
		stdout = stdout[:maxOutput] + "\n[truncated]"
	}
	if len(stderr) > maxOutput {
		stderr = stderr[:maxOutput] + "\n[truncated]"
	}
	if _, err := t.s.db.Exec(`UPDATE script_runs SET status=?, exit_code=?, stdout=?, stderr=?, finished_at=? WHERE id=?`, status, res.ExitCode, stdout, stderr, now(), id); err != nil {
		slog.Warn("finish run", "id", id, "err", err)
	}
	t.s.hub.broadcast(hubEvent{Kind: "run", AgentID: agentID, Data: map[string]any{"run_id": id, "status": status, "exit_code": res.ExitCode}})
	if status == "failed" || status == "timeout" {
		t.s.alerts.scriptFailed(agentID, id, status)
	}
}

// Live returns the buffered output of a running job (nil when not live).
func (t *runTracker) Live(id string) (stdout, stderr string, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	lr := t.live[id]
	if lr == nil {
		return "", "", false
	}
	return lr.stdout.String(), lr.stderr.String(), true
}

func (t *runTracker) Cancel(id string) error {
	t.mu.Lock()
	lr := t.live[id]
	t.mu.Unlock()
	if lr == nil {
		// queued?
		res, err := t.s.db.Exec(`UPDATE script_runs SET status='cancelled', finished_at=? WHERE id=? AND status='queued'`, now(), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errors.New("run is not active")
		}
		return nil
	}
	return t.s.hub.Notify(lr.agentID, protocol.ReqScriptCancel, map[string]string{"run_id": id})
}

// releaseQueued launches queued runs for an agent that just connected.
func (t *runTracker) releaseQueued(agentID string) {
	rows, err := t.s.db.Query(`SELECT id, script_id, args, task_id FROM script_runs WHERE agent_id = ? AND status = 'queued' ORDER BY started_at`, agentID)
	if err != nil {
		return
	}
	type q struct {
		id   string
		sid  sql.NullInt64
		args string
	}
	var list []q
	for rows.Next() {
		var x q
		var tid sql.NullInt64
		rows.Scan(&x.id, &x.sid, &x.args, &tid)
		list = append(list, x)
	}
	rows.Close()
	for _, x := range list {
		if !x.sid.Valid {
			t.s.db.Exec(`UPDATE script_runs SET status='failed', stderr='script no longer exists', finished_at=? WHERE id=?`, now(), x.id)
			continue
		}
		sc, err := t.s.db.GetScript(x.sid.Int64)
		if err != nil {
			t.s.db.Exec(`UPDATE script_runs SET status='failed', stderr='script no longer exists', finished_at=? WHERE id=?`, now(), x.id)
			continue
		}
		var args []string
		json.Unmarshal([]byte(x.args), &args)
		t.s.db.Exec(`UPDATE script_runs SET status='running', started_at=? WHERE id=?`, now(), x.id)
		t.launch(x.id, agentID, protocol.ScriptRun{RunID: x.id, Language: sc.Language, Body: sc.Body, Args: args, Timeout: sc.TimeoutSec})
	}
}

// WaitDone blocks until the run leaves the live set or ctx ends (used by
// automations that chain on a result).
func (t *runTracker) WaitDone(ctx context.Context, id string) {
	for {
		t.mu.Lock()
		_, live := t.live[id]
		t.mu.Unlock()
		if !live {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}
