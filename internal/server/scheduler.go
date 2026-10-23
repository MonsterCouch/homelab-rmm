package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// scheduler runs cron-scheduled tasks and patch policies, releases queued
// runs, fires automations and purges old data.
type scheduler struct {
	s    *Server
	mu   sync.Mutex
	cron *cron.Cron
	ctx  context.Context
	// autoLimit caps how often one automation may fire. Automations can feed
	// each other (alert_opened -> run_script -> failure -> script_failed
	// alert -> alert_opened), and nothing else in the chain refuses to
	// re-enter: without a ceiling the loop runs as fast as the device can
	// execute the script, one run row, one alert row and one email per turn.
	autoLimit *rateLimiter
}

// maxAutomationFiresPerMinute is deliberately generous for a home lab: a fleet
// of twenty devices coming online at once is normal, a hundred fires a minute
// from one automation is not.
const maxAutomationFiresPerMinute = 60

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

func validateCron(expr string) error {
	_, err := cronParser.Parse(expr)
	return err
}

func newScheduler(s *Server) *scheduler {
	return &scheduler{s: s, ctx: context.Background(), autoLimit: newRateLimiter(maxAutomationFiresPerMinute, time.Minute)}
}

func (sc *scheduler) start(ctx context.Context) {
	sc.ctx = ctx
	sc.reload()
	sc.s.goJob(func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		sc.purge()
		for {
			select {
			case <-ctx.Done():
				sc.mu.Lock()
				if sc.cron != nil {
					sc.cron.Stop()
				}
				sc.mu.Unlock()
				return
			case <-t.C:
				sc.purge()
			}
		}
	})
}

// reload rebuilds the cron table from the tasks and patch policies tables.
func (sc *scheduler) reload() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.cron != nil {
		sc.cron.Stop()
	}
	c := cron.New(cron.WithParser(cronParser), cron.WithLocation(time.Local))
	tasks, _ := sc.s.db.ListTasks()
	for _, t := range tasks {
		if !t.Enabled || t.Schedule == "" {
			continue
		}
		task := t
		id, err := c.AddFunc(task.Schedule, func() { sc.runTask(&task, "scheduler") })
		if err != nil {
			slog.Warn("task schedule invalid", "task", task.Name, "err", err)
			continue
		}
		_ = id
	}
	pols, _ := sc.s.db.ListPatchPolicies()
	for _, p := range pols {
		if !p.Enabled {
			continue
		}
		pol := p
		if pol.ScanSchedule != "" {
			c.AddFunc(pol.ScanSchedule, func() { sc.runPatchPolicy(&pol, false) })
		}
		if pol.InstallSchedule != "" {
			c.AddFunc(pol.InstallSchedule, func() { sc.runPatchPolicy(&pol, true) })
		}
	}
	c.Start()
	sc.cron = c
	// next-run times for the UI
	for _, e := range c.Entries() {
		_ = e
	}
	for _, t := range tasks {
		if t.Enabled && t.Schedule != "" {
			if sched, err := cronParser.Parse(t.Schedule); err == nil {
				sc.s.db.Exec(`UPDATE tasks SET next_run = ? WHERE id = ?`, sched.Next(time.Now()).Unix(), t.ID)
			}
		} else {
			sc.s.db.Exec(`UPDATE tasks SET next_run = 0 WHERE id = ?`, t.ID)
		}
	}
}

// runTask executes a task against its resolved targets; returns device count.
func (sc *scheduler) runTask(t *Task, by string) int {
	agents, err := sc.s.db.ResolveTargets(t.Targets)
	if err != nil {
		return 0
	}
	sc.s.db.Exec(`UPDATE tasks SET last_run = ? WHERE id = ?`, now(), t.ID)
	if sched, err := cronParser.Parse(t.Schedule); err == nil && t.Schedule != "" {
		sc.s.db.Exec(`UPDATE tasks SET next_run = ? WHERE id = ?`, sched.Next(time.Now()).Unix(), t.ID)
	}
	var opts struct {
		Reboot  bool `json:"reboot_if_required"`
		Delay   int  `json:"delay_sec"`
		AllOnly bool `json:"online_only"`
	}
	json.Unmarshal(t.Options, &opts)
	n := 0
	for _, a := range agents {
		switch t.Kind {
		case "script":
			if t.ScriptID == nil {
				continue
			}
			script, err := sc.s.db.GetScript(*t.ScriptID)
			if err != nil {
				continue
			}
			if script.OSFilter != "" && script.OSFilter != a.OS {
				continue
			}
			taskID := t.ID
			if _, err := sc.s.runs.Start(a.ID, RunRequest{Script: script, Args: t.Args, Timeout: t.TimeoutSec, Trigger: "task", RunBy: by, TaskID: &taskID,
				Standing: &standingRef{Type: approvalTask, ID: strconv.FormatInt(t.ID, 10)}}); err == nil {
				n++
			}
		case "patch_scan":
			if sc.s.hub.IsOnline(a.ID) {
				go sc.s.patchScan(a.ID)
				n++
			}
		case "patch_install":
			if sc.s.hub.IsOnline(a.ID) {
				unit, ok := sc.s.unitForTask(t)
				go sc.s.patchInstall(a.ID, nil, opts.Reboot, by, sc.s.standingAuthForUnit(a.ID, unit, ok))
				n++
			}
		case "reboot":
			if sc.s.hub.IsOnline(a.ID) {
				ctx, cancel := context.WithTimeout(sc.ctx, quickTimeout)
				unit, ok := sc.s.unitForTask(t)
				sc.s.hub.RequestA(ctx, a.ID, protocol.ReqPower, protocol.Power{Action: "reboot", Delay: opts.Delay, Message: "Scheduled reboot by RMM task " + t.Name}, nil, sc.s.standingAuthForUnit(a.ID, unit, ok))
				cancel()
				n++
			}
		case "inventory":
			if sc.s.hub.IsOnline(a.ID) {
				go func(id string) {
					ctx, cancel := context.WithTimeout(sc.ctx, 2*time.Minute)
					defer cancel()
					sc.s.hub.Request(ctx, id, protocol.ReqInventoryRefresh, nil, nil)
				}(a.ID)
				n++
			}
		}
	}
	slog.Info("task ran", "task", t.Name, "devices", n, "by", by)
	return n
}

func (sc *scheduler) runPatchPolicy(p *PatchPolicy, install bool) {
	agents, err := sc.s.db.ResolveTargets(p.Targets)
	if err != nil {
		return
	}
	for _, a := range agents {
		if !sc.s.hub.IsOnline(a.ID) {
			continue
		}
		if a.MaintenanceUntil > now() && install {
			continue
		}
		if install {
			go sc.s.patchInstallPolicy(a.ID, p)
		} else {
			go sc.s.patchScan(a.ID)
		}
	}
}

func (sc *scheduler) agentOnline(id string) {
	sc.s.runs.releaseQueued(id)
	sc.automation("agent_online", id, nil)
	// first contact: a device with no inventory yet gets a patch scan soon after
	go func() {
		time.Sleep(20 * time.Second)
		var n int
		sc.s.db.QueryRow(`SELECT COUNT(*) FROM patches WHERE agent_id = ?`, id).Scan(&n)
		if n == 0 && sc.s.hub.IsOnline(id) {
			sc.s.patchScan(id)
		}
	}()
}

// automation fires every enabled automation whose trigger and filter match.
func (sc *scheduler) automation(trigger, agentID string, data map[string]any) {
	autos, err := sc.s.db.ListAutomations()
	if err != nil {
		return
	}
	var agent *Agent
	if agentID != "" {
		agent, _ = sc.s.db.GetAgent(agentID)
	}
	for _, a := range autos {
		if !a.Enabled || a.Trigger != trigger {
			continue
		}
		var filter struct {
			Targets  *Targets `json:"targets"`
			RuleIDs  []int64  `json:"rule_ids"`
			Severity string   `json:"severity"`
		}
		json.Unmarshal(a.Filter, &filter)
		if filter.Targets != nil && agent != nil && !filter.Targets.Matches(agent) {
			continue
		}
		if len(filter.RuleIDs) > 0 {
			rid, _ := data["rule_id"].(*int64)
			ok := false
			for _, id := range filter.RuleIDs {
				if rid != nil && *rid == id {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		if filter.Severity != "" {
			if sev, _ := data["severity"].(string); sev != filter.Severity {
				continue
			}
		}
		if !sc.autoLimit.allow(fmt.Sprintf("automation:%d", a.ID)) {
			slog.Warn("automation rate limit hit; skipping this fire (check for a loop: an alert_opened -> run_script automation whose script fails re-opens the alert)",
				"automation", a.Name, "trigger", trigger, "limit_per_minute", maxAutomationFiresPerMinute)
			continue
		}
		auto := a
		sc.s.goJob(func() { sc.runAutomation(&auto, agentID, agent, data) })
	}
}

func (sc *scheduler) runAutomation(a *Automation, agentID string, agent *Agent, data map[string]any) {
	var p struct {
		ScriptID int64    `json:"script_id"`
		Args     []string `json:"args"`
		Subject  string   `json:"subject"`
		URL      string   `json:"url"`
	}
	json.Unmarshal(a.ActionParams, &p)
	name := agentID
	if agent != nil {
		name = agent.DisplayName
	}
	switch a.Action {
	case "run_script":
		if agentID == "" || p.ScriptID == 0 {
			return
		}
		script, err := sc.s.db.GetScript(p.ScriptID)
		if err != nil {
			return
		}
		sc.s.runs.Start(agentID, RunRequest{Script: script, Args: p.Args, Trigger: "automation", RunBy: "automation:" + a.Name,
			Standing: &standingRef{Type: approvalAutomation, ID: strconv.FormatInt(a.ID, 10)}})
	case "email":
		subj := p.Subject
		if subj == "" {
			subj = fmt.Sprintf("[RMM] %s: %s", a.Trigger, name)
		}
		b, _ := json.MarshalIndent(data, "", "  ")
		sc.s.mail.Send(subj, fmt.Sprintf("Automation %q fired on trigger %s.\nDevice: %s\n\n%s\n", a.Name, a.Trigger, name, b))
	case "webhook":
		if p.URL == "" {
			return
		}
		payload := map[string]any{"automation": a.Name, "trigger": a.Trigger, "agent_id": agentID, "agent_name": name, "data": data, "ts": now()}
		b, _ := json.Marshal(payload)
		ctx, cancel := context.WithTimeout(sc.ctx, 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(b))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			slog.Warn("webhook failed", "automation", a.Name, "err", err)
			return
		}
		resp.Body.Close()
	}
}

// purge enforces retention. Defaults keep metrics 30 days, runs 90, audit 365.
func (sc *scheduler) purge() {
	var ret struct {
		MetricsDays int `json:"metrics_days"`
		RunsDays    int `json:"runs_days"`
		AuditDays   int `json:"audit_days"`
		EventsDays  int `json:"events_days"`
	}
	ret.MetricsDays, ret.RunsDays, ret.AuditDays, ret.EventsDays = 30, 90, 365, 30
	sc.s.db.SettingJSON("retention", &ret)
	day := int64(86400)
	// The two big append-only tables are deleted in bounded time slices so a
	// single statement never holds the one SQLite connection for long.
	sc.s.db.purgeByTS("metrics", "ts", now()-int64(ret.MetricsDays)*day)
	sc.s.db.purgeByTS("agent_events", "ts", now()-int64(ret.EventsDays)*day)
	// Drift history follows the events retention, as docs/BASELINES.md says.
	sc.s.db.purgeByTS("baseline_history", "ts", now()-int64(ret.EventsDays)*day)
	sc.s.db.Exec(`DELETE FROM script_runs WHERE started_at < ? AND status NOT IN ('running','queued')`, now()-int64(ret.RunsDays)*day)
	sc.s.db.Exec(`DELETE FROM audit WHERE ts < ?`, now()-int64(ret.AuditDays)*day)
	// Alerts whose kind has no auto-resolve path (a failed run, a failed
	// patch, a log line) are resolved once they are long stale, so they stop
	// being counted forever by the per-device open-alert count and can then
	// age out with every other resolved alert.
	if res, err := sc.s.db.Exec(`UPDATE alerts SET status='resolved', resolved_at=?
		WHERE status != 'resolved' AND opened_at < ? AND rule_kind IN ('script_failed','patch_failed','event')`,
		now(), now()-int64(staleAlertDays)*day); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			slog.Info("resolved stale alerts", "count", n, "older_than_days", staleAlertDays)
		}
	}
	sc.s.db.Exec(`DELETE FROM alerts WHERE status = 'resolved' AND resolved_at < ?`, now()-int64(ret.AuditDays)*day)
	sc.s.db.Exec(`DELETE FROM enroll_tokens WHERE expires_at < ?`, now()-day)
	sc.s.db.purgeSessions()
	// runs stuck in 'running' after a server restart can never finish
	sc.s.db.Exec(`UPDATE script_runs SET status='failed', stderr='server restarted while the script was running', finished_at=? WHERE status='running' AND started_at < ?`, now(), now()-6*3600)
}

// staleAlertDays is how long an alert of a kind that nothing auto-resolves
// may stay open before purge closes it.
const staleAlertDays = 30
