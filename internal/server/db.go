package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite handle. modernc.org/sqlite is pure Go, so the server
// cross-compiles for Windows without a C toolchain. One writer at a time is
// enforced by SQLite itself; WAL mode lets readers proceed concurrently.
type DB struct {
	*sql.DB
}

func openDB(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer; one connection avoids SQLITE_BUSY storms
	db.SetConnMaxLifetime(0)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	d := &DB{db}
	if err := d.migrate(); err != nil {
		return nil, err
	}
	return d, nil
}

var migrations = []string{
	// 1: initial schema
	`
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE users (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'admin',   -- admin, tech, viewer
	totp_secret TEXT NOT NULL DEFAULT '',
	totp_enabled INTEGER NOT NULL DEFAULT 0,
	email TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	last_login INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE sessions (
	token TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT ''
);

CREATE TABLE groups (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);

CREATE TABLE enroll_tokens (
	id INTEGER PRIMARY KEY,
	token TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL DEFAULT '',
	group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
	uses_left INTEGER NOT NULL DEFAULT 1,   -- -1 = unlimited
	expires_at INTEGER NOT NULL,
	created_by TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);

CREATE TABLE agents (
	id TEXT PRIMARY KEY,
	key_hash TEXT NOT NULL,
	hostname TEXT NOT NULL DEFAULT '',
	display_name TEXT NOT NULL DEFAULT '',
	os TEXT NOT NULL DEFAULT '',
	platform TEXT NOT NULL DEFAULT '',
	arch TEXT NOT NULL DEFAULT '',
	version TEXT NOT NULL DEFAULT '',
	group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
	tags TEXT NOT NULL DEFAULT '[]',
	custom_fields TEXT NOT NULL DEFAULT '{}',
	notes TEXT NOT NULL DEFAULT '',
	inventory TEXT NOT NULL DEFAULT '{}',
	last_ip TEXT NOT NULL DEFAULT '',
	last_seen INTEGER NOT NULL DEFAULT 0,
	last_metrics TEXT NOT NULL DEFAULT '{}',
	online INTEGER NOT NULL DEFAULT 0,
	monitored_services TEXT NOT NULL DEFAULT '[]',
	maintenance_until INTEGER NOT NULL DEFAULT 0,
	enrolled_at INTEGER NOT NULL,
	pending_reboot INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE metrics (
	agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	ts INTEGER NOT NULL,
	cpu REAL NOT NULL,
	mem_used INTEGER NOT NULL,
	mem_total INTEGER NOT NULL,
	disks TEXT NOT NULL,
	net_rx INTEGER NOT NULL,
	net_tx INTEGER NOT NULL,
	uptime INTEGER NOT NULL,
	load1 REAL NOT NULL DEFAULT 0,
	procs INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (agent_id, ts)
) WITHOUT ROWID;

CREATE TABLE scripts (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	category TEXT NOT NULL DEFAULT '',
	language TEXT NOT NULL,           -- powershell, cmd, bash, sh, python
	body TEXT NOT NULL,
	params TEXT NOT NULL DEFAULT '[]', -- [{name, description, default, required}]
	timeout_sec INTEGER NOT NULL DEFAULT 300,
	os_filter TEXT NOT NULL DEFAULT '', -- '', windows, linux
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE script_runs (
	id TEXT PRIMARY KEY,
	script_id INTEGER REFERENCES scripts(id) ON DELETE SET NULL,
	script_name TEXT NOT NULL DEFAULT '',
	agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	task_id INTEGER,
	trigger TEXT NOT NULL DEFAULT 'manual', -- manual, task, automation, alert
	run_by TEXT NOT NULL DEFAULT '',
	args TEXT NOT NULL DEFAULT '[]',
	status TEXT NOT NULL DEFAULT 'pending',  -- pending, running, done, failed, timeout, cancelled
	exit_code INTEGER NOT NULL DEFAULT -1,
	stdout TEXT NOT NULL DEFAULT '',
	stderr TEXT NOT NULL DEFAULT '',
	started_at INTEGER NOT NULL,
	finished_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_script_runs_agent ON script_runs(agent_id, started_at DESC);
CREATE INDEX idx_script_runs_started ON script_runs(started_at DESC);

CREATE TABLE tasks (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	kind TEXT NOT NULL DEFAULT 'script',   -- script, patch_scan, patch_install, reboot, inventory
	script_id INTEGER REFERENCES scripts(id) ON DELETE SET NULL,
	args TEXT NOT NULL DEFAULT '[]',
	targets TEXT NOT NULL DEFAULT '{}',    -- {"all":bool,"agents":[],"groups":[],"tags":[],"os":""}
	schedule TEXT NOT NULL DEFAULT '',     -- cron expression; '' = manual only
	enabled INTEGER NOT NULL DEFAULT 1,
	timeout_sec INTEGER NOT NULL DEFAULT 300,
	options TEXT NOT NULL DEFAULT '{}',
	last_run INTEGER NOT NULL DEFAULT 0,
	next_run INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE automations (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	trigger TEXT NOT NULL,            -- agent_online, agent_offline, alert_opened, alert_resolved, enrolled, reboot_required
	filter TEXT NOT NULL DEFAULT '{}', -- {"rule_ids":[], "severity":"", "targets":{...}}
	action TEXT NOT NULL,             -- run_script, email, webhook
	action_params TEXT NOT NULL DEFAULT '{}',
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL
);

CREATE TABLE alert_rules (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	kind TEXT NOT NULL,        -- cpu, memory, disk, offline, service, reboot_required, script_failed, patch_failed, event
	params TEXT NOT NULL DEFAULT '{}',   -- {"threshold":90,"minutes":5,"mount":"","service":""}
	targets TEXT NOT NULL DEFAULT '{"all":true}',
	severity TEXT NOT NULL DEFAULT 'warning', -- info, warning, critical
	notify_email INTEGER NOT NULL DEFAULT 1,
	auto_resolve INTEGER NOT NULL DEFAULT 1,
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL
);

CREATE TABLE alerts (
	id INTEGER PRIMARY KEY,
	rule_id INTEGER REFERENCES alert_rules(id) ON DELETE SET NULL,
	rule_kind TEXT NOT NULL DEFAULT '',
	agent_id TEXT REFERENCES agents(id) ON DELETE CASCADE,
	severity TEXT NOT NULL,
	title TEXT NOT NULL,
	message TEXT NOT NULL DEFAULT '',
	dedupe_key TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'open',   -- open, acked, resolved
	opened_at INTEGER NOT NULL,
	acked_at INTEGER NOT NULL DEFAULT 0,
	acked_by TEXT NOT NULL DEFAULT '',
	resolved_at INTEGER NOT NULL DEFAULT 0,
	notified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_alerts_status ON alerts(status, opened_at DESC);
CREATE INDEX idx_alerts_dedupe ON alerts(dedupe_key, status);

CREATE TABLE patches (
	agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	patch_id TEXT NOT NULL,
	title TEXT NOT NULL,
	kb TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL DEFAULT '',
	categories TEXT NOT NULL DEFAULT '[]',
	size INTEGER NOT NULL DEFAULT 0,
	source TEXT NOT NULL DEFAULT '',
	version TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'available',  -- available, approved, installing, installed, failed, ignored
	reboot_required INTEGER NOT NULL DEFAULT 0,
	first_seen INTEGER NOT NULL,
	last_seen INTEGER NOT NULL,
	installed_at INTEGER NOT NULL DEFAULT 0,
	error TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (agent_id, patch_id)
);

CREATE TABLE patch_policies (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	targets TEXT NOT NULL DEFAULT '{"all":true}',
	scan_schedule TEXT NOT NULL DEFAULT '0 */6 * * *',
	install_schedule TEXT NOT NULL DEFAULT '',     -- '' = manual approval only
	mode TEXT NOT NULL DEFAULT 'approved',         -- approved (install approved only), all, security
	reboot TEXT NOT NULL DEFAULT 'never',          -- never, if_required, always
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL
);

CREATE TABLE audit (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,
	user TEXT NOT NULL,
	ip TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL,
	target TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_ts ON audit(ts DESC);

CREATE TABLE agent_events (
	id INTEGER PRIMARY KEY,
	agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	ts INTEGER NOT NULL,
	kind TEXT NOT NULL,
	message TEXT NOT NULL,
	fields TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_agent_events ON agent_events(agent_id, ts DESC);
`,
}

func (d *DB) migrate() error {
	var version int
	if err := d.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		slog.Info("database migrated", "version", i+1)
	}
	return nil
}

// ---- settings ----

func (d *DB) Setting(key, def string) string {
	var v string
	if err := d.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

func (d *DB) SetSetting(key, value string) error {
	_, err := d.Exec(`INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (d *DB) SettingJSON(key string, out any) bool {
	v := d.Setting(key, "")
	if v == "" {
		return false
	}
	return json.Unmarshal([]byte(v), out) == nil
}

func (d *DB) SetSettingJSON(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return d.SetSetting(key, string(b))
}

// ---- audit ----

func (d *DB) Audit(user, ip, action, target string, details any) {
	det := ""
	switch v := details.(type) {
	case nil:
	case string:
		det = v
	default:
		b, _ := json.Marshal(v)
		det = string(b)
	}
	if _, err := d.Exec(`INSERT INTO audit(ts, user, ip, action, target, details) VALUES(?,?,?,?,?,?)`,
		now(), user, ip, action, target, det); err != nil {
		slog.Warn("audit write failed", "err", err)
	}
}

func now() int64 { return time.Now().Unix() }

// jsonText marshals for storage in a TEXT column, never failing.
func jsonText(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

// withTx runs fn inside a transaction.
func (d *DB) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
