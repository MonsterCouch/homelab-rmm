package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// OpenDatabase opens an EXISTING database for a command-line tool: it
// migrates, and does nothing else. server.New is not usable here - it creates
// the data directory, seeds the starter scripts and rules, mints a setup code
// and marks every device offline, so pointing a CLI command at a typo created
// a plausible-looking empty fleet, and pointing it at a RUNNING server wrote
// "every device is offline" into the live database.
func OpenDatabase(cfg Config) (*DB, error) {
	path := cfg.path("rmm.db")
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no database at %s (wrong --data?)", path)
	}
	return openDB(path)
}

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
	// 2: repair enrollment tokens an older server drove below -1.
	//
	// Before the enrollment race was closed, concurrent agents each decremented
	// uses_left without a guard, so a one-use token could end up at -10. Any
	// negative value read as "unlimited", which turned a spent single-use
	// token into a permanent one. -1 is the operator's own "unlimited"; every
	// other negative is damage, and a damaged token is spent.
	`
UPDATE enroll_tokens SET uses_left = 0 WHERE uses_left < -1;
`,
	// 3: indexes for the three queries that were full table scans.
	//
	// metrics is PRIMARY KEY (agent_id, ts) WITHOUT ROWID, so the retention
	// delete "WHERE ts < ?" could use no index at all: at the documented
	// steady state (30 days of 30 s samples) that is ~86k rows per device,
	// scanned every hour on the single connection. agent_events is the same
	// shape. agents.key_hash is looked up on EVERY agent connect, so a
	// reconnect storm after a network blip was a full scan per attempt.
	`
CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(ts);
CREATE INDEX IF NOT EXISTS idx_agent_events_ts ON agent_events(ts);
CREATE INDEX IF NOT EXISTS idx_agents_key_hash ON agents(key_hash);
CREATE INDEX IF NOT EXISTS idx_patches_agent_status ON patches(agent_id, status);
`,
	// 4: baselines (desired state, drift detection, self-healing).
	//
	// baseline_checks.id is the ONLY identity a result, a history row or a
	// drift alert key ever uses, so it is AUTOINCREMENT: a bare INTEGER
	// PRIMARY KEY lets SQLite reuse the largest free rowid after a DELETE,
	// and the new check would inherit the dead one's results, its history and
	// its still-open alert (dedupe key drift:<baseline>:<check>:<agent>).
	//
	// baseline_history.agent_id and .check_id deliberately carry NO foreign
	// key: the audit trail has to survive the device or the check being
	// deleted. Every other reference is a real FK, and foreign_keys(ON) is in
	// the DSN, so an ingest for a check that vanished mid-report FAILS - the
	// ingest path checks membership inside the same transaction.
	//
	// IF NOT EXISTS throughout, like migration 3: a database whose
	// user_version was rewound (a downgrade, or a repair) re-runs the
	// statements, and a migration that cannot be replayed onto its own result
	// bricks the upgrade.
	`
CREATE TABLE IF NOT EXISTS baselines(
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	targets TEXT NOT NULL DEFAULT '{}',
	enforce INTEGER NOT NULL DEFAULT 0,
	interval_sec INTEGER NOT NULL DEFAULT 3600,
	notify_email INTEGER NOT NULL DEFAULT 0,
	enabled INTEGER NOT NULL DEFAULT 0,
	version INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline_checks(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	baseline_id INTEGER NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
	position INTEGER NOT NULL DEFAULT 0,
	name TEXT NOT NULL,
	kind TEXT NOT NULL,
	params TEXT NOT NULL DEFAULT '{}',
	remediate INTEGER NOT NULL DEFAULT 0,
	severity TEXT NOT NULL DEFAULT 'warning',
	os_filter TEXT NOT NULL DEFAULT '',
	timeout_sec INTEGER NOT NULL DEFAULT 60
);
CREATE INDEX IF NOT EXISTS idx_baseline_checks_baseline ON baseline_checks(baseline_id, position);

CREATE TABLE IF NOT EXISTS baseline_results(
	agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	check_id INTEGER NOT NULL REFERENCES baseline_checks(id) ON DELETE CASCADE,
	baseline_id INTEGER NOT NULL,
	state TEXT NOT NULL,
	expected TEXT NOT NULL DEFAULT '',
	observed TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT '',
	fixed INTEGER NOT NULL DEFAULT 0,
	duration_ms INTEGER NOT NULL DEFAULT 0,
	version INTEGER NOT NULL DEFAULT 0,
	stale INTEGER NOT NULL DEFAULT 0,
	checked_at INTEGER NOT NULL,
	received_at INTEGER NOT NULL,
	since INTEGER NOT NULL,
	PRIMARY KEY(agent_id, check_id)
);
CREATE INDEX IF NOT EXISTS idx_baseline_results_baseline ON baseline_results(baseline_id, state);

CREATE TABLE IF NOT EXISTS baseline_state(
	agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	baseline_id INTEGER NOT NULL,
	version INTEGER NOT NULL DEFAULT 0,
	last_report_ts INTEGER NOT NULL DEFAULT 0,
	last_received_at INTEGER NOT NULL DEFAULT 0,
	last_trigger TEXT NOT NULL DEFAULT '',
	PRIMARY KEY(agent_id, baseline_id)
);

CREATE TABLE IF NOT EXISTS baseline_history(
	id INTEGER PRIMARY KEY,
	agent_id TEXT NOT NULL,
	baseline_id INTEGER NOT NULL,
	check_id INTEGER NOT NULL,
	check_name TEXT NOT NULL DEFAULT '',
	ts INTEGER NOT NULL,
	from_state TEXT NOT NULL DEFAULT '',
	to_state TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_baseline_history_agent ON baseline_history(agent_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_baseline_history_ts ON baseline_history(ts);
`,
	// 5: patches.downloaded and patches.description.
	//
	// The agent has always sent IsDownloaded and the (truncated) description
	// with every Windows Update scan and the table had nowhere to put them,
	// so the console showed a bare 96 GB against a cumulative update Windows
	// had already staged on disk.
	//
	// The columns arrive by rebuild rather than by ALTER TABLE ADD COLUMN:
	// ADD COLUMN cannot be written IF NOT EXISTS, and a migration that
	// cannot be replayed onto its own result bricks a database whose
	// user_version was rewound - the rule migrations 3 and 4 spell out.
	// Replaying this one copies the table onto a fresh one of the same shape
	// and succeeds, but it is not quite a no-op: the copy carries only the
	// columns the pre-v5 table had, so downloaded and description fall back
	// to their defaults. Every patch scan rewrites both, so a replay costs
	// one scan, not the row.
	`
CREATE TABLE IF NOT EXISTS patches_v5 (
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
	downloaded INTEGER NOT NULL DEFAULT 0,     -- windows: the payload is already on the device
	description TEXT NOT NULL DEFAULT '',
	first_seen INTEGER NOT NULL,
	last_seen INTEGER NOT NULL,
	installed_at INTEGER NOT NULL DEFAULT 0,
	error TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (agent_id, patch_id)
);
INSERT INTO patches_v5(agent_id, patch_id, title, kb, severity, categories, size, source, version, status, reboot_required, first_seen, last_seen, installed_at, error)
	SELECT agent_id, patch_id, title, kb, severity, categories, size, source, version, status, reboot_required, first_seen, last_seen, installed_at, error FROM patches;
DROP TABLE patches;
ALTER TABLE patches_v5 RENAME TO patches;
CREATE INDEX IF NOT EXISTS idx_patches_agent_status ON patches(agent_id, status);
`,
}

// Close checkpoints the write-ahead log before closing, so a short-lived
// command does not leave the whole database sitting in rmm.db-wal beside a
// 4 KB rmm.db - which the backup and restore instructions treat as a file
// that only exists while the server is running.
func (d *DB) Close() error {
	d.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return d.DB.Close()
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

// placeholders renders "?, ?, ?" for an IN clause. n == 0 renders NULL, which
// matches nothing, so a caller that passes an empty set gets an empty result
// rather than a syntax error.
func placeholders(n int) string {
	if n <= 0 {
		return "NULL"
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// purgeByTS deletes rows older than cutoff in bounded time slices. A single
// unqualified DELETE over months of metrics holds the one and only SQLite
// connection for as long as it takes, blocking every HTTP request, every
// agent write and every alert evaluation behind it.
func (d *DB) purgeByTS(table, tsCol string, cutoff int64) {
	const window = int64(6 * 3600)
	for i := 0; i < 2000; i++ { // bounded so a clock jump cannot spin here
		var oldest sql.NullInt64
		if err := d.QueryRow(`SELECT MIN(` + tsCol + `) FROM ` + table).Scan(&oldest); err != nil {
			return
		}
		if !oldest.Valid || oldest.Int64 >= cutoff {
			return
		}
		step := oldest.Int64 + window
		if step > cutoff {
			step = cutoff
		}
		if _, err := d.Exec(`DELETE FROM `+table+` WHERE `+tsCol+` < ?`, step); err != nil {
			return
		}
	}
}

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
