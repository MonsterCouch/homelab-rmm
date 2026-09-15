package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ---- stored shapes ----

// Baseline is a stored desired-state definition. Checks is filled by
// GetBaseline and left nil by ListBaselines, which is the hot path for the
// console list.
type Baseline struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Targets     Targets         `json:"targets"`
	Enforce     bool            `json:"enforce"`
	IntervalSec int             `json:"interval_sec"`
	NotifyEmail bool            `json:"notify_email"`
	Enabled     bool            `json:"enabled"`
	Version     int             `json:"version"`
	CreatedAt   int64           `json:"created_at"`
	UpdatedAt   int64           `json:"updated_at"`
	Checks      []BaselineCheck `json:"-"`
}

// BaselineCheck is one stored check. Its id is permanent: results, history
// rows and drift alert keys all address a check by it, and an edit that keeps
// the kind keeps the id (see saveBaseline).
type BaselineCheck struct {
	ID         int64           `json:"id"`
	BaselineID int64           `json:"baseline_id"`
	Position   int             `json:"position"`
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Params     json.RawMessage `json:"params"`
	Remediate  bool            `json:"remediate"`
	Severity   string          `json:"severity"`
	OSFilter   string          `json:"os_filter"`
	TimeoutSec int             `json:"timeout_sec"`
}

// BaselineResult is one (device, check) row as the API returns it.
type BaselineResult struct {
	CheckID    int64  `json:"check_id"`
	State      string `json:"state"`
	Expected   string `json:"expected"`
	Observed   string `json:"observed"`
	Detail     string `json:"detail"`
	Fixed      bool   `json:"fixed"`
	DurationMs int64  `json:"duration_ms"`
	Version    int    `json:"version"`
	Stale      bool   `json:"stale"`
	CheckedAt  int64  `json:"checked_at"`
	ReceivedAt int64  `json:"received_at"`
	Since      int64  `json:"since"`
}

// BaselineHistoryRow is one recorded transition.
type BaselineHistoryRow struct {
	ID           int64  `json:"id"`
	TS           int64  `json:"ts"`
	BaselineID   int64  `json:"baseline_id"`
	BaselineName string `json:"baseline_name"`
	CheckID      int64  `json:"check_id"`
	CheckName    string `json:"check_name"`
	FromState    string `json:"from_state"`
	ToState      string `json:"to_state"`
	Detail       string `json:"detail"`
}

// baselineState is the per (device, baseline) bookkeeping that orders reports.
type baselineState struct {
	Version        int
	LastReportTS   int64
	LastReceivedAt int64
	LastTrigger    string
}

// ---- reads ----

const baselineCols = `id, name, description, targets, enforce, interval_sec, notify_email, enabled, version, created_at, updated_at`

func scanBaseline(row interface{ Scan(...any) error }) (*Baseline, error) {
	var b Baseline
	var targets string
	if err := row.Scan(&b.ID, &b.Name, &b.Description, &targets, &b.Enforce, &b.IntervalSec, &b.NotifyEmail, &b.Enabled, &b.Version, &b.CreatedAt, &b.UpdatedAt); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(targets), &b.Targets)
	return &b, nil
}

// ListBaselines returns every baseline, without its checks.
func (d *DB) ListBaselines() ([]*Baseline, error) {
	rows, err := d.Query(`SELECT ` + baselineCols + ` FROM baselines ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Baseline{}
	for rows.Next() {
		b, err := scanBaseline(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListBaselinesWithChecks is ListBaselines plus every check, in one extra
// query rather than one per baseline (the config push reads the whole set for
// every connecting device).
func (d *DB) ListBaselinesWithChecks() ([]*Baseline, error) {
	list, err := d.ListBaselines()
	if err != nil {
		return nil, err
	}
	checks, err := d.allBaselineChecks()
	if err != nil {
		return nil, err
	}
	for _, b := range list {
		b.Checks = checks[b.ID]
		if b.Checks == nil {
			b.Checks = []BaselineCheck{}
		}
	}
	return list, nil
}

func (d *DB) allBaselineChecks() (map[int64][]BaselineCheck, error) {
	rows, err := d.Query(`SELECT id, baseline_id, position, name, kind, params, remediate, severity, os_filter, timeout_sec
		FROM baseline_checks ORDER BY baseline_id, position, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]BaselineCheck{}
	for rows.Next() {
		c, err := scanBaselineCheck(rows)
		if err != nil {
			return nil, err
		}
		out[c.BaselineID] = append(out[c.BaselineID], c)
	}
	return out, rows.Err()
}

// GetBaseline returns one baseline with its checks in position order.
func (d *DB) GetBaseline(id int64) (*Baseline, error) {
	b, err := scanBaseline(d.QueryRow(`SELECT `+baselineCols+` FROM baselines WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	b.Checks, err = d.baselineChecksFor(id)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// baselineChecksFor reads one baseline's checks in position order. GetBaseline
// runs on the ingest path, once per report, on the single SQLite connection:
// folding the whole baseline_checks table to pick one baseline out of it was
// a full scan per device per pass.
func (d *DB) baselineChecksFor(id int64) ([]BaselineCheck, error) {
	rows, err := d.Query(`SELECT id, baseline_id, position, name, kind, params, remediate, severity, os_filter, timeout_sec
		FROM baseline_checks WHERE baseline_id = ? ORDER BY position, id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BaselineCheck{}
	for rows.Next() {
		c, err := scanBaselineCheck(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanBaselineCheck(rows interface{ Scan(...any) error }) (BaselineCheck, error) {
	var c BaselineCheck
	var params string
	if err := rows.Scan(&c.ID, &c.BaselineID, &c.Position, &c.Name, &c.Kind, &params, &c.Remediate, &c.Severity, &c.OSFilter, &c.TimeoutSec); err != nil {
		return c, err
	}
	c.Params = json.RawMessage(params)
	if len(c.Params) == 0 {
		c.Params = json.RawMessage("{}")
	}
	return c, nil
}

func (d *DB) countBaselines() (int, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(*) FROM baselines`).Scan(&n)
	return n, err
}

// baselineResultsFor returns every stored result for a baseline, keyed by
// device.
func (d *DB) baselineResultsFor(baselineID int64) (map[string][]BaselineResult, error) {
	rows, err := d.Query(`SELECT agent_id, check_id, state, expected, observed, detail, fixed, duration_ms, version, stale, checked_at, received_at, since
		FROM baseline_results WHERE baseline_id = ?`, baselineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]BaselineResult{}
	for rows.Next() {
		var agentID string
		var r BaselineResult
		if err := rows.Scan(&agentID, &r.CheckID, &r.State, &r.Expected, &r.Observed, &r.Detail, &r.Fixed, &r.DurationMs, &r.Version, &r.Stale, &r.CheckedAt, &r.ReceivedAt, &r.Since); err != nil {
			return nil, err
		}
		out[agentID] = append(out[agentID], r)
	}
	return out, rows.Err()
}

// allBaselineResults is every stored result, keyed by baseline and then by
// device. The list page and the fleet summary both need the whole matrix, and
// one query beats one per baseline on the single SQLite connection.
func (d *DB) allBaselineResults() (map[int64]map[string][]BaselineResult, error) {
	rows, err := d.Query(`SELECT baseline_id, agent_id, check_id, state, expected, observed, detail, fixed, duration_ms, version, stale, checked_at, received_at, since
		FROM baseline_results`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]map[string][]BaselineResult{}
	for rows.Next() {
		var baselineID int64
		var agentID string
		var r BaselineResult
		if err := rows.Scan(&baselineID, &agentID, &r.CheckID, &r.State, &r.Expected, &r.Observed, &r.Detail, &r.Fixed, &r.DurationMs, &r.Version, &r.Stale, &r.CheckedAt, &r.ReceivedAt, &r.Since); err != nil {
			return nil, err
		}
		if out[baselineID] == nil {
			out[baselineID] = map[string][]BaselineResult{}
		}
		out[baselineID][agentID] = append(out[baselineID][agentID], r)
	}
	return out, rows.Err()
}

// baselineResultsForAgent returns one device's results keyed by baseline.
func (d *DB) baselineResultsForAgent(agentID string) (map[int64][]BaselineResult, error) {
	rows, err := d.Query(`SELECT baseline_id, check_id, state, expected, observed, detail, fixed, duration_ms, version, stale, checked_at, received_at, since
		FROM baseline_results WHERE agent_id = ?`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]BaselineResult{}
	for rows.Next() {
		var baselineID int64
		var r BaselineResult
		if err := rows.Scan(&baselineID, &r.CheckID, &r.State, &r.Expected, &r.Observed, &r.Detail, &r.Fixed, &r.DurationMs, &r.Version, &r.Stale, &r.CheckedAt, &r.ReceivedAt, &r.Since); err != nil {
			return nil, err
		}
		out[baselineID] = append(out[baselineID], r)
	}
	return out, rows.Err()
}

// countsFor folds one device's results for one baseline in the database
// rather than reading every row: the ingest path runs this once per report,
// on the single shared connection.
func (d *DB) countsFor(agentID string, baselineID int64, totalChecks int) (baselineCounts, error) {
	rows, err := d.Query(`SELECT state, stale, COUNT(*) FROM baseline_results WHERE agent_id = ? AND baseline_id = ? GROUP BY state, stale`, agentID, baselineID)
	if err != nil {
		return baselineCounts{}, err
	}
	defer rows.Close()
	var c baselineCounts
	stored := 0
	for rows.Next() {
		var state string
		var stale bool
		var n int
		if err := rows.Scan(&state, &stale, &n); err != nil {
			return baselineCounts{}, err
		}
		stored += n
		for i := 0; i < n; i++ {
			c.add(state, stale)
		}
	}
	if err := rows.Err(); err != nil {
		return baselineCounts{}, err
	}
	if missing := totalChecks - stored; missing > 0 {
		c.Unknown += missing
	}
	return c, nil
}

// failingCheckIDs are the checks that are drifted on a device right now
// (stale rows excluded: they describe a version nobody is evaluating).
func (d *DB) failingCheckIDs(agentID string, baselineID int64) ([]int64, error) {
	rows, err := d.Query(`SELECT check_id FROM baseline_results
		WHERE agent_id = ? AND baseline_id = ? AND stale = 0 AND state IN ('fail','error')`, agentID, baselineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (d *DB) baselineStateFor(agentID string, baselineID int64) (baselineState, bool) {
	var st baselineState
	err := d.QueryRow(`SELECT version, last_report_ts, last_received_at, last_trigger FROM baseline_state WHERE agent_id = ? AND baseline_id = ?`,
		agentID, baselineID).Scan(&st.Version, &st.LastReportTS, &st.LastReceivedAt, &st.LastTrigger)
	if err != nil {
		return baselineState{}, false
	}
	return st, true
}

// baselineStatesForAgent is every baseline_state row for one device.
func (d *DB) baselineStatesForAgent(agentID string) (map[int64]baselineState, error) {
	rows, err := d.Query(`SELECT baseline_id, version, last_report_ts, last_received_at, last_trigger FROM baseline_state WHERE agent_id = ?`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]baselineState{}
	for rows.Next() {
		var id int64
		var st baselineState
		if err := rows.Scan(&id, &st.Version, &st.LastReportTS, &st.LastReceivedAt, &st.LastTrigger); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

// baselineStatesFor is every baseline_state row for one baseline, keyed by device.
func (d *DB) baselineStatesFor(baselineID int64) (map[string]baselineState, error) {
	rows, err := d.Query(`SELECT agent_id, version, last_report_ts, last_received_at, last_trigger FROM baseline_state WHERE baseline_id = ?`, baselineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]baselineState{}
	for rows.Next() {
		var id string
		var st baselineState
		if err := rows.Scan(&id, &st.Version, &st.LastReportTS, &st.LastReceivedAt, &st.LastTrigger); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

// lastBaselineChange is MAX(baseline_history.ts) per baseline, 0 when none.
func (d *DB) lastBaselineChanges() (map[int64]int64, error) {
	rows, err := d.Query(`SELECT baseline_id, MAX(ts) FROM baseline_history GROUP BY baseline_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var id, ts int64
		if err := rows.Scan(&id, &ts); err != nil {
			return nil, err
		}
		out[id] = ts
	}
	return out, rows.Err()
}

// BaselineHistory returns a device's transitions, newest first. Baseline names
// are resolved at read time and are "" for a baseline that has been deleted -
// history rows deliberately outlive the rows they point at.
//
// baselineID > 0 narrows the rows to one baseline IN SQL. Filtering the newest
// N rows client-side instead is a lie on a device with several baselines: the
// newest 100 transitions can easily be entirely another baseline's, and the
// drawer then says "no transitions yet" over a full history.
func (d *DB) BaselineHistory(agentID string, limit int64, baselineID int64) ([]BaselineHistoryRow, error) {
	q := `SELECT h.id, h.ts, h.baseline_id, COALESCE(b.name, ''), h.check_id, h.check_name, h.from_state, h.to_state, h.detail
		FROM baseline_history h LEFT JOIN baselines b ON b.id = h.baseline_id
		WHERE h.agent_id = ?`
	args := []any{agentID}
	if baselineID > 0 {
		q += ` AND h.baseline_id = ?`
		args = append(args, baselineID)
	}
	q += ` ORDER BY h.ts DESC, h.id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BaselineHistoryRow{}
	for rows.Next() {
		var h BaselineHistoryRow
		if err := rows.Scan(&h.ID, &h.TS, &h.BaselineID, &h.BaselineName, &h.CheckID, &h.CheckName, &h.FromState, &h.ToState, &h.Detail); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---- writes ----

// baselineInput is the request body of POST/PUT /api/baselines.
type baselineInput struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Targets     Targets              `json:"targets"`
	Enforce     bool                 `json:"enforce"`
	IntervalSec int                  `json:"interval_sec"`
	NotifyEmail bool                 `json:"notify_email"`
	Enabled     bool                 `json:"enabled"`
	Checks      []baselineCheckInput `json:"checks"`
	// AllowEmptyTargets lets an operator save a baseline that currently
	// matches nothing on purpose (A50); without it that is a 400.
	AllowEmptyTargets bool `json:"allow_empty_targets"`
	// ConfirmFleetReboot is required to enforce an allow_reboot check against
	// every device (A41).
	ConfirmFleetReboot bool `json:"confirm_fleet_reboot"`
}

type baselineCheckInput struct {
	ID         int64           `json:"id"`
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Params     json.RawMessage `json:"params"`
	Remediate  bool            `json:"remediate"`
	Severity   string          `json:"severity"`
	OSFilter   string          `json:"os_filter"`
	TimeoutSec int             `json:"timeout_sec"`
}

// saveResult reports what a save did, so the handler can push config, clean
// up the checks that went away and audit the right action.
type saveResult struct {
	Created        bool
	VersionBumped  bool
	DeletedChecks  []int64
	EnabledChanged bool
}

var errUnknownCheckID = errors.New("unknown check id")

// errDuplicateCheckID is a body that names the same existing check twice. It
// has to be a 400 rather than a last-one-wins merge: the two entries collapse
// into a single row, and every OTHER check of the baseline - the ones whose
// ids the duplicate crowded out of the body - is then treated as "absent from
// the body" and deleted with its results. A copy/paste in the raw-JSON editor
// must not silently destroy half a baseline.
var errDuplicateCheckID = errors.New("duplicate check id")

// saveBaseline inserts or MERGES a baseline. A PUT is never a delete and
// reinsert of the checks: an id that belongs to this baseline is updated in
// place (keeping its results, its history and its open drift alert), an
// absent id is inserted, and an existing check missing from the body is
// deleted together with its results. Changing the kind of an existing id is a
// delete plus an insert, because `expected`/`observed` from the old kind mean
// nothing under the new one.
//
// The version is bumped by exactly one when a field the AGENT sees changed
// (name, enforce, interval, or any check field including its order) and never
// for description/targets/notify_email/enabled, which the agent never reads.
func (d *DB) saveBaseline(ctx context.Context, id int64, in baselineInput) (*Baseline, saveResult, error) {
	var res saveResult
	res.Created = id == 0
	var prev *Baseline
	if id != 0 {
		var err error
		prev, err = d.GetBaseline(id)
		if err != nil {
			return nil, res, err
		}
		res.EnabledChanged = prev.Enabled != in.Enabled
	}

	ts := now()
	err := d.withTx(ctx, func(tx *sql.Tx) error {
		if id == 0 {
			r, err := tx.Exec(`INSERT INTO baselines(name, description, targets, enforce, interval_sec, notify_email, enabled, version, created_at, updated_at)
				VALUES(?,?,?,?,?,?,?,1,?,?)`, in.Name, in.Description, jsonText(in.Targets), in.Enforce, in.IntervalSec, in.NotifyEmail, in.Enabled, ts, ts)
			if err != nil {
				return err
			}
			id, err = r.LastInsertId()
			if err != nil {
				return err
			}
		}

		existing := map[int64]BaselineCheck{}
		if prev != nil {
			for _, c := range prev.Checks {
				existing[c.ID] = c
			}
		}
		kept := map[int64]bool{}
		// seen is every id the body has already claimed, whichever branch it
		// took: an id that changed kind is deleted and re-inserted, so `kept`
		// alone would not notice it coming back a second time.
		seen := map[int64]bool{}
		for i, c := range in.Checks {
			if c.ID != 0 {
				if seen[c.ID] {
					return fmt.Errorf("%w: %d", errDuplicateCheckID, c.ID)
				}
				seen[c.ID] = true
			}
			params := string(c.Params)
			if strings.TrimSpace(params) == "" {
				params = "{}"
			}
			if c.ID != 0 {
				old, ok := existing[c.ID]
				if !ok {
					return fmt.Errorf("%w: %d", errUnknownCheckID, c.ID)
				}
				if old.Kind == c.Kind {
					if _, err := tx.Exec(`UPDATE baseline_checks SET position=?, name=?, params=?, remediate=?, severity=?, os_filter=?, timeout_sec=? WHERE id=? AND baseline_id=?`,
						i, c.Name, params, c.Remediate, c.Severity, c.OSFilter, c.TimeoutSec, c.ID, id); err != nil {
						return err
					}
					kept[c.ID] = true
					continue
				}
				// kind changed: the old id's stored state is meaningless now
				if err := deleteCheckTx(tx, c.ID); err != nil {
					return err
				}
				res.DeletedChecks = append(res.DeletedChecks, c.ID)
			}
			if _, err := tx.Exec(`INSERT INTO baseline_checks(baseline_id, position, name, kind, params, remediate, severity, os_filter, timeout_sec)
				VALUES(?,?,?,?,?,?,?,?,?)`, id, i, c.Name, c.Kind, params, c.Remediate, c.Severity, c.OSFilter, c.TimeoutSec); err != nil {
				return err
			}
		}
		// Sorted, so the audit entry and the alert cleanup that follow this
		// save are the same on every run.
		for _, cid := range sortedInt64s(mapKeys(existing)) {
			if kept[cid] {
				continue
			}
			already := false
			for _, d := range res.DeletedChecks {
				if d == cid {
					already = true
				}
			}
			if already {
				continue
			}
			if err := deleteCheckTx(tx, cid); err != nil {
				return err
			}
			res.DeletedChecks = append(res.DeletedChecks, cid)
		}

		if prev == nil {
			return nil
		}
		if _, err := tx.Exec(`UPDATE baselines SET name=?, description=?, targets=?, enforce=?, interval_sec=?, notify_email=?, enabled=?, updated_at=? WHERE id=?`,
			in.Name, in.Description, jsonText(in.Targets), in.Enforce, in.IntervalSec, in.NotifyEmail, in.Enabled, ts, id); err != nil {
			return err
		}
		// The version bump and the stale marking belong to the SAME commit as
		// the checks they describe. Run after it and a crash in between leaves
		// new checks carrying the old version - which every agent reads as
		// "nothing changed", so the fleet keeps evaluating a spec that no
		// longer exists and nothing ever bumps it again.
		cur, err := txBaselineForSignature(tx, id, in)
		if err != nil {
			return err
		}
		if agentVisibleSignature(prev) == agentVisibleSignature(cur) {
			return nil
		}
		// One bump per save, never a decrement, never a reuse. Stored results
		// are marked stale rather than deleted so the console can show the
		// last known state greyed out while the fleet re-evaluates.
		if _, err := tx.Exec(`UPDATE baselines SET version = version + 1 WHERE id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE baseline_results SET stale = 1 WHERE baseline_id = ?`, id); err != nil {
			return err
		}
		res.VersionBumped = true
		return nil
	})
	if err != nil {
		return nil, saveResult{Created: res.Created}, err
	}

	saved, err := d.GetBaseline(id)
	if err != nil {
		return nil, res, err
	}
	return saved, res, nil
}

// txBaselineForSignature reads the baseline back from inside the save
// transaction, so agentVisibleSignature compares the stored result against the
// stored previous state through exactly one formatter.
func txBaselineForSignature(tx *sql.Tx, id int64, in baselineInput) (*Baseline, error) {
	b := &Baseline{ID: id, Name: in.Name, Enforce: in.Enforce, IntervalSec: in.IntervalSec}
	rows, err := tx.Query(`SELECT id, baseline_id, position, name, kind, params, remediate, severity, os_filter, timeout_sec
		FROM baseline_checks WHERE baseline_id = ? ORDER BY position, id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanBaselineCheck(rows)
		if err != nil {
			return nil, err
		}
		b.Checks = append(b.Checks, c)
	}
	return b, rows.Err()
}

// deleteCheckTx removes a check and the results that point at it. History
// rows stay: they carry the check's name and no foreign key precisely so the
// audit trail survives the check.
func deleteCheckTx(tx *sql.Tx, checkID int64) error {
	if _, err := tx.Exec(`DELETE FROM baseline_results WHERE check_id = ?`, checkID); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM baseline_checks WHERE id = ?`, checkID)
	return err
}

// agentVisibleSignature is every field the agent receives in its config. Two
// baselines with the same signature are the same job to a device, so a save
// that leaves it unchanged must not bump the version (and must not make the
// whole fleet re-evaluate).
func agentVisibleSignature(b *Baseline) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\x00%v\x00%d\x00", b.Name, b.Enforce, b.IntervalSec)
	for _, c := range b.Checks {
		fmt.Fprintf(&sb, "%d\x01%d\x01%s\x01%s\x01%s\x01%v\x01%s\x01%s\x01%d\x00",
			c.ID, c.Position, c.Name, c.Kind, canonicalJSON(c.Params), c.Remediate, c.Severity, c.OSFilter, c.TimeoutSec)
	}
	return sb.String()
}

// canonicalJSON re-marshals an object so that key order and whitespace do not
// make an unedited check look changed (and bump the version of every baseline
// the console ever re-saves). UseNumber keeps a qword out of float64, where
// two different values could round to the same signature.
func canonicalJSON(raw json.RawMessage) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return string(raw)
	}
	b, err := json.Marshal(v) // encoding/json writes map keys in sorted order
	if err != nil {
		return string(raw)
	}
	return string(b)
}

// DeleteBaseline removes a baseline; checks cascade, and results cascade with
// them. Callers must first collect the devices that were matched, so the open
// drift alerts can be resolved (nothing else ever resolves them).
func (d *DB) DeleteBaseline(id int64) error {
	return d.withTx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM baseline_results WHERE baseline_id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM baseline_state WHERE baseline_id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM baseline_checks WHERE baseline_id = ?`, id); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM baselines WHERE id = ?`, id)
		return err
	})
}

// forgetBaselineOn drops everything a device holds for a baseline it no
// longer matches. The alerts are resolved by the caller through the alert
// engine, which is what fires the SSE event and the alert_resolved automation.
func (d *DB) forgetBaselineOn(agentID string, baselineID int64) error {
	return d.withTx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM baseline_results WHERE agent_id = ? AND baseline_id = ?`, agentID, baselineID); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM baseline_state WHERE agent_id = ? AND baseline_id = ?`, agentID, baselineID)
		return err
	})
}

// openDriftKeysFor lists the still-open drift alert keys for one device and
// baseline, including the flap alerts.
func (d *DB) openDriftKeysFor(agentID string, baselineID int64) ([]string, error) {
	rows, err := d.Query(`SELECT DISTINCT dedupe_key FROM alerts
		WHERE status != 'resolved' AND agent_id = ? AND (dedupe_key LIKE ? OR dedupe_key LIKE ?)`,
		agentID, fmt.Sprintf("drift:%d:%%", baselineID), fmt.Sprintf("driftflap:%d:%%", baselineID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// openDriftKeysForBaseline lists the still-open drift alert keys of a whole
// baseline, across every device - including devices that no longer match its
// targets. A delete has to resolve those too: after the rows are gone there is
// nothing left to find them from, and nothing else ever resolves a drift alert.
func (d *DB) openDriftKeysForBaseline(baselineID int64) ([]string, error) {
	rows, err := d.Query(`SELECT DISTINCT dedupe_key FROM alerts
		WHERE status != 'resolved' AND (dedupe_key LIKE ? OR dedupe_key LIKE ?)`,
		fmt.Sprintf("drift:%d:%%", baselineID), fmt.Sprintf("driftflap:%d:%%", baselineID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// openDriftKeysForCheck lists the still-open drift alert keys for one check,
// across every device (used when a check is deleted).
func (d *DB) openDriftKeysForCheck(baselineID, checkID int64) ([]string, error) {
	rows, err := d.Query(`SELECT DISTINCT dedupe_key FROM alerts
		WHERE status != 'resolved' AND (dedupe_key LIKE ? OR dedupe_key LIKE ?)`,
		fmt.Sprintf("drift:%d:%d:%%", baselineID, checkID), fmt.Sprintf("driftflap:%d:%d:%%", baselineID, checkID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (d *DB) countOpenDriftAlerts() int {
	var n int
	d.QueryRow(`SELECT COUNT(*) FROM alerts WHERE status != 'resolved' AND rule_kind = 'drift'`).Scan(&n)
	return n
}
