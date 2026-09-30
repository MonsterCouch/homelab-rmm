package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Agent is the API shape of a device.
type Agent struct {
	ID                string              `json:"id"`
	Hostname          string              `json:"hostname"`
	DisplayName       string              `json:"display_name"`
	OS                string              `json:"os"`
	Platform          string              `json:"platform"`
	Arch              string              `json:"arch"`
	Version           string              `json:"version"`
	GroupID           *int64              `json:"group_id"`
	GroupName         string              `json:"group_name,omitempty"`
	OrgID             string              `json:"org_id"`
	OrgName           string              `json:"org_name,omitempty"`
	SiteID            string              `json:"site_id"`
	SiteName          string              `json:"site_name,omitempty"`
	Tags              []string            `json:"tags"`
	CustomFields      map[string]string   `json:"custom_fields"`
	Notes             string              `json:"notes"`
	LastIP            string              `json:"last_ip"`
	LastSeen          int64               `json:"last_seen"`
	Online            bool                `json:"online"`
	MonitoredServices []string            `json:"monitored_services"`
	MaintenanceUntil  int64               `json:"maintenance_until"`
	EnrolledAt        int64               `json:"enrolled_at"`
	PendingReboot     bool                `json:"pending_reboot"`
	LastMetrics       *protocol.Metrics   `json:"last_metrics,omitempty"`
	Inventory         *protocol.Inventory `json:"inventory,omitempty"`
	OpenAlerts        int                 `json:"open_alerts"`
	PatchesAvailable  int                 `json:"patches_available"`
	Isolated          bool                `json:"isolated"`
	IsolatedAt        int64               `json:"isolated_at"`
	IsolatedBy        string              `json:"isolated_by,omitempty"`
}

const agentCols = `a.id, a.hostname, a.display_name, a.os, a.platform, a.arch, a.version, a.group_id, COALESCE(g.name,''),
	COALESCE(a.org_id,''), COALESCE(o.name,''), COALESCE(a.site_id,''), COALESCE(s.name,''),
	a.tags, a.custom_fields, a.notes, a.last_ip, a.last_seen, a.online, a.monitored_services, a.maintenance_until, a.enrolled_at,
	a.pending_reboot, a.isolated, a.isolated_at, a.isolated_by, a.last_metrics,
	(SELECT COUNT(*) FROM alerts al WHERE al.agent_id = a.id AND al.status != 'resolved'),
	(SELECT COUNT(*) FROM patches p WHERE p.agent_id = a.id AND p.status IN ('available','approved'))`

func scanAgent(rows interface{ Scan(...any) error }, withInventory bool) (*Agent, error) {
	var a Agent
	var tags, cf, ms, lm, inv string
	var gid sql.NullInt64
	var isoInt int
	dest := []any{&a.ID, &a.Hostname, &a.DisplayName, &a.OS, &a.Platform, &a.Arch, &a.Version, &gid, &a.GroupName,
		&a.OrgID, &a.OrgName, &a.SiteID, &a.SiteName,
		&tags, &cf, &a.Notes, &a.LastIP, &a.LastSeen, &a.Online, &ms, &a.MaintenanceUntil, &a.EnrolledAt,
		&a.PendingReboot, &isoInt, &a.IsolatedAt, &a.IsolatedBy, &lm, &a.OpenAlerts, &a.PatchesAvailable}
	if withInventory {
		dest = append(dest, &inv)
	}
	if err := rows.Scan(dest...); err != nil {
		return nil, err
	}
	if gid.Valid {
		a.GroupID = &gid.Int64
	}
	a.Isolated = (isoInt == 1)
	a.Tags = []string{}
	json.Unmarshal([]byte(tags), &a.Tags)
	a.CustomFields = map[string]string{}
	json.Unmarshal([]byte(cf), &a.CustomFields)
	a.MonitoredServices = []string{}
	json.Unmarshal([]byte(ms), &a.MonitoredServices)
	if lm != "" && lm != "{}" {
		var m protocol.Metrics
		if json.Unmarshal([]byte(lm), &m) == nil {
			a.LastMetrics = &m
		}
	}
	if withInventory && inv != "" && inv != "{}" {
		var i protocol.Inventory
		if json.Unmarshal([]byte(inv), &i) == nil {
			a.Inventory = &i
		}
	}
	if a.DisplayName == "" {
		a.DisplayName = a.Hostname
	}
	return &a, nil
}

func (d *DB) ListAgents() ([]*Agent, error) {
	rows, err := d.Query(`SELECT ` + agentCols + ` FROM agents a
		LEFT JOIN groups g ON g.id = a.group_id
		LEFT JOIN organizations o ON o.id = a.org_id
		LEFT JOIN sites s ON s.id = a.site_id
		ORDER BY a.online DESC, a.hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Agent{}
	for rows.Next() {
		a, err := scanAgent(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) GetAgent(id string) (*Agent, error) {
	row := d.QueryRow(`SELECT `+agentCols+`, a.inventory FROM agents a
		LEFT JOIN groups g ON g.id = a.group_id
		LEFT JOIN organizations o ON o.id = a.org_id
		LEFT JOIN sites s ON s.id = a.site_id
		WHERE a.id = ?`, id)
	a, err := scanAgent(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return a, err
}

var errNotFound = errors.New("not found")

func (d *DB) agentByKey(key string) (string, bool) {
	var id string
	if err := d.QueryRow(`SELECT id FROM agents WHERE key_hash = ?`, hashKey(key)).Scan(&id); err != nil {
		return "", false
	}
	return id, true
}

// unlimitedUses is the only non-positive uses_left that still enrolls. Any
// other value <= 0 is exhausted, so a row an older server drove negative (or a
// hand-edited one) reads as spent rather than as "unlimited forever".
const unlimitedUses = -1

func usesExhausted(usesLeft int) bool { return usesLeft != unlimitedUses && usesLeft <= 0 }

// checkEnrollToken reports whether a token could still enroll a device.
func (d *DB) checkEnrollToken(token string) error {
	var usesLeft int
	var expires int64
	if err := d.QueryRow(`SELECT uses_left, expires_at FROM enroll_tokens WHERE token = ?`, token).Scan(&usesLeft, &expires); err != nil {
		return errors.New("unknown token")
	}
	if expires < now() {
		return errors.New("token expired")
	}
	if usesExhausted(usesLeft) {
		return errors.New("token exhausted")
	}
	return nil
}

// enrollResult is what an enrollment did, beyond the identity it issued.
type enrollResult struct {
	ID  string
	Key string
	// Rekeyed: an existing OFFLINE record with this hostname+os was adopted
	// and given the new key (a reinstall - or a device claiming another's
	// hostname, which is why it is audited apart from a fresh enrollment).
	Rekeyed bool
	// DuplicateHostname: a record with this hostname+os already existed but
	// was online, so a second one was created. Same takeover attempt, louder
	// symptom (two devices with one name in the console).
	DuplicateHostname bool
}

// enrollAgent consumes an enrollment token and creates the agent record. The
// token is consumed with a conditional UPDATE inside the same transaction
// that creates the device, so concurrent enrollments cannot stretch a
// single-use token, and uses_left never drops below zero (-1 = unlimited).
// isOnline reports whether a device has a live socket right now. The
// agents.online column is a convenience that a restart or a replaced socket
// can leave stale, and a stale 0 widens the window in which another machine
// claiming the same hostname takes over the record.
func (d *DB) enrollAgent(token string, hello protocol.Hello, ip string, isOnline func(string) bool) (enrollResult, error) {
	var res enrollResult
	res.Key = randomToken(32)
	err := d.withTx(context.Background(), func(tx *sql.Tx) error {
		var (
			tid      int64
			usesLeft int
			expires  int64
			gid      sql.NullInt64
			orgID    sql.NullString
			siteID   sql.NullString
		)
		if err := tx.QueryRow(`SELECT id, uses_left, expires_at, group_id, org_id, site_id FROM enroll_tokens WHERE token = ?`, token).Scan(&tid, &usesLeft, &expires, &gid, &orgID, &siteID); err != nil {
			return errors.New("unknown token")
		}
		if expires < now() {
			return errors.New("token expired")
		}
		if usesExhausted(usesLeft) {
			return errors.New("token exhausted")
		}
		if usesLeft > 0 {
			r, err := tx.Exec(`UPDATE enroll_tokens SET uses_left = uses_left - 1 WHERE id = ? AND uses_left > 0`, tid)
			if err != nil {
				return err
			}
			if n, _ := r.RowsAffected(); n != 1 {
				return errors.New("token exhausted")
			}
		}
		finalOrg := "org_default"
		if orgID.Valid && orgID.String != "" {
			finalOrg = orgID.String
		}
		finalSite := "site_default"
		if siteID.Valid && siteID.String != "" {
			finalSite = siteID.String
		}
		// A re-enrollment from the same hostname+os replaces the old record's
		// key instead of creating a duplicate device (reinstalls are common).
		// Liveness comes from the hub, not the column.
		// Scope to finalOrg to prevent cross-tenant device hijacking.
		var candidates []string
		crows, qerr := tx.Query(`SELECT id FROM agents WHERE hostname = ? AND os = ? AND org_id = ? ORDER BY online ASC`, hello.Hostname, hello.OS, finalOrg)
		if qerr == nil {
			for crows.Next() {
				var id string
				crows.Scan(&id)
				candidates = append(candidates, id)
			}
			crows.Close()
		}
		var existing string
		for _, id := range candidates {
			if isOnline == nil || !isOnline(id) {
				existing = id
				break
			}
		}
		if existing != "" {
			res.ID, res.Rekeyed = existing, true
			_, err := tx.Exec(`UPDATE agents SET key_hash = ?, version = ?, platform = ?, arch = ?, last_ip = ? WHERE id = ?`,
				hashKey(res.Key), hello.Version, hello.Platform, hello.Arch, ip, res.ID)
			return err
		}
		// hostname is not unique, so an enrollment that collides with a device
		// that is currently ONLINE gets its own record. Report it: the record
		// it failed to adopt is the one it was aiming at.
		res.DuplicateHostname = len(candidates) > 0
		res.ID = randomHex(8)
		_, err := tx.Exec(`INSERT INTO agents(id, key_hash, hostname, os, platform, arch, version, group_id, org_id, site_id, last_ip, enrolled_at, last_seen)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, res.ID, hashKey(res.Key), hello.Hostname, hello.OS, hello.Platform, hello.Arch, hello.Version, gid, finalOrg, finalSite, ip, now(), now())
		return err
	})
	if err != nil {
		return enrollResult{}, err
	}
	return res, nil
}

func (d *DB) markOnline(id string, hello protocol.Hello, ip string, online bool) {
	d.Exec(`UPDATE agents SET online = ?, last_seen = ?, last_ip = ?, version = ?, platform = ?, arch = ?, hostname = ? WHERE id = ?`,
		online, now(), ip, hello.Version, hello.Platform, hello.Arch, hello.Hostname, id)
}

func (d *DB) markAllOffline() {
	d.Exec(`UPDATE agents SET online = 0`)
}

func (d *DB) saveInventory(id string, inv *protocol.Inventory) error {
	_, err := d.Exec(`UPDATE agents SET inventory = ?, hostname = ?, pending_reboot = ?, last_seen = ? WHERE id = ?`,
		jsonText(inv), inv.Hostname, inv.PendingReboot, now(), id)
	return err
}

func (d *DB) saveMetrics(id string, m *protocol.Metrics) error {
	_, err := d.Exec(`INSERT OR REPLACE INTO metrics(agent_id, ts, cpu, mem_used, mem_total, disks, net_rx, net_tx, uptime, load1, procs)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, m.TS, m.CPUPct, m.MemUsed, m.MemTotal, jsonText(m.Disks), m.NetRxBps, m.NetTxBps, m.Uptime, m.Load1, m.ProcCount)
	if err != nil {
		return err
	}
	_, err = d.Exec(`UPDATE agents SET last_metrics = ?, last_seen = ?, pending_reboot = ? WHERE id = ?`, jsonText(m), now(), m.PendingReboot, id)
	return err
}

// MetricRow is one sample as returned to the UI.
type MetricRow struct {
	TS       int64                `json:"ts"`
	CPU      float64              `json:"cpu"`
	MemUsed  uint64               `json:"mem_used"`
	MemTotal uint64               `json:"mem_total"`
	Disks    []protocol.DiskUsage `json:"disks"`
	NetRx    uint64               `json:"net_rx"`
	NetTx    uint64               `json:"net_tx"`
	Uptime   uint64               `json:"uptime"`
	Load1    float64              `json:"load1"`
	Procs    int                  `json:"procs"`
}

// maxMetricPoints caps the buckets one chart may ask for. Without it
// ?points=100000000 made the bucket 1 second wide and streamed every stored
// sample for the device - tens of thousands of rows with embedded disks JSON -
// through the single database connection, blocking everything else.
const maxMetricPoints = 2000

func (d *DB) MetricsRange(id string, from, to int64, maxPoints int) ([]MetricRow, error) {
	if maxPoints <= 0 {
		maxPoints = 600
	}
	if maxPoints > maxMetricPoints {
		maxPoints = maxMetricPoints
	}
	if from < 0 {
		from = 0
	}
	// Bucket to at most maxPoints by averaging within buckets; SQLite does the
	// grouping so a 30-day range does not ship a million rows to the browser.
	span := to - from
	if span <= 0 {
		span = 1
	}
	bucket := span / int64(maxPoints)
	if bucket < 1 {
		bucket = 1
	}
	// disks and uptime are bare columns beside exactly one max() aggregate,
	// which SQLite defines as coming from the row that produced that maximum:
	// the LAST sample in the bucket. MAX(disks) was a lexicographic maximum
	// over JSON text, so the disk series was an arbitrary sample that
	// corresponded to no real point in time.
	rows, err := d.Query(`SELECT (ts / ?) * ?, AVG(cpu), AVG(mem_used), AVG(mem_total), AVG(net_rx), AVG(net_tx), AVG(load1), AVG(procs), MAX(ts), disks, uptime
		FROM metrics WHERE agent_id = ? AND ts BETWEEN ? AND ? GROUP BY 1 ORDER BY 1`, bucket, bucket, id, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MetricRow{}
	for rows.Next() {
		var r MetricRow
		var disks string
		var mem, memTotal, rx, tx, procs float64
		var lastTS int64
		if err := rows.Scan(&r.TS, &r.CPU, &mem, &memTotal, &rx, &tx, &r.Load1, &procs, &lastTS, &disks, &r.Uptime); err != nil {
			return nil, err
		}
		r.MemUsed, r.MemTotal, r.NetRx, r.NetTx, r.Procs = uint64(mem), uint64(memTotal), uint64(rx), uint64(tx), int(procs)
		json.Unmarshal([]byte(disks), &r.Disks)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AgentUpdate is the editable subset of an agent.
type AgentUpdate struct {
	DisplayName       *string           `json:"display_name"`
	GroupID           *int64            `json:"group_id"`
	ClearGroup        bool              `json:"clear_group"`
	Tags              []string          `json:"tags"`
	CustomFields      map[string]string `json:"custom_fields"`
	Notes             *string           `json:"notes"`
	OrgID             *string           `json:"org_id"`
	SiteID            *string           `json:"site_id"`
	MonitoredServices []string          `json:"monitored_services"`
	MaintenanceUntil  *int64            `json:"maintenance_until"`
}

// Bounds for the fields an operator types on a device. Nothing here is a
// security boundary; they keep one device from degrading the console for
// everyone (notes ride along on every GET /api/agents row) and keep a
// mistyped maintenance window from silencing a device for good.
const (
	maxDisplayNameLen  = 200
	maxNotesLen        = 16 << 10
	maxTagCount        = 64
	maxTagLen          = 64
	maxCustomFields    = 64
	maxCustomFieldLen  = 4096
	maxMaintenanceDays = 30
)

// Validate bounds the editable fields. An out-of-range value is refused with
// the limit named rather than clamped: an operator who asked for a year of
// maintenance should be told it is a month, not discover it later.
func (u AgentUpdate) Validate() error {
	if u.DisplayName != nil && len(*u.DisplayName) > maxDisplayNameLen {
		return fmt.Errorf("display_name: at most %d characters", maxDisplayNameLen)
	}
	if u.Notes != nil && len(*u.Notes) > maxNotesLen {
		return fmt.Errorf("notes: at most %d characters", maxNotesLen)
	}
	if len(u.Tags) > maxTagCount {
		return fmt.Errorf("tags: at most %d tags", maxTagCount)
	}
	for _, t := range u.Tags {
		if len(t) > maxTagLen {
			return fmt.Errorf("tags: each tag is at most %d characters", maxTagLen)
		}
	}
	if len(u.CustomFields) > maxCustomFields {
		return fmt.Errorf("custom_fields: at most %d fields", maxCustomFields)
	}
	for k, v := range u.CustomFields {
		if len(k) > maxTagLen || len(v) > maxCustomFieldLen {
			return fmt.Errorf("custom_fields: a name is at most %d and a value at most %d characters", maxTagLen, maxCustomFieldLen)
		}
	}
	if u.MaintenanceUntil != nil {
		// 0 is "not in maintenance" and has to stay allowed. A negative value
		// is always in the past, and an unbounded one (MaxInt64, or seconds
		// mistaken for milliseconds) suppresses every alert and every patch
		// install for that device forever, with nothing in the UI saying so.
		v := *u.MaintenanceUntil
		if v < 0 {
			return errors.New("maintenance_until: must not be negative")
		}
		if limit := now() + maxMaintenanceDays*24*3600; v > limit {
			return fmt.Errorf("maintenance_until: at most %d days ahead", maxMaintenanceDays)
		}
	}
	return nil
}

func (d *DB) UpdateAgent(id string, u AgentUpdate) error {
	set, args := []string{}, []any{}
	if u.DisplayName != nil {
		set, args = append(set, "display_name = ?"), append(args, strings.TrimSpace(*u.DisplayName))
	}
	if u.ClearGroup {
		set = append(set, "group_id = NULL")
	} else if u.GroupID != nil {
		set, args = append(set, "group_id = ?"), append(args, *u.GroupID)
	}
	if u.Tags != nil {
		set, args = append(set, "tags = ?"), append(args, jsonText(u.Tags))
	}
	if u.CustomFields != nil {
		set, args = append(set, "custom_fields = ?"), append(args, jsonText(u.CustomFields))
	}
	if u.Notes != nil {
		set, args = append(set, "notes = ?"), append(args, *u.Notes)
	}
	if u.OrgID != nil {
		set, args = append(set, "org_id = ?"), append(args, *u.OrgID)
	}
	if u.SiteID != nil {
		set, args = append(set, "site_id = ?"), append(args, *u.SiteID)
	}
	if u.MonitoredServices != nil {
		set, args = append(set, "monitored_services = ?"), append(args, jsonText(u.MonitoredServices))
	}
	if u.MaintenanceUntil != nil {
		set, args = append(set, "maintenance_until = ?"), append(args, *u.MaintenanceUntil)
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := d.Exec(fmt.Sprintf(`UPDATE agents SET %s WHERE id = ?`, strings.Join(set, ", ")), args...)
	return err
}

func (d *DB) DeleteAgent(id string) error {
	_, err := d.Exec(`DELETE FROM agents WHERE id = ?`, id)
	return err
}

// Targets selects devices for tasks, alert rules and patch policies.
type Targets struct {
	All           bool     `json:"all"`
	Agents        []string `json:"agents,omitempty"`
	Groups        []int64  `json:"groups,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	OS            string   `json:"os,omitempty"`
	Organizations []string `json:"organizations,omitempty"`
	Sites         []string `json:"sites,omitempty"`
}

// Matches reports whether a device is selected by the target set.
func (t Targets) Matches(a *Agent) bool {
	if t.OS != "" && a.OS != t.OS {
		return false
	}
	if len(t.Organizations) > 0 {
		matchedOrg := false
		for _, org := range t.Organizations {
			if org == a.OrgID {
				matchedOrg = true
				break
			}
		}
		if !matchedOrg {
			return false
		}
	}
	if len(t.Sites) > 0 {
		matchedSite := false
		for _, site := range t.Sites {
			if site == a.SiteID {
				matchedSite = true
				break
			}
		}
		if !matchedSite {
			return false
		}
	}
	if t.All {
		return true
	}
	for _, id := range t.Agents {
		if id == a.ID {
			return true
		}
	}
	if a.GroupID != nil {
		for _, g := range t.Groups {
			if g == *a.GroupID {
				return true
			}
		}
	}
	for _, want := range t.Tags {
		for _, have := range a.Tags {
			if strings.EqualFold(want, have) {
				return true
			}
		}
	}
	hasSelector := len(t.Agents) > 0 || len(t.Groups) > 0 || len(t.Tags) > 0
	if !hasSelector && (len(t.Organizations) > 0 || len(t.Sites) > 0) {
		return true
	}
	return false
}

// ResolveTargets returns every agent matched by t.
func (d *DB) ResolveTargets(t Targets) ([]*Agent, error) {
	all, err := d.ListAgents()
	if err != nil {
		return nil, err
	}
	var out []*Agent
	for _, a := range all {
		if t.Matches(a) {
			out = append(out, a)
		}
	}
	return out, nil
}

// ---- groups ----

type Group struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	AgentCount  int    `json:"agent_count"`
	CreatedAt   int64  `json:"created_at"`
}

func (d *DB) ListGroups() ([]Group, error) {
	rows, err := d.Query(`SELECT g.id, g.name, g.description, g.created_at, (SELECT COUNT(*) FROM agents a WHERE a.group_id = g.id) FROM groups g ORDER BY g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.AgentCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ---- enrollment tokens ----

type EnrollToken struct {
	ID        int64  `json:"id"`
	Token     string `json:"token"`
	Name      string `json:"name"`
	GroupID   *int64 `json:"group_id"`
	OrgID     string `json:"org_id"`
	SiteID    string `json:"site_id"`
	UsesLeft  int    `json:"uses_left"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
}

func (d *DB) ListEnrollTokens() ([]EnrollToken, error) {
	rows, err := d.Query(`SELECT id, token, name, group_id, COALESCE(org_id, 'org_default'), COALESCE(site_id, 'site_default'), uses_left, expires_at, created_by, created_at FROM enroll_tokens WHERE expires_at > ? AND uses_left != 0 ORDER BY created_at DESC`, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnrollToken{}
	for rows.Next() {
		var t EnrollToken
		var gid sql.NullInt64
		if err := rows.Scan(&t.ID, &t.Token, &t.Name, &gid, &t.OrgID, &t.SiteID, &t.UsesLeft, &t.ExpiresAt, &t.CreatedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		if gid.Valid {
			t.GroupID = &gid.Int64
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) SetAgentIsolated(id string, isolated bool, by string) error {
	var isoInt int
	var isoAt int64
	if isolated {
		isoInt = 1
		isoAt = now()
	}
	_, err := d.Exec(`UPDATE agents SET isolated = ?, isolated_at = ?, isolated_by = ? WHERE id = ?`, isoInt, isoAt, by, id)
	return err
}

