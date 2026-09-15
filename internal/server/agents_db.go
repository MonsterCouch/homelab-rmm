package server

import (
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
}

const agentCols = `a.id, a.hostname, a.display_name, a.os, a.platform, a.arch, a.version, a.group_id, COALESCE(g.name,''),
	a.tags, a.custom_fields, a.notes, a.last_ip, a.last_seen, a.online, a.monitored_services, a.maintenance_until, a.enrolled_at,
	a.pending_reboot, a.last_metrics,
	(SELECT COUNT(*) FROM alerts al WHERE al.agent_id = a.id AND al.status != 'resolved'),
	(SELECT COUNT(*) FROM patches p WHERE p.agent_id = a.id AND p.status IN ('available','approved'))`

func scanAgent(rows interface{ Scan(...any) error }, withInventory bool) (*Agent, error) {
	var a Agent
	var tags, cf, ms, lm, inv string
	var gid sql.NullInt64
	dest := []any{&a.ID, &a.Hostname, &a.DisplayName, &a.OS, &a.Platform, &a.Arch, &a.Version, &gid, &a.GroupName,
		&tags, &cf, &a.Notes, &a.LastIP, &a.LastSeen, &a.Online, &ms, &a.MaintenanceUntil, &a.EnrolledAt,
		&a.PendingReboot, &lm, &a.OpenAlerts, &a.PatchesAvailable}
	if withInventory {
		dest = append(dest, &inv)
	}
	if err := rows.Scan(dest...); err != nil {
		return nil, err
	}
	if gid.Valid {
		a.GroupID = &gid.Int64
	}
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
	rows, err := d.Query(`SELECT ` + agentCols + ` FROM agents a LEFT JOIN groups g ON g.id = a.group_id ORDER BY a.online DESC, a.hostname`)
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
	row := d.QueryRow(`SELECT `+agentCols+`, a.inventory FROM agents a LEFT JOIN groups g ON g.id = a.group_id WHERE a.id = ?`, id)
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

// checkEnrollToken reports whether a token could still enrol a device.
func (d *DB) checkEnrollToken(token string) error {
	var usesLeft int
	var expires int64
	if err := d.QueryRow(`SELECT uses_left, expires_at FROM enroll_tokens WHERE token = ?`, token).Scan(&usesLeft, &expires); err != nil {
		return errors.New("unknown token")
	}
	if expires < now() {
		return errors.New("token expired")
	}
	if usesLeft == 0 {
		return errors.New("token exhausted")
	}
	return nil
}

// enrollAgent consumes an enrolment token and creates the agent record.
func (d *DB) enrollAgent(token string, hello protocol.Hello, ip string) (id, key string, err error) {
	var (
		tid      int64
		usesLeft int
		expires  int64
		gid      sql.NullInt64
	)
	err = d.QueryRow(`SELECT id, uses_left, expires_at, group_id FROM enroll_tokens WHERE token = ?`, token).Scan(&tid, &usesLeft, &expires, &gid)
	if err != nil {
		return "", "", errors.New("unknown token")
	}
	if expires < now() {
		return "", "", errors.New("token expired")
	}
	if usesLeft == 0 {
		return "", "", errors.New("token exhausted")
	}
	// A re-enrolment from the same hostname+os replaces the old record's key
	// instead of creating a duplicate device (reinstalls are common).
	var existing string
	d.QueryRow(`SELECT id FROM agents WHERE hostname = ? AND os = ? AND online = 0`, hello.Hostname, hello.OS).Scan(&existing)

	key = randomToken(32)
	if existing != "" {
		id = existing
		if _, err = d.Exec(`UPDATE agents SET key_hash = ?, version = ?, platform = ?, arch = ?, last_ip = ? WHERE id = ?`,
			hashKey(key), hello.Version, hello.Platform, hello.Arch, ip, id); err != nil {
			return "", "", err
		}
	} else {
		id = randomHex(8)
		_, err = d.Exec(`INSERT INTO agents(id, key_hash, hostname, os, platform, arch, version, group_id, last_ip, enrolled_at, last_seen)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, hashKey(key), hello.Hostname, hello.OS, hello.Platform, hello.Arch, hello.Version, gid, ip, now(), now())
		if err != nil {
			return "", "", err
		}
	}
	if usesLeft > 0 {
		d.Exec(`UPDATE enroll_tokens SET uses_left = uses_left - 1 WHERE id = ?`, tid)
	}
	return id, key, nil
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

func (d *DB) MetricsRange(id string, from, to int64, maxPoints int) ([]MetricRow, error) {
	if maxPoints <= 0 {
		maxPoints = 600
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
	rows, err := d.Query(`SELECT (ts / ?) * ?, AVG(cpu), AVG(mem_used), MAX(mem_total), MAX(disks), AVG(net_rx), AVG(net_tx), MAX(uptime), AVG(load1), MAX(procs)
		FROM metrics WHERE agent_id = ? AND ts BETWEEN ? AND ? GROUP BY 1 ORDER BY 1`, bucket, bucket, id, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MetricRow{}
	for rows.Next() {
		var r MetricRow
		var disks string
		var mem, rx, tx float64
		if err := rows.Scan(&r.TS, &r.CPU, &mem, &r.MemTotal, &disks, &rx, &tx, &r.Uptime, &r.Load1, &r.Procs); err != nil {
			return nil, err
		}
		r.MemUsed, r.NetRx, r.NetTx = uint64(mem), uint64(rx), uint64(tx)
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
	MonitoredServices []string          `json:"monitored_services"`
	MaintenanceUntil  *int64            `json:"maintenance_until"`
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
	All    bool     `json:"all"`
	Agents []string `json:"agents,omitempty"`
	Groups []int64  `json:"groups,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	OS     string   `json:"os,omitempty"`
}

// Matches reports whether a device is selected by the target set.
func (t Targets) Matches(a *Agent) bool {
	if t.OS != "" && a.OS != t.OS {
		return false
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

// ---- enrolment tokens ----

type EnrollToken struct {
	ID        int64  `json:"id"`
	Token     string `json:"token"`
	Name      string `json:"name"`
	GroupID   *int64 `json:"group_id"`
	UsesLeft  int    `json:"uses_left"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
}

func (d *DB) ListEnrollTokens() ([]EnrollToken, error) {
	rows, err := d.Query(`SELECT id, token, name, group_id, uses_left, expires_at, created_by, created_at FROM enroll_tokens WHERE expires_at > ? AND uses_left != 0 ORDER BY created_at DESC`, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnrollToken{}
	for rows.Next() {
		var t EnrollToken
		var gid sql.NullInt64
		if err := rows.Scan(&t.ID, &t.Token, &t.Name, &gid, &t.UsesLeft, &t.ExpiresAt, &t.CreatedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		if gid.Valid {
			t.GroupID = &gid.Int64
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
