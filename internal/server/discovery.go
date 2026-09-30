package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/netscan"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

type DiscoveredDevice struct {
	ID             string `json:"id"`
	IP             string `json:"ip"`
	MAC            string `json:"mac"`
	Hostname       string `json:"hostname"`
	Vendor         string `json:"vendor"`
	OS             string `json:"os"`
	DeviceType     string `json:"device_type"`
	OpenPorts      []int  `json:"open_ports"`
	SNMPEnabled    bool   `json:"snmp_enabled"`
	SNMPSysName    string `json:"snmp_sys_name"`
	SNMPSysDescr   string `json:"snmp_sys_descr"`
	SNMPSysUpTime  int64  `json:"snmp_sys_uptime"`
	DiscoveredBy   string `json:"discovered_by"`
	OrgID          string `json:"org_id"`
	SiteID         string `json:"site_id"`
	Status         string `json:"status"` // discovered, managed, ignored
	FirstSeen      int64  `json:"first_seen"`
	LastSeen       int64  `json:"last_seen"`
}

type NetworkScan struct {
	ID           int64  `json:"id"`
	Subnet       string `json:"subnet"`
	AgentID      string `json:"agent_id"`
	Status       string `json:"status"` // pending, running, completed, failed
	DevicesFound int    `json:"devices_found"`
	StartedAt    int64  `json:"started_at"`
	CompletedAt  int64  `json:"completed_at"`
	Error        string `json:"error"`
}

// ---- DB Operations ----

func (d *DB) ListDiscoveredDevices(orgID, siteID, statusFilter string) ([]DiscoveredDevice, error) {
	q := `SELECT id, ip, mac, hostname, vendor, os, device_type, open_ports, snmp_enabled, snmp_sys_name, snmp_sys_descr, snmp_sys_uptime, discovered_by, org_id, site_id, status, first_seen, last_seen FROM discovered_devices WHERE 1=1`
	var args []any
	if orgID != "" {
		q += ` AND org_id = ?`
		args = append(args, orgID)
	}
	if siteID != "" {
		q += ` AND site_id = ?`
		args = append(args, siteID)
	}
	if statusFilter != "" {
		q += ` AND status = ?`
		args = append(args, statusFilter)
	}
	q += ` ORDER BY last_seen DESC, ip ASC`

	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []DiscoveredDevice{}
	for rows.Next() {
		var dd DiscoveredDevice
		var openPortsJSON string
		var snmpEnabledInt int
		if err := rows.Scan(&dd.ID, &dd.IP, &dd.MAC, &dd.Hostname, &dd.Vendor, &dd.OS, &dd.DeviceType, &openPortsJSON, &snmpEnabledInt, &dd.SNMPSysName, &dd.SNMPSysDescr, &dd.SNMPSysUpTime, &dd.DiscoveredBy, &dd.OrgID, &dd.SiteID, &dd.Status, &dd.FirstSeen, &dd.LastSeen); err != nil {
			return nil, err
		}
		dd.SNMPEnabled = snmpEnabledInt != 0
		_ = json.Unmarshal([]byte(openPortsJSON), &dd.OpenPorts)
		if dd.OpenPorts == nil {
			dd.OpenPorts = []int{}
		}
		out = append(out, dd)
	}
	return out, rows.Err()
}

func (d *DB) GetDiscoveredDevice(id string) (*DiscoveredDevice, error) {
	var dd DiscoveredDevice
	var openPortsJSON string
	var snmpEnabledInt int
	err := d.QueryRow(`SELECT id, ip, mac, hostname, vendor, os, device_type, open_ports, snmp_enabled, snmp_sys_name, snmp_sys_descr, snmp_sys_uptime, discovered_by, org_id, site_id, status, first_seen, last_seen FROM discovered_devices WHERE id = ?`, id).
		Scan(&dd.ID, &dd.IP, &dd.MAC, &dd.Hostname, &dd.Vendor, &dd.OS, &dd.DeviceType, &openPortsJSON, &snmpEnabledInt, &dd.SNMPSysName, &dd.SNMPSysDescr, &dd.SNMPSysUpTime, &dd.DiscoveredBy, &dd.OrgID, &dd.SiteID, &dd.Status, &dd.FirstSeen, &dd.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	dd.SNMPEnabled = snmpEnabledInt != 0
	_ = json.Unmarshal([]byte(openPortsJSON), &dd.OpenPorts)
	if dd.OpenPorts == nil {
		dd.OpenPorts = []int{}
	}
	return &dd, nil
}

func (d *DB) SaveDiscoveredDevice(dd *DiscoveredDevice) error {
	now := time.Now().Unix()
	if dd.FirstSeen == 0 {
		dd.FirstSeen = now
	}
	dd.LastSeen = now
	if dd.OrgID == "" {
		dd.OrgID = "org_default"
	}
	if dd.SiteID == "" {
		dd.SiteID = "site_default"
	}
	if dd.ID == "" {
		dd.ID = fmt.Sprintf("disc_%s_%s_%s", dd.OrgID, dd.SiteID, strings.ReplaceAll(dd.IP, ".", "_"))
	}
	if dd.Status == "" {
		dd.Status = "discovered"
	}
	portsBytes, _ := json.Marshal(dd.OpenPorts)
	snmpInt := 0
	if dd.SNMPEnabled {
		snmpInt = 1
	}

	_, err := d.Exec(`INSERT INTO discovered_devices (id, ip, mac, hostname, vendor, os, device_type, open_ports, snmp_enabled, snmp_sys_name, snmp_sys_descr, snmp_sys_uptime, discovered_by, org_id, site_id, status, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE discovered_devices.mac END,
			hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE discovered_devices.hostname END,
			vendor = CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE discovered_devices.vendor END,
			os = CASE WHEN excluded.os != '' THEN excluded.os ELSE discovered_devices.os END,
			device_type = CASE WHEN excluded.device_type != 'unknown' THEN excluded.device_type ELSE discovered_devices.device_type END,
			open_ports = excluded.open_ports,
			snmp_enabled = excluded.snmp_enabled,
			snmp_sys_name = excluded.snmp_sys_name,
			snmp_sys_descr = excluded.snmp_sys_descr,
			snmp_sys_uptime = excluded.snmp_sys_uptime,
			last_seen = excluded.last_seen`,
		dd.ID, dd.IP, dd.MAC, dd.Hostname, dd.Vendor, dd.OS, dd.DeviceType, string(portsBytes), snmpInt, dd.SNMPSysName, dd.SNMPSysDescr, dd.SNMPSysUpTime, dd.DiscoveredBy, dd.OrgID, dd.SiteID, dd.Status, dd.FirstSeen, dd.LastSeen)
	return err
}

func (d *DB) DeleteDiscoveredDevice(id string) error {
	_, err := d.Exec(`DELETE FROM discovered_devices WHERE id = ?`, id)
	return err
}

func (d *DB) ListNetworkScans(limit int) ([]NetworkScan, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.Query(`SELECT id, subnet, agent_id, status, devices_found, started_at, completed_at, error FROM network_scans ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []NetworkScan{}
	for rows.Next() {
		var s NetworkScan
		if err := rows.Scan(&s.ID, &s.Subnet, &s.AgentID, &s.Status, &s.DevicesFound, &s.StartedAt, &s.CompletedAt, &s.Error); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) CreateNetworkScan(subnet, agentID string) (*NetworkScan, error) {
	now := time.Now().Unix()
	res, err := d.Exec(`INSERT INTO network_scans (subnet, agent_id, status, devices_found, started_at, completed_at, error) VALUES (?, ?, 'running', 0, ?, 0, '')`, subnet, agentID, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &NetworkScan{
		ID:        id,
		Subnet:    subnet,
		AgentID:   agentID,
		Status:    "running",
		StartedAt: now,
	}, nil
}

func (d *DB) UpdateNetworkScan(scan *NetworkScan) error {
	_, err := d.Exec(`UPDATE network_scans SET status = ?, devices_found = ?, completed_at = ?, error = ? WHERE id = ?`, scan.Status, scan.DevicesFound, scan.CompletedAt, scan.Error, scan.ID)
	return err
}

// ---- Scanning Engine ----

func generateSubnetIPs(cidr string) ([]string, error) {
	return netscan.GenerateSubnetIPs(cidr)
}

func probeHost(ip string) *DiscoveredDevice {
	h := netscan.ProbeHost(ip)
	if h == nil {
		return nil
	}
	return &DiscoveredDevice{
		IP:            h.IP,
		MAC:           h.MAC,
		Hostname:      h.Hostname,
		Vendor:        h.Vendor,
		OS:            h.OS,
		DeviceType:    h.DeviceType,
		OpenPorts:     h.OpenPorts,
		SNMPEnabled:   h.SNMPEnabled,
		SNMPSysName:   h.SNMPSysName,
		SNMPSysDescr:  h.SNMPSysDescr,
		SNMPSysUpTime: h.SNMPSysUpTime,
	}
}

func (s *Server) runSubnetScan(scan *NetworkScan) {
	hosts, err := netscan.ScanSubnet(context.Background(), scan.Subnet, 32)
	if err != nil {
		scan.Status = "failed"
		scan.Error = err.Error()
		scan.CompletedAt = time.Now().Unix()
		_ = s.db.UpdateNetworkScan(scan)
		return
	}

	foundCount := 0
	for _, h := range hosts {
		dd := &DiscoveredDevice{
			IP:            h.IP,
			MAC:           h.MAC,
			Hostname:      h.Hostname,
			Vendor:        h.Vendor,
			OS:            h.OS,
			DeviceType:    h.DeviceType,
			OpenPorts:     h.OpenPorts,
			SNMPEnabled:   h.SNMPEnabled,
			SNMPSysName:   h.SNMPSysName,
			SNMPSysDescr:  h.SNMPSysDescr,
			SNMPSysUpTime: h.SNMPSysUpTime,
			DiscoveredBy:  scan.AgentID,
			OrgID:         "org_default",
			SiteID:        "site_default",
			Status:        "discovered",
		}
		if err := s.db.SaveDiscoveredDevice(dd); err == nil {
			foundCount++
		}
	}

	scan.Status = "completed"
	scan.DevicesFound = foundCount
	scan.CompletedAt = time.Now().Unix()
	_ = s.db.UpdateNetworkScan(scan)
}

func (s *Server) runAgentSubnetScan(scan *NetworkScan, agentID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	a, err := s.db.GetAgent(agentID)
	if err != nil {
		scan.Status = "failed"
		scan.Error = "agent not found: " + err.Error()
		scan.CompletedAt = time.Now().Unix()
		_ = s.db.UpdateNetworkScan(scan)
		return
	}

	var resp protocol.NetworkScanResp
	err = s.hub.Request(ctx, agentID, protocol.ReqNetworkScan, protocol.NetworkScanReq{Subnet: scan.Subnet}, &resp)
	if err != nil {
		scan.Status = "failed"
		scan.Error = "probe agent scan failed: " + err.Error()
		scan.CompletedAt = time.Now().Unix()
		_ = s.db.UpdateNetworkScan(scan)
		return
	}

	foundCount := 0
	for _, h := range resp.Hosts {
		dd := &DiscoveredDevice{
			IP:            h.IP,
			MAC:           h.MAC,
			Hostname:      h.Hostname,
			Vendor:        h.Vendor,
			OS:            h.OS,
			DeviceType:    h.DeviceType,
			OpenPorts:     h.OpenPorts,
			SNMPEnabled:   h.SNMPEnabled,
			SNMPSysName:   h.SNMPSysName,
			SNMPSysDescr:  h.SNMPSysDescr,
			SNMPSysUpTime: h.SNMPSysUpTime,
			DiscoveredBy:  agentID,
			OrgID:         a.OrgID,
			SiteID:        a.SiteID,
			Status:        "discovered",
		}
		if err := s.db.SaveDiscoveredDevice(dd); err == nil {
			foundCount++
		}
	}

	scan.Status = "completed"
	scan.DevicesFound = foundCount
	scan.CompletedAt = time.Now().Unix()
	_ = s.db.UpdateNetworkScan(scan)

	// Record event on the probe agent
	evMsg := fmt.Sprintf("Network scan of %s completed (%d devices discovered)", scan.Subnet, foundCount)
	s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, agentID, time.Now().Unix(), "system", evMsg, jsonText(map[string]any{
		"scan_id": scan.ID,
		"subnet":  scan.Subnet,
		"found":   foundCount,
	}))
}

// ---- HTTP Handlers ----

func (s *Server) handleListDiscoveredDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	orgID := q.Get("org_id")
	siteID := q.Get("site_id")
	status := q.Get("status")

	devs, err := s.db.ListDiscoveredDevices(orgID, siteID, status)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	filtered := make([]DiscoveredDevice, 0, len(devs))
	for _, d := range devs {
		if s.canAccessAgent(me, d.OrgID) {
			filtered = append(filtered, d)
		}
	}
	writeJSON(w, 200, filtered)
}

func (s *Server) handleGetDiscoveredDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dev, err := s.db.GetDiscoveredDevice(id)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if !s.canAccessAgent(me, dev.OrgID) {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	writeJSON(w, 200, dev)
}

func (s *Server) handleUpdateDiscoveredDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dev, err := s.db.GetDiscoveredDevice(id)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if !s.canAccessAgent(me, dev.OrgID) {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}

	var update DiscoveredDevice
	if err := readJSON(r, &update); err != nil {
		fail(w, err)
		return
	}

	if update.Status != "" {
		dev.Status = update.Status
	}
	if update.DeviceType != "" {
		dev.DeviceType = update.DeviceType
	}
	if update.Hostname != "" {
		dev.Hostname = update.Hostname
	}
	if update.OrgID != "" {
		if update.OrgID != dev.OrgID && !s.canAccessAgent(me, update.OrgID) {
			writeErr(w, http.StatusForbidden, "cannot move device to unauthorized organization")
			return
		}
		dev.OrgID = update.OrgID
	}
	if update.SiteID != "" {
		dev.SiteID = update.SiteID
	}

	if err := s.db.SaveDiscoveredDevice(dev); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, dev)
}

func (s *Server) handleDeleteDiscoveredDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dev, err := s.db.GetDiscoveredDevice(id)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if !s.canAccessAgent(me, dev.OrgID) {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	if err := s.db.DeleteDiscoveredDevice(id); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handlePollDiscoveredDeviceSNMP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dev, err := s.db.GetDiscoveredDevice(id)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	if !s.canAccessAgent(me, dev.OrgID) {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}

	var sysName, sysDescr string
	var sysUpTime int64

	// If device was discovered by an agent and that agent is online, proxy through that agent
	if dev.DiscoveredBy != "" && s.hub.IsOnline(dev.DiscoveredBy) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var pollResp protocol.SNMPPollResp
		err := s.hub.Request(ctx, dev.DiscoveredBy, protocol.ReqSNMPPoll, protocol.SNMPPollReq{IP: dev.IP, Community: "public"}, &pollResp)
		if err != nil {
			writeErr(w, http.StatusBadGateway, fmt.Sprintf("Agent SNMP poll failed: %v", err))
			return
		}
		sysName = pollResp.SysName
		sysDescr = pollResp.SysDescr
		sysUpTime = pollResp.SysUpTime
	} else {
		// Server direct fallback
		res, err := netscan.QuerySNMP(dev.IP, "public", 1500*time.Millisecond)
		if err != nil {
			writeErr(w, http.StatusBadGateway, fmt.Sprintf("SNMP poll failed: %v", err))
			return
		}
		sysName = res.SysName
		sysDescr = res.SysDescr
		sysUpTime = res.SysUpTime
	}

	dev.SNMPEnabled = true
	dev.SNMPSysDescr = sysDescr
	dev.SNMPSysName = sysName
	dev.SNMPSysUpTime = sysUpTime
	if dev.Hostname == "" && sysName != "" {
		dev.Hostname = sysName
	}
	_ = s.db.SaveDiscoveredDevice(dev)

	writeJSON(w, 200, dev)
}

func (s *Server) handleListNetworkScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.db.ListNetworkScans(50)
	if err != nil {
		fail(w, err)
		return
	}
	me := userFrom(r.Context())
	filtered := make([]NetworkScan, 0, len(scans))
	for _, sc := range scans {
		if sc.AgentID != "" {
			if a, err := s.db.GetAgent(sc.AgentID); err == nil && !s.canAccessAgent(me, a.OrgID) {
				continue
			}
		}
		filtered = append(filtered, sc)
	}
	writeJSON(w, 200, filtered)
}

func (s *Server) handleStartNetworkScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Subnet  string `json:"subnet"`
		AgentID string `json:"agent_id"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, err)
		return
	}

	if body.AgentID != "" {
		if _, ok := s.getScopedAgent(w, r, body.AgentID); !ok {
			return
		}
		if !s.hub.IsOnline(body.AgentID) {
			writeErr(w, http.StatusConflict, "probe agent is offline")
			return
		}
	} else {
		if !userFrom(r.Context()).IsAdmin() {
			writeErr(w, http.StatusForbidden, "server-side network scans require administrator privileges")
			return
		}
	}

	subnet := strings.TrimSpace(body.Subnet)
	if subnet == "" {
		// Default to local server subnet if omitted
		subnet = "192.168.1.0/24"
	}
	if _, err := generateSubnetIPs(subnet); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	scan, err := s.db.CreateNetworkScan(subnet, body.AgentID)
	if err != nil {
		fail(w, err)
		return
	}

	// Dispatch scan: to agent if specified, else local server
	if body.AgentID != "" {
		go s.runAgentSubnetScan(scan, body.AgentID)
	} else {
		go s.runSubnetScan(scan)
	}

	s.audit(r, "network.scan", subnet, map[string]any{
		"scan_id":  scan.ID,
		"subnet":   subnet,
		"agent_id": body.AgentID,
	})

	writeJSON(w, 202, scan)
}
