package server

import (
	"testing"
)

func TestDiscoveryCRUD(t *testing.T) {
	s, _, b := newTestServer(t)

	// 1. Save discovered device
	dev := &DiscoveredDevice{
		ID:          "disc_192_168_1_50",
		IP:          "192.168.1.50",
		Hostname:    "core-switch",
		DeviceType:  "switch",
		OpenPorts:   []int{80, 443, 161},
		SNMPEnabled: true,
		SNMPSysName: "core-switch-01",
		Status:      "discovered",
	}
	if err := s.db.SaveDiscoveredDevice(dev); err != nil {
		t.Fatalf("SaveDiscoveredDevice: %v", err)
	}

	// 2. Query via API
	var list []DiscoveredDevice
	b.mustJSON("GET", "/api/discovered-devices", nil, &list)
	if len(list) == 0 {
		t.Fatalf("expected at least 1 discovered device")
	}

	var got DiscoveredDevice
	b.mustJSON("GET", "/api/discovered-devices/disc_192_168_1_50", nil, &got)
	if got.Hostname != "core-switch" || got.DeviceType != "switch" {
		t.Errorf("mismatched device: %+v", got)
	}

	// 3. Update status to managed
	b.mustJSON("PUT", "/api/discovered-devices/disc_192_168_1_50", map[string]string{"status": "managed"}, &got)
	if got.Status != "managed" {
		t.Errorf("expected status 'managed', got %s", got.Status)
	}

	// 4. Delete device
	var delRes map[string]any
	b.mustJSON("DELETE", "/api/discovered-devices/disc_192_168_1_50", nil, &delRes)
	if delRes["ok"] != true {
		t.Fatalf("delete returned %+v", delRes)
	}
}

func TestNetworkScanAPI(t *testing.T) {
	_, _, b := newTestServer(t)

	var scan NetworkScan
	b.mustJSON("POST", "/api/network-scans", map[string]string{
		"subnet": "127.0.0.1/32",
	}, &scan)

	if scan.Subnet != "127.0.0.1/32" || scan.Status != "running" {
		t.Errorf("unexpected scan response: %+v", scan)
	}

	var scans []NetworkScan
	b.mustJSON("GET", "/api/network-scans", nil, &scans)
	if len(scans) == 0 {
		t.Fatalf("expected at least 1 scan record")
	}
}

func TestAgentScopedDiscovery(t *testing.T) {
	s, _, b := newTestServer(t)

	// Create test org and site
	if _, err := s.db.Exec("INSERT INTO organizations(id, name, created_at) VALUES(?, ?, ?)", "org_acme", "Acme Corp", 1000); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := s.db.Exec("INSERT INTO sites(id, org_id, name, created_at) VALUES(?, ?, ?, ?)", "site_hq", "org_acme", "Headquarters", 1000); err != nil {
		t.Fatalf("insert site: %v", err)
	}

	// Create agent attached to this org and site
	if _, err := s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, display_name, os, platform, arch, version, enrolled_at, last_seen, last_ip, org_id, site_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"ag_probe_01", "hash123", "probe-host", "Acme Probe", "linux", "Linux", "amd64", "1.0.0", 1000, 2000, "10.0.0.2", "org_acme", "site_hq"); err != nil {
		t.Fatalf("insert agent: %v", err)
	}

	// Verify offline probe agent returns 409 Conflict
	status, _ := b.do("POST", "/api/network-scans", map[string]string{
		"subnet":   "10.0.0.0/24",
		"agent_id": "ag_probe_01",
	})
	if status != 409 {
		t.Fatalf("expected 409 Conflict for offline probe agent, got %d", status)
	}

	// Ingest discovered device from this agent
	dev := &DiscoveredDevice{
		IP:           "10.0.0.55",
		MAC:          "00:11:22:33:44:55",
		Hostname:     "acme-nas",
		DeviceType:   "server",
		DiscoveredBy: "ag_probe_01",
		OrgID:        "org_acme",
		SiteID:       "site_hq",
		Status:       "discovered",
	}
	if err := s.db.SaveDiscoveredDevice(dev); err != nil {
		t.Fatalf("SaveDiscoveredDevice: %v", err)
	}

	// Query filtered by org
	var list []DiscoveredDevice
	b.mustJSON("GET", "/api/discovered-devices?org_id=org_acme", nil, &list)
	if len(list) != 1 || list[0].Hostname != "acme-nas" {
		t.Fatalf("expected 1 discovered device for Acme org, got %v", list)
	}
	if list[0].SiteID != "site_hq" || list[0].DiscoveredBy != "ag_probe_01" {
		t.Fatalf("device did not inherit agent's site or probe identity: %+v", list[0])
	}
}
