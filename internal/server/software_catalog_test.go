package server

import (
	"net/http"
	"testing"
	"time"
)

func TestSoftwareCatalogCRUD(t *testing.T) {
	s, _, b := newTestServer(t)

	// 1. List pre-seeded catalog
	items, err := s.db.ListSoftwareCatalog("")
	if err != nil {
		t.Fatalf("ListSoftwareCatalog: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected pre-seeded catalog items, got 0")
	}

	// 2. Filter by OS
	winItems, err := s.db.ListSoftwareCatalog("windows")
	if err != nil {
		t.Fatalf("ListSoftwareCatalog(windows): %v", err)
	}
	for _, it := range winItems {
		if it.OS != "windows" && it.OS != "all" {
			t.Errorf("unexpected OS %s in windows filter", it.OS)
		}
	}

	// 3. Create custom catalog item via API
	newItem := map[string]any{
		"id":          "sw_custom_test",
		"name":        "Test Tool",
		"description": "A custom test utility",
		"publisher":   "Acme Corp",
		"version":     "1.0.0",
		"category":    "Utilities",
		"install_cmd": "echo 'installing'",
		"os":          "all",
	}
	var created SoftwareCatalogItem
	b.mustJSON("POST", "/api/software-catalog", newItem, &created)
	if created.Name != "Test Tool" {
		t.Fatalf("unexpected created name: %s", created.Name)
	}

	// 4. Retrieve item via API
	var got SoftwareCatalogItem
	b.mustJSON("GET", "/api/software-catalog/sw_custom_test", nil, &got)
	if got.Name != "Test Tool" || got.Publisher != "Acme Corp" {
		t.Errorf("mismatch in retrieved item: %+v", got)
	}

	// 5. Delete item via API
	var delRes map[string]any
	b.mustJSON("DELETE", "/api/software-catalog/sw_custom_test", nil, &delRes)
	if delRes["ok"] != true {
		t.Fatalf("delete returned %+v", delRes)
	}

	_, err = s.db.GetSoftwareCatalogItem("sw_custom_test")
	if err == nil {
		t.Fatalf("expected item to be deleted from database")
	}
}

func TestSoftwareInstallHandler(t *testing.T) {
	s, ts, b := newTestServer(t)

	// 1. Connect a real agent over WebSocket
	tok := enrollToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "online_box_sw", "windows")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })

	// 2. Request installation of pre-seeded Chrome on the online agent
	var resp map[string]any
	b.mustJSON("POST", "/api/agents/"+ag.id+"/software/install", map[string]string{
		"catalog_id": "sw_chrome",
	}, &resp)

	if resp["status"] != "started" || resp["run_id"] == "" {
		t.Errorf("invalid response payload: %+v", resp)
	}

	// 3. Disconnect agent, attempt installation -> expect 409
	ag.ws.Close()
	// Allow hub a moment to process close
	time.Sleep(50 * time.Millisecond)
	status, _ := b.do("POST", "/api/agents/"+ag.id+"/software/install", map[string]string{
		"catalog_id": "sw_chrome",
	})
	if status != 409 {
		t.Fatalf("expected 409 when agent offline, got %d", status)
	}
}
