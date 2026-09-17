package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// insertPatch is a patch row for a device that does not have to exist as an
// agent: the FK is on agents(id), so the caller inserts that first.
func insertPatch(t *testing.T, s *Server, agentID, patchID, source, severity, status string) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO patches(agent_id, patch_id, title, severity, source, status, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?)`,
		agentID, patchID, "update "+patchID, severity, source, status, now(), now()); err != nil {
		t.Fatal(err)
	}
}

func testAgentRow(t *testing.T, s *Server, id string) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at) VALUES(?,'h',?,'windows',?)`, id, id, now()); err != nil {
		t.Fatal(err)
	}
}

// ---- WIN-13: the status endpoint and the keys the API itself emits ----

func TestPatchStatusAcceptsBothKeySpellingsAndRejectsUnmatched(t *testing.T) {
	s, _, b := newTestServer(t)
	testAgentRow(t, s, "dev1")
	insertPatch(t, s, "dev1", "winget:GitHub.cli", "winget", "", "available")

	// the shape a client gets back from GET /api/patches used to be a silent
	// no-op that still answered 200 and still wrote an audit record
	var out struct {
		OK      bool  `json:"ok"`
		Changed int64 `json:"changed"`
	}
	b.mustJSON("POST", "/api/patches/status", map[string]any{
		"items":  []map[string]string{{"agent_id": "dev1", "patch_id": "winget:GitHub.cli"}},
		"status": "ignored",
	}, &out)
	if !out.OK || out.Changed != 1 {
		t.Fatalf("snake_case items changed nothing: %+v", out)
	}
	ps, _ := s.db.ListPatches("dev1", "ignored", 10)
	if len(ps) != 1 {
		t.Fatalf("the row was not ignored: %+v", ps)
	}

	// the console's spelling keeps working
	b.mustJSON("POST", "/api/patches/status", map[string]any{
		"items":  []map[string]string{{"AgentID": "dev1", "PatchID": "winget:GitHub.cli"}},
		"status": "approved",
	}, &out)
	if out.Changed != 1 {
		t.Fatalf("PascalCase items changed nothing: %+v", out)
	}

	// an item that matches no patch is an error, not a success with an audit
	// record claiming the change happened
	if st, body := b.do("POST", "/api/patches/status", map[string]any{
		"items":  []map[string]string{{"agent_id": "dev1", "patch_id": "nope"}},
		"status": "ignored",
	}); st != 404 {
		t.Fatalf("unmatched item: %d %s", st, body)
	}
	if st, _ := b.do("POST", "/api/patches/status", map[string]any{"items": []any{}, "status": "ignored"}); st != 400 {
		t.Fatalf("empty items should be 400, got %d", st)
	}

	var audit []struct {
		Action string `json:"action"`
	}
	b.mustJSON("GET", "/api/audit?limit=200", nil, &audit)
	n := 0
	for _, a := range audit {
		if strings.HasPrefix(a.Action, "patch.") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("audit recorded %d patch status changes, want the 2 that changed something", n)
	}
}

// ---- WIN-14: severity order ----

func TestListPatchesOrdersSeverityWorstFirst(t *testing.T) {
	s, _, _ := newTestServer(t)
	testAgentRow(t, s, "dev1")
	// Critical/Important/Moderate/Low are Windows Update's ratings;
	// "security" is the only severity apt/dnf/zypper ever set.
	for _, sev := range []string{"Unspecified", "Low", "Critical", "", "Moderate", "Important", "security"} {
		insertPatch(t, s, "dev1", "p-"+sev, "wua", sev, "available")
	}
	ps, err := s.db.ListPatches("dev1", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range ps {
		got = append(got, p.Severity)
	}
	// "security" ranks with Important, and the tie breaks on title
	// ("update p-Important" < "update p-security").
	want := []string{"Critical", "Important", "security", "Moderate", "Low"}
	for i, w := range want {
		if i >= len(got) || got[i] != w {
			t.Fatalf("severity order = %v, want it to start %v (a LIMIT must truncate the least important rows, not the Critical ones)", got, want)
		}
	}
}

// A Linux device reports "security" or nothing at all, so that one value is
// the whole ordering: if it lands in the same bucket as the unrated rows the
// 2000-row LIMIT in handleListPatches/handleAgentPatches cuts security
// updates as readily as anything else.
func TestListPatchesOrdersLinuxSecurityFirst(t *testing.T) {
	s, _, _ := newTestServer(t)
	testAgentRow(t, s, "linux1")
	// interleaved, and named so that a plain title sort would lead with an
	// unrated row
	for _, r := range []struct{ id, sev string }{
		{"pkg-a", ""}, {"pkg-b", "security"}, {"pkg-c", ""}, {"pkg-d", "security"},
	} {
		insertPatch(t, s, "linux1", r.id, "apt", r.sev, "available")
	}
	ps, err := s.db.ListPatches("linux1", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range ps {
		got = append(got, p.Severity)
	}
	want := []string{"security", "security", "", ""}
	for i, w := range want {
		if i >= len(got) || got[i] != w {
			t.Fatalf("linux severity order = %v, want %v (security updates must not be truncated by the LIMIT)", got, want)
		}
	}
}

// ---- WIN-15 / WIN-17: what a scan stores and hands back ----

func TestPatchScanStoresCategoriesDownloadedAndDescription(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrollToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "winbox", "windows")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })
	go func() {
		for {
			var env protocol.Envelope
			if err := ag.ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqUpdatesScan:
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.UpdatesScanResult{
					Updates: []protocol.Update{
						{ID: "916031e1-9d13-48e9-a262-c8a0db93fbac", Title: "2026-09 Security Update (KB5129195)", KB: "KB5129195",
							Categories: []string{"Security Updates"}, SizeBytes: 96888104301, Downloaded: true,
							Description: "A security update.", RebootReq: true, Source: "wua"},
						// no categories at all: the column is NOT NULL
						// DEFAULT '[]' and the published type promises an array
						{ID: "winget:Notepad++.Notepad++", Title: "Notepad++", Version: "8.9.8", Source: "winget"},
					},
				})})
			}
		}
	}()

	var out struct {
		Patches []json.RawMessage `json:"patches"`
	}
	b.mustJSON("POST", "/api/agents/"+ag.id+"/patches/scan", nil, &out)
	if len(out.Patches) != 2 {
		t.Fatalf("scan stored %d patches", len(out.Patches))
	}
	for _, raw := range out.Patches {
		if strings.Contains(string(raw), `"categories":null`) {
			t.Errorf("categories must always be an array: %s", raw)
		}
	}
	ps, _ := s.db.ListPatches(ag.id, "", 10)
	for _, p := range ps {
		if p.Categories == nil {
			t.Errorf("%s: categories is nil", p.PatchID)
		}
		if p.PatchID == "916031e1-9d13-48e9-a262-c8a0db93fbac" {
			if !p.Downloaded || p.Description == "" {
				t.Errorf("downloaded/description were dropped on the way in: %+v", p)
			}
		}
	}

	// a row written before the categories fix holds the literal "null"; the
	// read path still has to produce an array
	s.db.Exec(`UPDATE patches SET categories='null' WHERE agent_id=?`, ag.id)
	ps, _ = s.db.ListPatches(ag.id, "", 10)
	for _, p := range ps {
		if p.Categories == nil {
			t.Errorf("%s: a stored \"null\" must read back as []", p.PatchID)
		}
	}

	// An update the agent offers again was not installed after all (a scan
	// that could not enumerate its source can decide that wrongly), so the
	// row must not keep an installed_at that contradicts its status.
	s.db.Exec(`UPDATE patches SET status='installed', installed_at=42 WHERE agent_id=? AND patch_id=?`, ag.id, "winget:Notepad++.Notepad++")
	b.mustJSON("POST", "/api/agents/"+ag.id+"/patches/scan", nil, &out)
	ps, _ = s.db.ListPatches(ag.id, "", 10)
	for _, p := range ps {
		if p.PatchID == "winget:Notepad++.Notepad++" && (p.Status != "available" || p.InstalledAt != 0) {
			t.Errorf("a re-offered update kept a stale install record: %+v", p)
		}
	}
}

// ---- WIN-08: one winget row must not decide the batch ----

func TestPatchInstallLeavesWingetRowsOutOfTheBatch(t *testing.T) {
	s, ts, b := newTestServer(t)
	tok := enrollToken(t, s)
	ag := dialAgentAs(t, ts, http.Header{"X-Enroll-Token": []string{tok}}, "winbox2", "windows")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(ag.id) })
	insertPatch(t, s, ag.id, "916031e1-9d13-48e9-a262-c8a0db93fbac", "wua", "Critical", "available")
	for _, id := range []string{"winget:Notepad++.Notepad++", "winget:GitHub.cli"} {
		insertPatch(t, s, ag.id, id, "winget", "", "available")
	}

	sent := make(chan []string, 1)
	go func() {
		for {
			var env protocol.Envelope
			if err := ag.ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqUpdatesInstall:
				var in protocol.UpdatesInstall
				json.Unmarshal(env.D, &in)
				select {
				case sent <- in.IDs:
				default:
				}
				ag.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.UpdatesInstallResult{
					Installed: in.IDs,
				})})
			}
		}
	}()

	if st, body := b.do("POST", "/api/agents/"+ag.id+"/patches/install", map[string]any{"all": true}); st != 202 {
		t.Fatalf("install all: %d %s", st, body)
	}
	ids := <-sent
	if len(ids) != 1 || ids[0] != "916031e1-9d13-48e9-a262-c8a0db93fbac" {
		t.Fatalf("the batch sent to the agent was %v, want only the WUA update: the agent cannot install winget rows, and one of them used to fail the whole batch", ids)
	}
	// the winget rows are left where they were, not approved into a batch
	// that can only fail
	ps, _ := s.db.ListPatches(ag.id, "", 10)
	for _, p := range ps {
		if p.Source == "winget" && p.Status != "available" {
			t.Errorf("%s: status %q, want it left available", p.PatchID, p.Status)
		}
	}
}

// ---- WIN-17: the migration that added downloaded/description ----

func TestPatchesMigrationReplaysCleanly(t *testing.T) {
	path := t.TempDir() + "/rmm.db"
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO agents(id, key_hash, hostname, os, enrolled_at) VALUES('a1','h','box','windows',?)`, now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO patches(agent_id, patch_id, title, downloaded, description, first_seen, last_seen) VALUES('a1','p1','t',1,'d',?,?)`, now(), now()); err != nil {
		t.Fatal(err)
	}
	// a database whose user_version was rewound (a downgrade, a repair) has
	// to be able to replay the migration onto its own result
	if _, err := db.Exec(`PRAGMA user_version = 4`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err = openDB(path)
	if err != nil {
		t.Fatalf("replaying the patches migration failed: %v", err)
	}
	defer db.Close()
	var title string
	var downloaded int
	if err := db.QueryRow(`SELECT title, downloaded FROM patches WHERE agent_id='a1' AND patch_id='p1'`).Scan(&title, &downloaded); err != nil {
		t.Fatalf("the patch row did not survive the rebuild: %v", err)
	}
	if title != "t" {
		t.Fatalf("title = %q", title)
	}
	var idx int
	db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_patches_agent_status'`).Scan(&idx)
	if idx != 1 {
		t.Error("the rebuild dropped idx_patches_agent_status")
	}
}
