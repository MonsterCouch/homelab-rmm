package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- helpers ----

// withoutDevDist keeps a developer's RMM_DEV_DIST settings from supplying an
// agent build the test did not stage: for any binary it cannot find in its own
// data directory the server falls back to that directory.
func withoutDevDist(t *testing.T) {
	t.Helper()
	t.Setenv("RMM_DEV_DIST_DIR", "")
	t.Setenv("RMM_DEV_DIST", "")
}

// stageAgentBinary puts a stand-in agent build where the server looks for one
// and returns the name it is served under and its SHA-256. The bytes name the
// build, so no two builds share a digest. The server caches a digest by path,
// size and modification time, so each build is written once per server.
func stageAgentBinary(t *testing.T, s *Server, fam, arch string) (name, sum string) {
	t.Helper()
	name = "rmm-agent-" + fam + "-" + arch
	if fam == "windows" {
		name += ".exe"
	}
	data := []byte("stand-in agent build for " + fam + "/" + arch + "\n")
	dir := s.cfg.path("agents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	return name, hex.EncodeToString(h[:])
}

// enroll connects a fake agent that reports osName in its hello, through a
// token for the given organization ("" is the default one).
func (f *signFixture) enroll(org, name, osName string) *rawAgent {
	f.t.Helper()
	req := map[string]any{"name": name, "uses": 1}
	if org != "" {
		req["org_id"] = org
	}
	var tok struct{ Token string }
	f.admin.mustJSON("POST", "/api/enroll", req, &tok)
	return dialAgentAs(f.t, f.ts, http.Header{"X-Enroll-Token": []string{tok.Token}}, name, osName)
}

// addAgentIn is addAgent for a device of another operating system or
// organization.
func (f *signFixture) addAgentIn(org, name, osName string) *sigAgent {
	f.t.Helper()
	ra := f.enroll(org, name, osName)
	a := &sigAgent{t: f.t, s: f.s, raw: ra, nonce: actionauth.NewMemoryNonceStore()}
	go a.loop()
	waitFor(f.t, "agent online", func() bool { return f.s.hub.IsOnline(ra.id) })
	return a
}

func (f *signFixture) addAgentOS(name, osName string) *sigAgent {
	f.t.Helper()
	return f.addAgentIn("", name, osName)
}

// addUpdateAgent connects a fake agent that only cares about agent.update: it
// answers with the error msg, or with success when msg is empty, or not at all
// when silent is set, as a device does that is still busy downloading. It
// returns the device's ID.
func (f *signFixture) addUpdateAgent(name, msg string, silent bool) string {
	f.t.Helper()
	ra := f.enroll("", name, "linux")
	go func() {
		for {
			var env protocol.Envelope
			if err := ra.ws.ReadJSON(&env); err != nil {
				return
			}
			if env.T == protocol.ReqAgentUpdate && !silent {
				ra.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, Err: msg})
			}
		}
	}()
	waitFor(f.t, "agent online", func() bool { return f.s.hub.IsOnline(ra.id) })
	return ra.id
}

// setArch records the architecture a device announced, as its hello would
// have. Every fake agent says amd64, and the column is what the fleet listing
// reads, because it does not load inventories.
func (f *signFixture) setArch(a *sigAgent, arch string) {
	f.t.Helper()
	// markOnline stamps the hello's architecture over the column once the
	// connection is registered, so the value is only changed after that.
	waitFor(f.t, a.ID()+" recorded as online", func() bool {
		ag, err := f.s.db.GetAgent(a.ID())
		return err == nil && ag.Online
	})
	if _, err := f.s.db.Exec(`UPDATE agents SET arch = ? WHERE id = ?`, arch, a.ID()); err != nil {
		f.t.Fatal(err)
	}
}

// disconnect drops a device's socket and waits until the server sees it gone.
func (f *signFixture) disconnect(a *sigAgent) {
	f.t.Helper()
	a.raw.ws.Close()
	waitFor(f.t, a.ID()+" to be seen as offline", func() bool { return !f.s.hub.IsOnline(a.ID()) })
}

func sortedIDs(agents ...*sigAgent) []string {
	ids := make([]string, 0, len(agents))
	for _, a := range agents {
		ids = append(ids, a.ID())
	}
	sort.Strings(ids)
	return ids
}

// The replies are decoded into types of the tests' own so the JSON names the
// console reads are spelled out here, not borrowed from the handlers.
type fleetGroup struct {
	Org      string   `json:"org"`
	OrgName  string   `json:"org_name"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	Version  string   `json:"version"`
	SHA256   string   `json:"sha256"`
	AgentIDs []string `json:"agent_ids"`
}

type fleetAll struct {
	OK             bool         `json:"ok"`
	DispatchedTo   int          `json:"dispatched_to"`
	SignedGroups   []fleetGroup `json:"signed_groups"`
	SkippedNoBuild int          `json:"skipped_no_build"`
	Message        string       `json:"message"`
}

type fleetFailure struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Error string `json:"error"`
}

type fleetBatch struct {
	OK           bool           `json:"ok"`
	DispatchedTo int            `json:"dispatched_to"`
	Signed       bool           `json:"signed"`
	Accepted     int            `json:"accepted"`
	Installing   int            `json:"installing"`
	Offline      int            `json:"offline"`
	Failed       []fleetFailure `json:"failed"`
	Message      string         `json:"message"`
}

// fleetAuditRow is a fleet.update entry of the audit log.
type fleetAuditRow struct {
	User    string
	IP      string
	Target  string
	Details struct {
		Targets    int    `json:"targets"`
		OS         string `json:"os"`
		Arch       string `json:"arch"`
		Version    string `json:"version"`
		SHA256     string `json:"sha256"`
		Accepted   int    `json:"accepted"`
		Installing int    `json:"installing"`
		Offline    int    `json:"offline"`
		Failed     int    `json:"failed"`
		// Failures is the devices that did not take the update, capped; Failed
		// stays the plain count of all of them.
		Failures []fleetFailure `json:"failures"`
	}
}

// fleetAuditRows waits for the fleet.update entries to show up and returns
// them oldest first.
func fleetAuditRows(t *testing.T, s *Server) []fleetAuditRow {
	t.Helper()
	var rows []fleetAuditRow
	waitFor(t, "a fleet.update audit entry", func() bool {
		rows = nil
		rs, err := s.db.Query(`SELECT user, ip, target, details FROM audit WHERE action = 'fleet.update' ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Close()
		for rs.Next() {
			var r fleetAuditRow
			var details string
			if err := rs.Scan(&r.User, &r.IP, &r.Target, &details); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(details), &r.Details); err != nil {
				t.Fatalf("audit details %q: %v", details, err)
			}
			rows = append(rows, r)
		}
		return len(rows) > 0
	})
	return rows
}

// updateAll posts the fleet-wide update as the administrator.
func updateAll(t *testing.T, f *signFixture) (fleetAll, []byte) {
	t.Helper()
	st, raw := f.admin.do("POST", "/api/agents/update-all", nil)
	if st != 200 {
		t.Fatalf("update-all = %d %s", st, raw)
	}
	var res fleetAll
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("update-all body %s: %v", raw, err)
	}
	return res, raw
}

// postBatch sends update-batch as the administrator for an organization that
// signs nothing, so the answer is the batch's own.
func postBatch(t *testing.T, f *signFixture, ids ...string) (fleetBatch, map[string]json.RawMessage, []byte) {
	t.Helper()
	st, raw := f.admin.do("POST", "/api/agents/update-batch", map[string]any{"agent_ids": ids})
	if st != 200 {
		t.Fatalf("update-batch = %d %s", st, raw)
	}
	var res fleetBatch
	var shape map[string]json.RawMessage
	json.Unmarshal(raw, &res)
	json.Unmarshal(raw, &shape)
	return res, shape, raw
}

// updateURL is where a device is told to download the named build.
func (f *signFixture) updateURL(name string) string {
	return f.s.PublicURL() + "/api/agent-download/" + name
}

// ---- tests ----

// A fleet-wide update never sends an unsigned agent.update into an
// organization that signs its actions: in enforce mode the device would refuse
// it and raise an alert, in audit mode it would install it and raise one. So
// update-all leaves those devices alone and hands them back as one group per
// organization and agent build, carrying the digest of the binary the operator
// will be asked to sign for, and the console takes each group to update-batch.
func TestFleetUpdateSignedOrgIsGroupedNotDispatched(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	_, hash := stageAgentBinary(t, f.s, "linux", "amd64")
	a1, a2 := f.addAgent("box1"), f.addAgent("box2")
	f.disconnect(f.addAgent("gone")) // a group is the devices that are online now

	res, raw := updateAll(t, f)
	want := fleetGroup{Org: trustOrg, OrgName: "Default Organization", OS: "linux", Arch: "amd64", Version: Version, SHA256: hash, AgentIDs: sortedIDs(a1, a2)}
	if !res.OK || res.DispatchedTo != 0 || len(res.SignedGroups) != 1 || !reflect.DeepEqual(res.SignedGroups[0], want) {
		t.Fatalf("update-all = %s, want nothing dispatched and the one group %+v", raw, want)
	}
	if wantMsg := "Dispatched update command to 0 online agent(s); 2 device(s) in 1 organization(s) that sign actions need a signed update"; res.Message != wantMsg {
		t.Fatalf("message = %q, want %q", res.Message, wantMsg)
	}
	// The wire shape is exactly what the console reads: no field missing, none extra.
	var shape struct {
		Groups []map[string]json.RawMessage `json:"signed_groups"`
	}
	json.Unmarshal(raw, &shape)
	var keys []string
	for k := range shape.Groups[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !slices.Equal(keys, []string{"agent_ids", "arch", "org", "org_name", "os", "sha256", "version"}) {
		t.Fatalf("a group has the fields %v", keys)
	}
	var top map[string]json.RawMessage
	json.Unmarshal(raw, &top)
	keys = nil
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !slices.Equal(keys, []string{"dispatched_to", "message", "ok", "signed_groups", "skipped_no_build", "up_to_date"}) || res.SkippedNoBuild != 0 {
		t.Fatalf("the reply has the fields %v and skipped_no_build %d, want a count of 0 for a server that has every build", keys, res.SkippedNoBuild)
	}

	// Dispatch for an unsigned organization runs on goroutines, so give a wrong
	// send the time to arrive before looking for it.
	time.Sleep(200 * time.Millisecond)
	for _, ag := range []*sigAgent{a1, a2} {
		if n := len(ag.requests(protocol.ReqAgentUpdate)); n != 0 {
			t.Fatalf("%s was sent %d agent.update requests by the fleet update, want none", ag.ID(), n)
		}
	}
}

// What update-all hands back is exactly what update-batch signs. A manifest
// names one organization and binds one payload, and the payload differs per
// operating system and architecture, so the groups split on both: an arm64
// device (known from its hello, since the fleet listing loads no inventories)
// must not land in the amd64 group and be offered the wrong binary. A device
// whose build the server does not have is in no group, an organization that
// does not sign still gets its update at once, and for each group the manifest
// the batch builds carries the group's organization, devices, build and digest.
func TestFleetUpdateGroupsAreWhatTheBatchSigns(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	amdName, amd := stageAgentBinary(t, f.s, "linux", "amd64")
	armName, arm := stageAgentBinary(t, f.s, "linux", "arm64")
	// There is deliberately no windows build on this server.

	lin1, lin2 := f.addAgent("lin1"), f.addAgent("lin2")
	arm1 := f.addAgent("arm1")
	f.setArch(arm1, "arm64")
	win := f.addAgentOS("win1", "windows")
	var acme Organization
	f.admin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Acme Corp"}, &acme)
	open := f.addAgentIn(acme.ID, "open1", "linux")

	res, raw := updateAll(t, f)
	groups := []fleetGroup{
		{Org: trustOrg, OrgName: "Default Organization", OS: "linux", Arch: "amd64", Version: Version, SHA256: amd, AgentIDs: sortedIDs(lin1, lin2)},
		{Org: trustOrg, OrgName: "Default Organization", OS: "linux", Arch: "arm64", Version: Version, SHA256: arm, AgentIDs: sortedIDs(arm1)},
	}
	if res.DispatchedTo != 1 || !reflect.DeepEqual(res.SignedGroups, groups) {
		t.Fatalf("update-all = %s, want one device dispatched and the groups %+v", raw, groups)
	}
	// The windows device is online and in no group, and nothing was sent to it:
	// the reply counts it, so that "nothing needed doing" is never what an empty
	// result means.
	if wantMsg := "Dispatched update command to 1 online agent(s); 3 device(s) in 1 organization(s) that sign actions need a signed update; 1 online device(s) skipped because this server has no agent build for them"; res.Message != wantMsg || res.SkippedNoBuild != 1 {
		t.Fatalf("message = %q with %d skipped, want %q with 1", res.Message, res.SkippedNoBuild, wantMsg)
	}

	// The organization that does not sign took its update at once, unsigned;
	// everything else was left alone.
	got := open.wait(protocol.ReqAgentUpdate, 1)[0]
	var sent protocol.AgentUpdate
	json.Unmarshal(got.Env.D, &sent)
	if got.Env.A != nil || sent.SHA256 != amd || sent.URL != f.updateURL(amdName) {
		t.Fatalf("the unsigned organization was sent %+v with authorization %v", sent, got.Env.A)
	}
	time.Sleep(100 * time.Millisecond)
	for _, ag := range []*sigAgent{lin1, lin2, arm1, win} {
		if n := len(ag.requests(protocol.ReqAgentUpdate)); n != 0 {
			t.Fatalf("%s was sent %d agent.update requests by the fleet update, want none", ag.ID(), n)
		}
	}

	// Each group is what update-batch asks the operator to sign.
	file := map[string]string{amd: amdName, arm: armName}
	for _, g := range res.SignedGroups {
		c := ask(t, f.admin, "POST", "/api/agents/update-batch", map[string]any{"agent_ids": g.AgentIDs})
		m := c.parsed(t)
		var pl protocol.AgentUpdate
		json.Unmarshal(m.Payload, &pl)
		if want := (protocol.AgentUpdate{URL: f.updateURL(file[g.SHA256]), SHA256: g.SHA256, Version: g.Version}); m.Org != g.Org || !slices.Equal(m.Targets, g.AgentIDs) || pl != want {
			t.Fatalf("group %s/%s: manifest for %v in %s binds %+v, want %+v", g.OS, g.Arch, m.Targets, m.Org, pl, want)
		}
	}
	// The device that no group lists has no build to sign for.
	st, body := f.admin.do("POST", "/api/agents/update-batch", map[string]any{"agent_ids": []string{win.ID()}})
	if st != 404 || !strings.Contains(string(body), "no agent binary available on server for windows/amd64") {
		t.Fatalf("a device without a build on the server = %d %s", st, body)
	}
}

// One signature updates a batch of devices: update-batch answers 428 with a
// manifest that names every device (sorted, once each) and binds the one
// payload they all receive - the server's download URL and the SHA-256 of the
// binary, which each device checks its download against - and once the operator
// has signed, every agent verifies that signature before it would install
// anything. The manifest is single-use and bound to the devices it was made for.
func TestFleetUpdateBatchSignedAndDispatched(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	name, hash := stageAgentBinary(t, f.s, "linux", "amd64")
	a1, a2 := f.addAgent("box1"), f.addAgent("box2")
	ids := sortedIDs(a1, a2)
	const path = "/api/agents/update-batch"
	// Out of order and with a repeat: what is signed is the set of devices.
	body := map[string]any{"agent_ids": []string{ids[1], ids[0], ids[1]}}
	want := protocol.AgentUpdate{URL: f.updateURL(name), SHA256: hash, Version: Version}

	c := ask(t, f.admin, "POST", path, body)
	if !c.Required {
		t.Fatal("enforce mode must say the signature is required")
	}
	m := c.parsed(t)
	if m.Kind != actionauth.KindAction || m.Op != protocol.ReqAgentUpdate || m.Org != trustOrg || m.Issuer != "admin" ||
		!slices.Equal(m.Targets, ids) || m.Exp-m.IAT != 300 || m.ID != c.ManifestID {
		t.Fatalf("manifest = %+v", m)
	}
	var bound protocol.AgentUpdate
	json.Unmarshal(m.Payload, &bound)
	if bound != want {
		t.Fatalf("payload = %s, want %+v", m.Payload, want)
	}
	// What the operator is shown names the devices and the exact build.
	if wantSummary := fmt.Sprintf("Update the agent on 2 device(s) running linux/amd64 in Default Organization to %s (binary SHA-256 %s...)", Version, hash[:16]); c.Summary != wantSummary {
		t.Fatalf("summary = %q, want %q", c.Summary, wantSummary)
	}
	for _, ag := range []*sigAgent{a1, a2} {
		if n := len(ag.requests(protocol.ReqAgentUpdate)); n != 0 {
			t.Fatalf("%s was sent an update before anything was signed", ag.ID())
		}
	}

	hdr := c.signedBy(t, f.ka)
	st, raw := f.admin.doHdr("POST", path, body, hdr)
	if st != 200 {
		t.Fatalf("signed retry = %d %s", st, raw)
	}
	var res fleetBatch
	var shape map[string]json.RawMessage
	json.Unmarshal(raw, &res)
	json.Unmarshal(raw, &shape)
	if !res.OK || res.DispatchedTo != 2 || !res.Signed || res.Accepted != 2 || res.Installing != 0 || res.Offline != 0 ||
		string(shape["failed"]) != "[]" || res.Message != "Update command sent to 2 device(s): 2 accepted" {
		t.Fatalf("reply = %s", raw)
	}
	for _, ag := range []*sigAgent{a1, a2} {
		got := ag.wait(protocol.ReqAgentUpdate, 1)
		if len(got) != 1 {
			t.Fatalf("%s got %d agent.update requests, want 1", ag.ID(), len(got))
		}
		x := got[0]
		if x.Env.A == nil || x.Env.A.M != c.Manifest {
			t.Fatalf("%s was sent a manifest other than the one that was signed (A=%v)", ag.ID(), x.Env.A)
		}
		if !x.Dec.Verified || !x.Dec.Allow || x.Dec.ManifestID != c.ManifestID || len(x.Dec.Signers) != 1 || x.Dec.Signers[0] != "admin" {
			t.Fatalf("%s decision = %+v", ag.ID(), x.Dec)
		}
		var signed, sent protocol.AgentUpdate
		json.Unmarshal(x.Dec.Payload, &signed)
		json.Unmarshal(x.Env.D, &sent)
		if signed != want || sent != want {
			t.Fatalf("%s would install %+v (envelope carried %+v), want %+v", ag.ID(), signed, sent, want)
		}
	}

	// The reply is not the only record: who updated what is in the audit log.
	rows := fleetAuditRows(t, f.s)
	d := rows[0].Details
	if len(rows) != 1 || rows[0].User != "admin" || rows[0].Target != trustOrg ||
		d.Targets != 2 || d.OS != "linux" || d.Arch != "amd64" || d.Version != Version || d.SHA256 != hash ||
		d.Accepted != 2 || d.Installing != 0 || d.Offline != 0 || d.Failed != 0 || len(d.Failures) != 0 {
		t.Fatalf("audit = %+v", rows)
	}

	// The manifest is consumed: replaying the same header is refused.
	if st, _ := f.admin.doHdr("POST", path, body, hdr); st != 410 {
		t.Fatalf("replayed header = %d, want 410", st)
	}
	// A signature for these two devices cannot be redirected at one of them.
	c2 := ask(t, f.admin, "POST", path, body)
	if st, raw := f.admin.doHdr("POST", path, map[string]any{"agent_ids": []string{ids[0]}}, c2.signedBy(t, f.ka)); st != 409 {
		t.Fatalf("retry for a different set of devices = %d %s, want 409", st, raw)
	}
	for _, ag := range []*sigAgent{a1, a2} {
		if n := len(ag.requests(protocol.ReqAgentUpdate)); n != 1 {
			t.Fatalf("%s got %d agent.update requests, want 1", ag.ID(), n)
		}
	}
	// Updating one device on its own signs the very same payload, byte for byte.
	single := ask(t, f.admin, "POST", "/api/agents/"+a1.ID()+"/update", nil).parsed(t)
	if string(single.Payload) != string(m.Payload) || !slices.Equal(single.Targets, []string{a1.ID()}) {
		t.Fatalf("single-device payload %s for %v, batch payload %s", single.Payload, single.Targets, m.Payload)
	}
}

// update-batch refuses what one manifest cannot cover before anything is
// offered for signing: devices of different organizations or running different
// builds, an unknown device or operating system, a build the server has no
// binary for, an empty or oversized set, and anyone who is not an
// administrator. None of the refusals leaves a manifest waiting for a signature.
func TestFleetUpdateBatchRefusals(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	lin := f.addAgent("lin")
	win := f.addAgentOS("win", "windows")
	mac := f.addAgentOS("mac", "darwin")
	const path = "/api/agents/update-batch"
	refused := func(what string, wantSt int, wantMsg string, ids ...string) {
		t.Helper()
		if ids == nil {
			ids = []string{} // an empty list, not null
		}
		st, body := f.admin.do("POST", path, map[string]any{"agent_ids": ids})
		if st != wantSt || !strings.Contains(string(body), wantMsg) {
			t.Fatalf("%s = %d %s, want %d mentioning %q", what, st, body, wantSt, wantMsg)
		}
	}

	// No binary is staged yet. Whether two devices can share a payload is
	// settled before the server looks for one, so the answer is the same
	// with or without it.
	refused("a linux and a windows device", 400, "different agent builds", lin.ID(), win.ID())
	refused("a device whose build the server lacks", 404, "no agent binary available on server for linux/amd64", lin.ID())
	stageAgentBinary(t, f.s, "linux", "amd64")
	refused("a linux and a windows device with a linux build", 400, "different agent builds", lin.ID(), win.ID())
	refused("a windows device with only a linux build", 404, "no agent binary available on server for windows/amd64", win.ID())
	refused("a device of an unknown operating system", 400, "the operating system of mac is unknown", mac.ID())

	// devices of two organizations
	var acme Organization
	f.admin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Acme Corp"}, &acme)
	other := f.addAgentIn(acme.ID, "acme-box", "linux")
	refused("devices of two organizations", 400, "different organizations", lin.ID(), other.ID())

	// the set itself
	refused("no devices", 400, "agent_ids required")
	if st, body := f.admin.do("POST", path, nil); st != 400 || !strings.Contains(string(body), "agent_ids required") {
		t.Fatalf("no body = %d %s, want 400 agent_ids required", st, body)
	}
	refused("an unknown device", 404, "not found", "no-such-device")
	refused("a known and an unknown device", 404, "not found", lin.ID(), "no-such-device")
	tooMany := make([]string, maxUpdateBatch+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("device-%05d", i)
	}
	refused("more devices than one update may cover", 400, "too many devices in one update", tooMany...)

	// not an administrator
	for _, tc := range []struct {
		who  string
		b    *browser
		path string
		body any
		st   int
	}{
		{"a technician's update-batch", f.bob, path, map[string]any{"agent_ids": []string{lin.ID()}}, 403},
		{"a technician's update-all", f.bob, "/api/agents/update-all", nil, 403},
		{"an anonymous update-batch", newBrowser(t, f.ts), path, map[string]any{"agent_ids": []string{lin.ID()}}, 401},
		{"an anonymous update-all", newBrowser(t, f.ts), "/api/agents/update-all", nil, 401},
	} {
		if st, body := tc.b.do("POST", tc.path, tc.body); st != tc.st {
			t.Fatalf("%s = %d %s, want %d", tc.who, st, body, tc.st)
		}
	}

	f.s.signing.mu.Lock()
	waiting := len(f.s.signing.pending)
	f.s.signing.mu.Unlock()
	if waiting != 0 {
		t.Fatalf("%d manifests are waiting for a signature after nothing but refusals", waiting)
	}
	if n := len(lin.requests(protocol.ReqAgentUpdate)); n != 0 {
		t.Fatalf("the linux device was sent %d updates by refused requests", n)
	}
}

// agent.update is high-risk, so with a high threshold of two the update of even
// one device needs two approvers. The first signature parks the request in the
// approvals queue; the second operator signs it there, and the request that
// completes it dispatches the batch and answers with the batch handler's own
// response, with the audit entry still attributed to the operator who asked.
func TestFleetUpdateBatchNeedsTwoApprovers(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeAudit, 2, 10)
	name, hash := stageAgentBinary(t, f.s, "linux", "amd64")
	a1, a2 := f.addAgent("box1"), f.addAgent("box2")
	ids := sortedIDs(a1, a2)
	const path = "/api/agents/update-batch"
	body := map[string]any{"agent_ids": ids}
	want := protocol.AgentUpdate{URL: f.updateURL(name), SHA256: hash, Version: Version}

	c := ask(t, f.admin, "POST", path, body)
	if m := c.parsed(t); m.Op != protocol.ReqAgentUpdate || !slices.Equal(m.Targets, ids) || m.Exp-m.IAT != 600 {
		t.Fatalf("manifest = %+v: with two approvers it must outlive the first signature", m)
	}
	st, data := f.admin.doHdr("POST", path, body, c.signedBy(t, f.ka))
	var pend struct {
		Pending    bool   `json:"pending"`
		ManifestID string `json:"manifest_id"`
		Have       int    `json:"have"`
		Need       int    `json:"need"`
	}
	json.Unmarshal(data, &pend)
	if st != 202 || !pend.Pending || pend.Have != 1 || pend.Need != 2 || pend.ManifestID != c.ManifestID {
		t.Fatalf("first signature = %d %s", st, data)
	}
	for _, ag := range []*sigAgent{a1, a2} {
		if n := len(ag.requests(protocol.ReqAgentUpdate)); n != 0 {
			t.Fatalf("%s was sent the update before the threshold was met", ag.ID())
		}
	}

	type queued struct {
		ManifestID string `json:"manifest_id"`
		Have       int    `json:"have"`
		Need       int    `json:"need"`
		CreatedBy  string `json:"created_by"`
		Summary    string `json:"summary"`
	}
	var mine, theirs []queued
	f.admin.mustJSON("GET", "/api/approvals", nil, &mine)
	f.bob.mustJSON("GET", "/api/approvals", nil, &theirs)
	if len(mine) != 0 {
		t.Fatalf("the operator who already signed sees %d approvals waiting for them", len(mine))
	}
	if len(theirs) != 1 || theirs[0].ManifestID != c.ManifestID || theirs[0].Have != 1 || theirs[0].Need != 2 || theirs[0].CreatedBy != "admin" ||
		theirs[0].Summary != c.Summary || !strings.Contains(theirs[0].Summary, hash[:16]) {
		t.Fatalf("bob's queue = %+v", theirs)
	}

	st, data = f.bob.do("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.kb.Sign(c.bytes(t), authtest.SignOpts{})})
	if st != 200 {
		t.Fatalf("completing signature = %d %s", st, data)
	}
	var res fleetBatch
	json.Unmarshal(data, &res)
	if !res.OK || res.DispatchedTo != 2 || !res.Signed || res.Accepted != 2 || res.Message != "Update command sent to 2 device(s): 2 accepted" {
		t.Fatalf("the completing request got %s, want the batch handler's own response", data)
	}
	for _, ag := range []*sigAgent{a1, a2} {
		got := ag.wait(protocol.ReqAgentUpdate, 1)[0]
		if got.Env.A == nil || got.Env.A.M != c.Manifest || !got.Dec.Verified || !got.Dec.Allow {
			t.Fatalf("%s: A=%v decision=%+v", ag.ID(), got.Env.A, got.Dec)
		}
		if signers := slices.Sorted(slices.Values(got.Dec.Signers)); !slices.Equal(signers, []string{"admin", "bob"}) {
			t.Fatalf("%s: signers = %v, want both approvers", ag.ID(), signers)
		}
		var signed protocol.AgentUpdate
		json.Unmarshal(got.Dec.Payload, &signed)
		if signed != want {
			t.Fatalf("%s would install %+v, want %+v", ag.ID(), signed, want)
		}
	}
	// Bob completed it, but the update is the administrator's request.
	if rows := fleetAuditRows(t, f.s); len(rows) != 1 || rows[0].User != "admin" || rows[0].Details.Accepted != 2 {
		t.Fatalf("audit = %+v, want one entry by admin", rows)
	}
	// Done: nothing is left to sign.
	if st, _ := f.bob.do("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.kb.Sign(c.bytes(t), authtest.SignOpts{})}); st != 410 {
		t.Fatalf("re-signing a finished manifest = %d, want 410", st)
	}
}

// An organization that does not sign - no trust bundle at all, or one whose
// mode is off - sees no change: update-all sends the update at once, unsigned,
// exactly as before, and reports an empty signed_groups list (an array, never
// null, because the console iterates it). Only devices that are online and
// have a build on the server are sent anything or counted.
func TestUnsignedOrgUpdateAllUnchanged(t *testing.T) {
	withoutDevDist(t)
	for _, mode := range []string{"", actionauth.ModeOff} {
		f := newSignFixture(t, mode, 1, 10)
		name, hash := stageAgentBinary(t, f.s, "linux", "amd64")
		ag := f.addAgent("box1")
		win := f.addAgentOS("win1", "windows") // there is no windows build to send it
		gone := f.addAgent("gone")
		f.disconnect(gone)

		res, raw := updateAll(t, f)
		var shape map[string]json.RawMessage
		json.Unmarshal(raw, &shape)
		if !res.OK || res.DispatchedTo != 1 || string(shape["signed_groups"]) != "[]" || res.SkippedNoBuild != 1 ||
			res.Message != "Dispatched update command to 1 online agent(s); 1 online device(s) skipped because this server has no agent build for them" {
			t.Fatalf("mode %q: update-all = %s", mode, raw)
		}
		got := ag.wait(protocol.ReqAgentUpdate, 1)[0]
		var sent protocol.AgentUpdate
		json.Unmarshal(got.Env.D, &sent)
		if got.Env.A != nil || !got.Dec.Allow || got.Dec.Err != nil {
			t.Fatalf("mode %q: an unsigned org was sent an authorization: A=%v decision=%+v", mode, got.Env.A, got.Dec)
		}
		if want := (protocol.AgentUpdate{URL: f.updateURL(name), SHA256: hash, Version: Version}); sent != want {
			t.Fatalf("mode %q: the device was sent %+v, want %+v", mode, sent, want)
		}
		time.Sleep(100 * time.Millisecond)
		if n := len(win.requests(protocol.ReqAgentUpdate)); n != 0 {
			t.Fatalf("mode %q: the windows device was sent %d updates although no windows build exists", mode, n)
		}
	}
}

// The unattended update poll is where an enforcing organization's devices would
// be told about a build they must refuse, and each of them would report the
// refusal as a security event. So the server answers them
// signed_update_required, with the digest but not the download URL, and
// advertises nothing. Audit mode, a bundle that is off and organizations
// without a bundle keep advertising the build, and a device that already runs
// it is simply up to date.
func TestUpdateCheckInEnforcingOrgDoesNotAdvertise(t *testing.T) {
	withoutDevDist(t)
	stale := strings.Repeat("0", 64)
	check := func(f *signFixture, ag *sigAgent, sha string) map[string]any {
		t.Helper()
		req, err := http.NewRequest("GET", f.ts.URL+"/api/agent/update-check?os=linux&arch=amd64&version=x&sha256="+sha, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+ag.raw.key)
		resp, err := f.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != 200 {
			t.Fatalf("update-check = %d (%v)", resp.StatusCode, err)
		}
		return out
	}

	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	_, hash := stageAgentBinary(t, f.s, "linux", "amd64")
	ag := f.addAgent("box1")
	got := check(f, ag, stale)
	if got["update_available"] != false || got["signed_update_required"] != true || got["sha256"] != hash || got["version"] != Version {
		t.Fatalf("enforce: update-check = %v", got)
	}
	if _, leaked := got["url"]; leaked {
		t.Fatalf("enforce: the unsigned poll was handed the download url: %v", got)
	}
	got = check(f, ag, hash)
	if len(got) != 1 || got["update_available"] != false {
		t.Fatalf("enforce, device already on the staged build: update-check = %v, want only update_available:false", got)
	}

	for _, mode := range []string{actionauth.ModeAudit, actionauth.ModeOff, ""} {
		g := newSignFixture(t, mode, 1, 10)
		name, sum := stageAgentBinary(t, g.s, "linux", "amd64")
		got := check(g, g.addAgent("box1"), stale)
		if got["update_available"] != true || got["sha256"] != sum || got["version"] != Version || got["url"] != g.updateURL(name) || got["signed_update_required"] == true {
			t.Fatalf("mode %q: update-check = %v, want the build advertised", mode, got)
		}
	}
}

// The batch reply accounts for every device: those that took the update, those
// that were offline, and those that answered with an error, with the device's
// name and the error. A batch that nobody took says so, and says what happened
// to the devices that were reached, but still lists who failed. In an
// organization without a bundle the same request needs no signature and goes
// straight out, and the reply says it was not signed.
func TestFleetUpdateBatchReportsEachDevice(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, "", 1, 10)
	_, hash := stageAgentBinary(t, f.s, "linux", "amd64")
	ok := f.addAgent("ok")
	badID := f.addUpdateAgent("bad", "boom: disk full", false)
	gone := f.addAgent("gone")
	f.disconnect(gone)
	failed := []fleetFailure{{ID: badID, Name: "bad", Error: "boom: disk full"}}

	res, _, raw := postBatch(t, f, ok.ID(), badID, gone.ID())
	if !res.OK || res.DispatchedTo != 1 || res.Signed || res.Accepted != 1 || res.Installing != 0 || res.Offline != 1 || !reflect.DeepEqual(res.Failed, failed) ||
		res.Message != "1 of 3 device(s) took the update: 1 accepted, 1 offline, 1 failed" {
		t.Fatalf("reply = %s", raw)
	}
	got := ok.wait(protocol.ReqAgentUpdate, 1)[0]
	var sent protocol.AgentUpdate
	json.Unmarshal(got.Env.D, &sent)
	if got.Env.A != nil || sent.SHA256 != hash {
		t.Fatalf("the device was sent %+v with authorization %v", sent, got.Env.A)
	}

	// Nobody took it: the answer says so without claiming that the device which
	// answered with an error was out of reach, and the failure is still listed.
	res, _, raw = postBatch(t, f, badID, gone.ID())
	if !res.OK || res.DispatchedTo != 0 || res.Accepted != 0 || res.Offline != 1 || !reflect.DeepEqual(res.Failed, failed) ||
		res.Message != "No device took the update (1 offline, 1 failed)" {
		t.Fatalf("reply = %s", raw)
	}
	// Only offline devices: failed is an empty list, never null.
	res, shape, raw := postBatch(t, f, gone.ID())
	if !res.OK || res.DispatchedTo != 0 || res.Offline != 1 || string(shape["failed"]) != "[]" || res.Message != "No device could be reached" {
		t.Fatalf("reply = %s", raw)
	}
	// The audit entry keeps who failed and why, and the count stays a plain
	// number next to the list.
	if rows := fleetAuditRows(t, f.s); len(rows) < 1 || rows[0].Details.Accepted != 1 || rows[0].Details.Offline != 1 || rows[0].Details.Failed != 1 || rows[0].Details.Targets != 3 ||
		!reflect.DeepEqual(rows[0].Details.Failures, failed) {
		t.Fatalf("audit = %+v, want the first batch counted as 1 accepted, 1 offline, 1 failed of 3, with the failure named", rows)
	}
}

// agent.update is answered only once the device has downloaded and staged the
// binary, which can take longer than the server is willing to wait. A device
// that has not answered when the window closes is therefore still installing,
// not failed, and the batch says so instead of raising a false alarm. The
// window is shortened here so the test does not wait out the real 20 s.
func TestFleetUpdateBatchCountsASilentDeviceAsInstalling(t *testing.T) {
	window := fleetUpdateReplyWindow
	fleetUpdateReplyWindow = 300 * time.Millisecond
	t.Cleanup(func() { fleetUpdateReplyWindow = window })
	withoutDevDist(t)
	f := newSignFixture(t, "", 1, 10)
	stageAgentBinary(t, f.s, "linux", "amd64")
	quick := f.addAgent("quick")
	slow := f.addUpdateAgent("slow", "", true)

	res, shape, raw := postBatch(t, f, quick.ID(), slow)
	if !res.OK || res.DispatchedTo != 2 || res.Accepted != 1 || res.Installing != 1 || res.Offline != 0 || string(shape["failed"]) != "[]" ||
		res.Message != "Update command sent to 2 device(s): 1 accepted, 1 still installing" {
		t.Fatalf("reply = %s", raw)
	}
	if rows := fleetAuditRows(t, f.s); len(rows) != 1 || rows[0].Details.Accepted != 1 || rows[0].Details.Installing != 1 || rows[0].Details.Failed != 0 {
		t.Fatalf("audit = %+v, want 1 accepted, 1 installing", rows)
	}
}

// The batch message names only what happened. Its count is the devices that
// took the update out of all of them, so it never stands beside buckets it does
// not include, and "could be reached" is said only of devices that were
// offline: one that answered with an error was reached.
func TestFleetUpdateMessage(t *testing.T) {
	for _, tc := range []struct {
		accepted, installing, offline, failed int
		want                                  string
	}{
		{2, 0, 0, 0, "Update command sent to 2 device(s): 2 accepted"},
		{1, 1, 0, 0, "Update command sent to 2 device(s): 1 accepted, 1 still installing"},
		{0, 3, 0, 0, "Update command sent to 3 device(s): 3 still installing"},
		{1, 0, 1, 1, "1 of 3 device(s) took the update: 1 accepted, 1 offline, 1 failed"},
		{2, 1, 4, 5, "3 of 12 device(s) took the update: 2 accepted, 1 still installing, 4 offline, 5 failed"},
		{3, 0, 2, 0, "3 of 5 device(s) took the update: 3 accepted, 2 offline"},
		{0, 0, 2, 0, "No device could be reached"},
		{0, 0, 0, 1, "No device took the update (1 failed)"},
		{0, 0, 2, 3, "No device took the update (2 offline, 3 failed)"},
		{0, 0, 0, 0, "No device could be reached"},
	} {
		if got := fleetUpdateMessage(tc.accepted, tc.installing, tc.offline, tc.failed); got != tc.want {
			t.Errorf("fleetUpdateMessage(%d, %d, %d, %d) = %q, want %q", tc.accepted, tc.installing, tc.offline, tc.failed, got, tc.want)
		}
	}
}

// ---- limits, and what a device gets to choose ----

// seedOnlineAgents adds n online linux/amd64 devices to the default
// organization, named seed-<first> onwards (so they sort in the order they are
// made), and returns their IDs. update-all and update-batch read the database
// rows and whether the hub holds a connection under the ID, and update-all
// sends nothing to an organization that signs, so a bare hub entry stands in
// for a socket. The entries go before the fixture's own cleanup, which would
// otherwise try to close a socket that is not there.
func seedOnlineAgents(t *testing.T, f *signFixture, first, n int) []string {
	t.Helper()
	tx, err := f.s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, n)
	for i := range ids {
		id := fmt.Sprintf("seed-%05d", first+i)
		ids[i] = id
		if _, err := tx.Exec(`INSERT INTO agents(id, hostname, display_name, os, platform, arch, version, key_hash, enrolled_at, last_seen, org_id)
			VALUES(?, ?, ?, 'linux', 'Test', 'amd64', '1', ?, ?, ?, ?)`, id, id, id, "hash-"+id, now(), now(), trustOrg); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	f.s.hub.mu.Lock()
	for _, id := range ids {
		f.s.hub.agents[id] = &agentConn{id: id}
	}
	f.s.hub.mu.Unlock()
	t.Cleanup(func() {
		f.s.hub.mu.Lock()
		for _, id := range ids {
			delete(f.s.hub.agents, id)
		}
		f.s.hub.mu.Unlock()
	})
	return ids
}

// update-batch takes at most maxUpdateBatch devices, so update-all must not
// hand out a group it would refuse: the operator would never be asked to sign
// it, and in an organization that enforces signatures its devices could not be
// updated at all. A build that more online devices of one organization run than
// that comes back as several groups, the devices in order, every one of which
// the batch accepts, and in the same order each time.
func TestFleetUpdateAllCutsBigGroupsToTheBatchLimit(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	_, hash := stageAgentBinary(t, f.s, "linux", "amd64")
	group := func(ids []string) fleetGroup {
		return fleetGroup{Org: trustOrg, OrgName: "Default Organization", OS: "linux", Arch: "amd64", Version: Version, SHA256: hash, AgentIDs: ids}
	}
	// Every group is what update-batch asks the operator to sign, device for device.
	signable := func(res fleetAll) {
		t.Helper()
		for i, g := range res.SignedGroups {
			c := ask(t, f.admin, "POST", "/api/agents/update-batch", map[string]any{"agent_ids": g.AgentIDs})
			if m := c.parsed(t); !slices.Equal(m.Targets, g.AgentIDs) {
				t.Fatalf("group %d: the manifest names %d devices, want the group's %d", i, len(m.Targets), len(g.AgentIDs))
			}
		}
	}

	// As many as one update may cover is still one group.
	ids := seedOnlineAgents(t, f, 0, maxUpdateBatch)
	res, raw := updateAll(t, f)
	if len(res.SignedGroups) != 1 || !reflect.DeepEqual(res.SignedGroups[0], group(ids)) {
		t.Fatalf("%d devices: update-all gave %d groups, want the one group of them all (%.300s)", len(ids), len(res.SignedGroups), raw)
	}
	signable(res)

	// One more is cut at the limit, and the devices stay in order.
	ids = append(ids, seedOnlineAgents(t, f, maxUpdateBatch, 1)...)
	res, raw = updateAll(t, f)
	want := []fleetGroup{group(ids[:maxUpdateBatch]), group(ids[maxUpdateBatch:])}
	if len(res.SignedGroups) != 2 || !reflect.DeepEqual(res.SignedGroups, want) {
		var sizes []int
		for _, g := range res.SignedGroups {
			sizes = append(sizes, len(g.AgentIDs))
		}
		t.Fatalf("%d devices: update-all gave groups of %v, want %d and 1 (%.300s)", len(ids), sizes, maxUpdateBatch, raw)
	}
	// Devices are counted, not groups.
	if wantMsg := fmt.Sprintf("Dispatched update command to 0 online agent(s); %d device(s) in 1 organization(s) that sign actions need a signed update", len(ids)); res.Message != wantMsg {
		t.Fatalf("message = %q, want %q", res.Message, wantMsg)
	}
	signable(res)

	// Nothing about the order is left to chance.
	for i := 0; i < 3; i++ {
		if again, _ := updateAll(t, f); !reflect.DeepEqual(again.SignedGroups, res.SignedGroups) {
			t.Fatalf("update-all gave the groups in a different order the %d. time it was asked again", i+2)
		}
	}
}

// sendInventory pushes the inventory frame a device sends after it connects and
// waits until the server has stored it.
func (f *signFixture) sendInventory(a *sigAgent, hostname, arch string) {
	f.t.Helper()
	frame := protocol.Envelope{T: protocol.TypeInventory, D: protocol.Must(protocol.Inventory{Hostname: hostname, Arch: arch})}
	a.mu.Lock()
	err := a.raw.ws.WriteJSON(frame)
	a.mu.Unlock()
	if err != nil {
		f.t.Fatal(err)
	}
	waitFor(f.t, hostname+"'s inventory to be stored", func() bool {
		ag, err := f.s.db.GetAgent(a.ID())
		return err == nil && ag.Inventory != nil && ag.Inventory.Arch == arch
	})
}

// update-all groups devices by the architecture they announced when they
// connected, because the fleet listing loads no inventories, and update-batch
// has to put every device of that group on the same build. A device whose
// inventory claims another architecture than its hello must not make the group
// it is listed in unsignable for everyone else: nobody could be told which
// device to leave out, and in an enforcing organization nothing else updates
// the rest. The hello decides for every update handler.
func TestFleetUpdateGroupIsSignableWhateverADeviceInventoryClaims(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	amdName, amd := stageAgentBinary(t, f.s, "linux", "amd64")
	stageAgentBinary(t, f.s, "linux", "arm64")
	a1, a2, a3 := f.addAgent("box1"), f.addAgent("box2"), f.addAgent("box3")
	f.sendInventory(a1, "box1", "amd64")
	f.sendInventory(a2, "box2", "amd64")
	f.sendInventory(a3, "box3", "arm64") // its hello said amd64

	res, raw := updateAll(t, f)
	want := fleetGroup{Org: trustOrg, OrgName: "Default Organization", OS: "linux", Arch: "amd64", Version: Version, SHA256: amd, AgentIDs: sortedIDs(a1, a2, a3)}
	if len(res.SignedGroups) != 1 || !reflect.DeepEqual(res.SignedGroups[0], want) {
		t.Fatalf("update-all = %s, want the one group %+v", raw, want)
	}
	// The group is accepted as it was handed out, and binds the build it names.
	m := ask(t, f.admin, "POST", "/api/agents/update-batch", map[string]any{"agent_ids": want.AgentIDs}).parsed(t)
	var pl protocol.AgentUpdate
	json.Unmarshal(m.Payload, &pl)
	if wantPl := (protocol.AgentUpdate{URL: f.updateURL(amdName), SHA256: amd, Version: Version}); pl != wantPl || !slices.Equal(m.Targets, want.AgentIDs) {
		t.Fatalf("the manifest for the group binds %+v for %v, want %+v for %v", pl, m.Targets, wantPl, want.AgentIDs)
	}
	// And the device on its own is offered the same build as the group it is in.
	single := ask(t, f.admin, "POST", "/api/agents/"+a3.ID()+"/update", nil).parsed(t)
	if string(single.Payload) != string(m.Payload) {
		t.Fatalf("updating the device on its own binds %s, the group binds %s", single.Payload, m.Payload)
	}
}

// The name of the build the server looks for is made from what a device says
// about itself, and filepath.Join cleans a ".." out of the middle of it, so an
// architecture such as "x/../../secret" used to find, and update-all to hash and
// bind into a manifest, any file the server could read; on Linux a device node
// would have made the hash read forever. The server only knows the platforms
// it builds for, so a value that is not one of them finds nothing, whichever
// way it arrives: the device's hello (the fleet and the single update) or the
// query of the unattended update-check.
func TestAgentBuildIsOnlyFoundByNameAndKnownPlatform(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, "", 1, 10)
	_, hash := stageAgentBinary(t, f.s, "linux", "amd64")
	// Real files, so that only the platform check stands between them and a lookup.
	stageAgentBinary(t, f.s, "linux", "riscv64")
	stageAgentBinary(t, f.s, "darwin", "amd64")
	// A file outside the agents directory that a path walked there would reach.
	secret := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(secret, []byte("not an agent build\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(filepath.Join(f.s.cfg.path("agents"), "rmm-agent-linux-x"), secret)
	if err != nil {
		t.Fatal(err)
	}
	walk := "x/" + filepath.ToSlash(rel)
	if got := filepath.Join(f.s.cfg.path("agents"), "rmm-agent-linux-"+walk); got != filepath.Clean(secret) {
		t.Fatalf("the test's own path arithmetic is off: %s does not reach %s", got, secret)
	}

	if got := f.s.agentBinaryPath("linux", "amd64"); got == "" || f.s.agentBinarySHA256("linux", "amd64") != hash {
		t.Fatalf("the build the server has is not found by name: path %q", got)
	}
	for _, c := range []struct{ what, os, arch string }{
		{"an architecture that walks out of agents/", "linux", walk},
		{"an architecture the server does not build for", "linux", "riscv64"},
		{"an operating system the server does not build for", "darwin", "amd64"},
		{"an operating system that is a path", "../x", "amd64"},
		{"no architecture", "linux", ""},
	} {
		if p, sum := f.s.agentBinaryPath(c.os, c.arch), f.s.agentBinarySHA256(c.os, c.arch); p != "" || sum != "" {
			t.Errorf("%s: found %q (sha256 %q), want nothing", c.what, p, sum)
		}
	}
	// A directory is not a build either.
	if err := os.MkdirAll(filepath.Join(f.s.cfg.path("agents"), "rmm-agent-linux-386"), 0o755); err != nil {
		t.Fatal(err)
	}
	if p := f.s.agentBinaryPath("linux", "386"); p != "" {
		t.Errorf("a directory named like a build was found: %q", p)
	}

	// A device that announces such an architecture is sent nothing, and is
	// counted among those the server has no build for.
	a := f.addAgent("sneaky")
	f.setArch(a, walk)
	res, raw := updateAll(t, f)
	if res.DispatchedTo != 0 || res.SkippedNoBuild != 1 || len(res.SignedGroups) != 0 {
		t.Fatalf("update-all = %s, want nothing dispatched and the device skipped", raw)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(a.requests(protocol.ReqAgentUpdate)); n != 0 {
		t.Fatalf("the device was sent %d updates", n)
	}
	if st, body := f.admin.do("POST", "/api/agents/"+a.ID()+"/update", nil); st != 404 || !strings.Contains(string(body), "no agent binary available on server") {
		t.Fatalf("updating that device on its own = %d %s, want 404", st, body)
	}
	// The unattended poll takes the architecture from its query.
	req, err := http.NewRequest("GET", f.ts.URL+"/api/agent/update-check?os=linux&arch="+url.QueryEscape(walk), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+a.raw.key)
	resp, err := f.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil || resp.StatusCode != 200 || len(got) != 1 || got["update_available"] != false {
		t.Fatalf("update-check for such an architecture = %d %v (%v), want only update_available:false", resp.StatusCode, got, err)
	}
}

// The reply says whether the update went out under a signature, which is not the
// same as the organization signing: in audit mode an operator may continue
// without signing, and the devices are then sent an update nobody signed. The
// console must not count them as updated by signed update.
func TestFleetUpdateBatchSaysWhetherItWasSigned(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	stageAgentBinary(t, f.s, "linux", "amd64")
	signed, unsigned := f.addAgent("signed"), f.addAgent("unsigned")
	const path = "/api/agents/update-batch"
	reply := func(st int, raw []byte) fleetBatch {
		t.Helper()
		var res fleetBatch
		if st != 200 || json.Unmarshal(raw, &res) != nil || !res.OK || res.DispatchedTo != 1 {
			t.Fatalf("update-batch = %d %s, want one device sent the update", st, raw)
		}
		return res
	}

	body := map[string]any{"agent_ids": []string{signed.ID()}}
	c := ask(t, f.admin, "POST", path, body)
	st, raw := f.admin.doHdr("POST", path, body, c.signedBy(t, f.ka))
	if res := reply(st, raw); !res.Signed {
		t.Fatalf("a signed update was reported as unsigned: %s", raw)
	}
	if got := signed.wait(protocol.ReqAgentUpdate, 1)[0]; got.Env.A == nil || !got.Dec.Verified {
		t.Fatalf("the device saw no verified signature: A=%v decision=%+v", got.Env.A, got.Dec)
	}

	// Continue without signing, which audit mode offers.
	body = map[string]any{"agent_ids": []string{unsigned.ID()}}
	if c := ask(t, f.admin, "POST", path, body); c.Required {
		t.Fatal("audit mode must not insist on a signature")
	}
	st, raw = f.admin.doHdr("POST", path, body, map[string]string{headerActionAuth: "skip"})
	if res := reply(st, raw); res.Signed {
		t.Fatalf("an update nobody signed was reported as signed: %s", raw)
	}
	if got := unsigned.wait(protocol.ReqAgentUpdate, 1)[0]; got.Env.A != nil {
		t.Fatalf("the device was sent an authorization: %v", got.Env.A)
	}
}

// The audit entry for a fleet update names who asked and from where, however it
// is completed. With two signers required the last signature arrives on another
// operator's request from another address, and the entry used to take its
// address from that one, so the log put the administrator's update at the
// address of the person who only approved it.
func TestFleetUpdateAuditKeepsTheAddressOfWhoAsked(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeAudit, 2, 10)
	stageAgentBinary(t, f.s, "linux", "amd64")
	a1 := f.addAgent("box1")
	// The test server sits behind the loopback address, so this is how the
	// operators' own addresses reach the audit log.
	f.s.trustedProxies = parseTrustedProxies([]string{"127.0.0.0/8"})
	const path = "/api/agents/update-batch"
	body := map[string]any{"agent_ids": []string{a1.ID()}}
	from := func(ip string) map[string]string { return map[string]string{"X-Forwarded-For": ip} }

	// The administrator asks from 10.0.0.1 ...
	st, data := f.admin.doHdr("POST", path, body, from("10.0.0.1"))
	var c challenge
	if json.Unmarshal(data, &c) != nil || st != 428 || c.ManifestID == "" {
		t.Fatalf("asking = %d %s, want 428", st, data)
	}
	// ... signs from it ...
	hdr := c.signedBy(t, f.ka)
	hdr["X-Forwarded-For"] = "10.0.0.1"
	if st, data := f.admin.doHdr("POST", path, body, hdr); st != 202 {
		t.Fatalf("first signature = %d %s", st, data)
	}
	// ... and bob completes it from 10.0.0.2.
	st, data = f.bob.doHdr("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.kb.Sign(c.bytes(t), authtest.SignOpts{})}, from("10.0.0.2"))
	if st != 200 {
		t.Fatalf("completing signature = %d %s", st, data)
	}
	if rows := fleetAuditRows(t, f.s); len(rows) != 1 || rows[0].User != "admin" || rows[0].IP != "10.0.0.1" {
		t.Fatalf("audit = %+v, want one entry by admin from 10.0.0.1, where the update was asked for", rows)
	}
}

// The audit entry names the devices that failed, but only the first few and
// with each reason clipped: a batch can cover maxUpdateBatch devices and a
// device writes its own reason, so a fleet that fails in one way must not put
// all of it in one row. The caller's own list is left whole for the reply.
func TestFleetUpdateAuditedFailuresAreCapped(t *testing.T) {
	var failed []fleetUpdateFailure
	for i := 0; i < maxAuditedFailures+5; i++ {
		failed = append(failed, fleetUpdateFailure{ID: fmt.Sprintf("d%02d", i), Name: "box", Error: strings.Repeat("x", 5*maxAuditedReasonLen)})
	}
	got := auditedFailures(failed)
	if len(got) != maxAuditedFailures || got[0].ID != "d00" || got[len(got)-1].ID != fmt.Sprintf("d%02d", maxAuditedFailures-1) {
		t.Fatalf("kept %d failures, want the first %d", len(got), maxAuditedFailures)
	}
	for _, f := range got {
		if len(f.Error) != maxAuditedReasonLen+len("...") || f.Name != "box" {
			t.Fatalf("a kept failure is %q for %q, want its reason clipped to %d characters", f.Error, f.Name, maxAuditedReasonLen)
		}
	}
	if len(failed) != maxAuditedFailures+5 || len(failed[0].Error) != 5*maxAuditedReasonLen {
		t.Fatal("the list that goes in the reply was cut as well")
	}
	if got := auditedFailures(nil); got == nil || len(got) != 0 {
		t.Fatalf("no failures = %v, want an empty list", got)
	}
}

// ---- single-device update window and the recorded build digest ----

// reportDigest is a device's update-check poll, which carries the SHA-256 of
// the binary it runs. It returns the decoded answer.
func reportDigest(t *testing.T, f *signFixture, agentKey, sha string) map[string]any {
	t.Helper()
	req, err := http.NewRequest("GET", f.ts.URL+"/api/agent/update-check?os=linux&arch=amd64&version=x&sha256="+sha, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+agentKey)
	resp, err := f.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != 200 {
		t.Fatalf("update-check = %d (%v)", resp.StatusCode, err)
	}
	return out
}

func recordedDigest(t *testing.T, s *Server, id string) (string, int64) {
	t.Helper()
	var sum string
	var at int64
	if err := s.db.QueryRow(`SELECT binary_sha256, binary_sha256_at FROM agents WHERE id = ?`, id).Scan(&sum, &at); err != nil {
		t.Fatal(err)
	}
	return sum, at
}

// A device slower than the reply window is still installing, as the batch
// says, and not a 400. A refusal is a 400 with the device's reason, and an
// offline device a 409.
func TestUpdateSingleDeviceWaitsLikeTheBatch(t *testing.T) {
	window := fleetUpdateReplyWindow
	fleetUpdateReplyWindow = 300 * time.Millisecond
	t.Cleanup(func() { fleetUpdateReplyWindow = window })
	withoutDevDist(t)
	f := newSignFixture(t, "", 1, 10)
	stageAgentBinary(t, f.s, "linux", "amd64")
	slow := f.addUpdateAgent("slow", "", true)
	bad := f.addUpdateAgent("bad", "boom: disk full", false)
	gone := f.addAgent("gone")
	f.disconnect(gone)

	st, raw := f.admin.do("POST", "/api/agents/"+slow+"/update", nil)
	var res struct {
		OK         bool   `json:"ok"`
		Installing bool   `json:"installing"`
		Message    string `json:"message"`
	}
	json.Unmarshal(raw, &res)
	if st != 200 || !res.OK || !res.Installing || !strings.Contains(res.Message, "is still downloading and checking the binary; it will restart on its own when done") {
		t.Fatalf("silent device: %d %s", st, raw)
	}
	if st, raw := f.admin.do("POST", "/api/agents/"+bad+"/update", nil); st != 400 || !strings.Contains(string(raw), "boom: disk full") {
		t.Fatalf("refusing device: %d %s, want 400 with the device's reason", st, raw)
	}
	if st, raw := f.admin.do("POST", "/api/agents/"+gone.ID()+"/update", nil); st != 409 {
		t.Fatalf("offline device: %d %s, want 409", st, raw)
	}
}

func TestUpdateCheckRecordsTheBinaryDigest(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, "", 1, 10)
	stageAgentBinary(t, f.s, "linux", "amd64")
	ag := f.addAgent("box")
	upper := strings.ToUpper(strings.Repeat("ab", 32))
	reportDigest(t, f, ag.raw.key, upper)
	sum, at := recordedDigest(t, f.s, ag.ID())
	if sum != strings.ToLower(upper) || at == 0 {
		t.Fatalf("recorded %q at %d, want the lower-cased digest with a time", sum, at)
	}
	// Anything that is not 64 hex characters leaves the record alone.
	for _, bad := range []string{"", "abc", strings.Repeat("z", 64), strings.Repeat("a", 65)} {
		reportDigest(t, f, ag.raw.key, bad)
		if got, _ := recordedDigest(t, f.s, ag.ID()); got != sum {
			t.Fatalf("digest %q replaced the record with %q", bad, got)
		}
	}
}

func TestFleetUpdateAllSkipsADeviceOnTheBuild(t *testing.T) {
	withoutDevDist(t)
	for _, mode := range []string{"", actionauth.ModeEnforce} {
		f := newSignFixture(t, mode, 1, 10)
		_, hash := stageAgentBinary(t, f.s, "linux", "amd64")
		cur, old := f.addAgent("current"), f.addAgent("old")
		reportDigest(t, f, cur.raw.key, hash)
		reportDigest(t, f, old.raw.key, strings.Repeat("0", 64))
		res, raw := updateAll(t, f)
		var shape struct {
			UpToDate int `json:"up_to_date"`
		}
		json.Unmarshal(raw, &shape)
		if shape.UpToDate != 1 || !strings.Contains(res.Message, "1 online device(s) already run this build") {
			t.Fatalf("mode %q: update-all = %s, want one device counted as up to date", mode, raw)
		}
		if mode == "" {
			if res.DispatchedTo != 1 || len(res.SignedGroups) != 0 {
				t.Fatalf("update-all = %s, want only the old device sent", raw)
			}
			if n := len(cur.requests(protocol.ReqAgentUpdate)); n != 0 {
				t.Fatalf("the current device was sent %d update(s)", n)
			}
		} else if len(res.SignedGroups) != 1 || !reflect.DeepEqual(res.SignedGroups[0].AgentIDs, []string{old.ID()}) {
			t.Fatalf("update-all = %s, want a group with only the old device", raw)
		}
	}
}

func TestFleetUpdateBatchOfCurrentDevicesNeedsNoSignature(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	_, hash := stageAgentBinary(t, f.s, "linux", "amd64")
	a, b := f.addAgent("a"), f.addAgent("b")
	reportDigest(t, f, a.raw.key, hash)
	reportDigest(t, f, b.raw.key, hash)

	st, raw := f.admin.do("POST", "/api/agents/update-batch", map[string]any{"agent_ids": []string{a.ID(), b.ID()}})
	var res struct {
		OK           bool   `json:"ok"`
		DispatchedTo int    `json:"dispatched_to"`
		UpToDate     int    `json:"up_to_date"`
		Signed       bool   `json:"signed"`
		Message      string `json:"message"`
	}
	json.Unmarshal(raw, &res)
	if st != 200 || !res.OK || res.DispatchedTo != 0 || res.UpToDate != 2 || res.Signed || res.Message != "every device already runs this build" {
		t.Fatalf("update-batch = %d %s", st, raw)
	}

	// One stale device keeps the request a signed one, naming only that device.
	reportDigest(t, f, b.raw.key, strings.Repeat("0", 64))
	c := ask(t, f.admin, "POST", "/api/agents/update-batch", map[string]any{"agent_ids": []string{a.ID(), b.ID()}})
	if !strings.Contains(string(c.bytes(t)), b.ID()) || strings.Contains(string(c.bytes(t)), a.ID()) {
		t.Fatalf("the manifest should name only the stale device %s, not %s", b.ID(), a.ID())
	}
}

func TestUpdateSingleDeviceAnswersUpToDateUnlessForced(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	_, hash := stageAgentBinary(t, f.s, "linux", "amd64")
	a := f.addAgent("a")
	reportDigest(t, f, a.raw.key, hash)

	path := "/api/agents/" + a.ID() + "/update"
	st, raw := f.admin.do("POST", path, nil)
	var res struct {
		OK       bool   `json:"ok"`
		UpToDate bool   `json:"up_to_date"`
		Message  string `json:"message"`
	}
	json.Unmarshal(raw, &res)
	if st != 200 || !res.OK || !res.UpToDate || res.Message == "" {
		t.Fatalf("current device: %d %s", st, raw)
	}
	ask(t, f.admin, "POST", path+"?force=1", nil)

	// A digest older than a day is unknown: the device may have been updated
	// by other means, so the update asks for its signature again.
	if _, err := f.s.db.Exec(`UPDATE agents SET binary_sha256_at = ? WHERE id = ?`, time.Now().Add(-25*time.Hour).Unix(), a.ID()); err != nil {
		t.Fatal(err)
	}
	ask(t, f.admin, "POST", path, nil)
	if st, raw := f.admin.do("POST", "/api/agents/update-batch", map[string]any{"agent_ids": []string{a.ID()}}); st != 428 {
		t.Fatalf("batch with a stale digest = %d %s, want 428", st, raw)
	}
	if res, raw := updateAll(t, f); len(res.SignedGroups) != 1 {
		t.Fatalf("update-all with a stale digest = %s, want the device grouped", raw)
	}
}
