package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/translog"
)

// ---- a fake device that holds a log head the way a real one does ----

// logAgent enrolls with a chosen hello, records every protected request it is
// sent, and answers each with Envelope.Log set to the size of the head that
// request carried, which is what the real agent does.
type logAgent struct {
	t    *testing.T
	raw  *rawAgent
	key  string
	mu   sync.Mutex
	seen []protocol.Envelope
}

func (f *signFixture) addLogAgent(name string, hello protocol.Hello) *logAgent {
	f.t.Helper()
	var tok struct{ Token string }
	f.admin.mustJSON("POST", "/api/enroll", map[string]any{"name": name, "uses": 1}, &tok)
	ws, _, err := websocket.DefaultDialer.Dial(wsURL(f.ts)+"/ws/agent", http.Header{"X-Enroll-Token": []string{tok.Token}})
	if err != nil {
		f.t.Fatal(err)
	}
	hello.Hostname, hello.OS, hello.Platform, hello.Arch, hello.Version, hello.ProtocolVersion = name, "linux", "Test", "amd64", "test", protocol.Version
	if err := ws.WriteJSON(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(hello)}); err != nil {
		f.t.Fatal(err)
	}
	var env protocol.Envelope
	if err := ws.ReadJSON(&env); err != nil || env.T != "welcome" {
		f.t.Fatalf("welcome: %v %s", err, env.T)
	}
	var wl struct {
		AgentID string `json:"agent_id"`
	}
	json.Unmarshal(env.D, &wl)
	f.t.Cleanup(func() { ws.Close() })
	a := &logAgent{t: f.t, raw: &rawAgent{ws: ws, id: wl.AgentID}, key: f.logKey()}
	go a.loop()
	waitFor(f.t, "agent online", func() bool { return f.s.hub.IsOnline(wl.AgentID) })
	return a
}

func (f *signFixture) logKey() string { return f.s.tlog.VerifierKey() }

func (a *logAgent) loop() {
	for {
		var env protocol.Envelope
		if err := a.raw.ws.ReadJSON(&env); err != nil {
			return
		}
		if env.ID == "" || env.T == protocol.ReqPing {
			continue
		}
		reply := protocol.Envelope{T: protocol.TypeReply, ID: env.ID}
		if env.A != nil && env.A.L != nil {
			a.mu.Lock()
			a.seen = append(a.seen, env)
			a.mu.Unlock()
			if tree, err := translog.ParseHead(a.key, mustB64(env.A.L.Head)); err == nil {
				reply.Log = tree.N
			}
		}
		if env.T == protocol.ReqScriptRun {
			var sr protocol.ScriptRun
			json.Unmarshal(env.D, &sr)
			reply.D = protocol.Must(protocol.ScriptResult{RunID: sr.RunID})
		}
		a.raw.ws.WriteJSON(reply)
	}
}

func mustB64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

func (a *logAgent) wait(n int) []protocol.Envelope {
	a.t.Helper()
	var got []protocol.Envelope
	waitFor(a.t, "protected requests with a log proof", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		got = append([]protocol.Envelope(nil), a.seen...)
		return len(got) >= n
	})
	return got
}

type logHead struct {
	Size int64  `json:"size"`
	Hash string `json:"hash"`
	Key  string `json:"key"`
	Note string `json:"note"`
}

func getHead(t *testing.T, b *browser) (logHead, tlog.Tree) {
	t.Helper()
	var h logHead
	b.mustJSON("GET", "/api/log/head", nil, &h)
	hash, err := tlog.ParseHash(h.Hash)
	if err != nil {
		t.Fatal(err)
	}
	return h, tlog.Tree{N: h.Size, Hash: hash}
}

// checkProof is what a device does with L: verify the head against the pinned
// key, the manifest's inclusion in it, and (when old is given) that the head
// extends old.
func checkProof(t *testing.T, key string, auth *protocol.ActionAuth, old *tlog.Tree) tlog.Tree {
	t.Helper()
	l := auth.L
	if l == nil {
		t.Fatal("the request carries no log proof")
	}
	tree, err := translog.ParseHead(key, mustB64(l.Head))
	if err != nil {
		t.Fatalf("head does not verify against the log key: %v", err)
	}
	leaf, err := actionauth.ManifestLeaf(auth)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := translog.DecodeProof(l.Proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := translog.CheckInclusion(tree, l.Index, leaf, tlog.RecordProof(proof)); err != nil {
		t.Fatalf("inclusion proof for leaf %d: %v", l.Index, err)
	}
	if old != nil {
		if l.From != old.N {
			t.Fatalf("consistency proof starts from %d, want %d", l.From, old.N)
		}
		cons, err := translog.DecodeProof(l.Consistency)
		if err != nil {
			t.Fatal(err)
		}
		if err := translog.CheckConsistency(*old, tree, tlog.TreeProof(cons)); err != nil {
			t.Fatalf("consistency proof from %d: %v", old.N, err)
		}
	} else if l.From != 0 || len(l.Consistency) != 0 {
		t.Fatalf("unexpected consistency proof from %d", l.From)
	}
	return tree
}

type entry struct {
	Index int64  `json:"index"`
	Kind  string `json:"kind"`
	Data  string `json:"data"`
	TS    int64  `json:"ts"`
}

func TestSignedRunReachesTheDeviceWithALogProof(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	head0, tree0 := getHead(t, f.admin)
	if head0.Key != f.logKey() {
		t.Fatalf("head key %q, server key %q", head0.Key, f.logKey())
	}
	ag := f.addLogAgent("box1", protocol.Hello{LogSize: head0.Size})

	run := func(body string) {
		t.Helper()
		if st, out := signedCall(t, f.admin, f.ka, "POST", "/api/agents/"+ag.raw.id+"/run", map[string]any{"language": "bash", "body": body}); st != 200 {
			t.Fatalf("signed run = %d %s", st, out)
		}
	}
	run("echo one")
	first := ag.wait(1)[0]
	if first.A.L.Index <= 0 {
		t.Fatalf("the manifest's leaf index = %d, want a leaf after the bundle and audit rows", first.A.L.Index)
	}
	tree1 := checkProof(t, head0.Key, first.A, &tree0)
	if tree1.N <= head0.Size {
		t.Fatalf("head %d did not grow past the device's %d", tree1.N, head0.Size)
	}

	// The reply carried Log: tree1.N, so the next proof starts there.
	waitFor(t, "hub to learn the device's log size", func() bool {
		ac, ok := f.s.hub.get(ag.raw.id)
		return ok && ac.logSize.Load() == tree1.N
	})
	run("echo two")
	second := ag.wait(2)[1]
	checkProof(t, head0.Key, second.A, &tree1)
	if second.A.L.Index == first.A.L.Index {
		t.Fatal("two signed runs share one leaf")
	}

	// The audit row of the run is a leaf too, and the leaf decodes to the row.
	var id, idx, ts int64
	var user, ip, action, target, details string
	if err := f.s.db.QueryRow(`SELECT id, ts, user, ip, action, target, details, log_index FROM audit WHERE action = 'action.sign' ORDER BY id DESC LIMIT 1`).
		Scan(&id, &ts, &user, &ip, &action, &target, &details, &idx); err != nil {
		t.Fatal(err)
	}
	if idx < 0 {
		t.Fatal("the audit row has no log_index")
	}
	var e entry
	f.admin.mustJSON("GET", "/api/log/entries/"+strconv.FormatInt(idx, 10), nil, &e)
	var leaf map[string]any
	if err := json.Unmarshal(mustB64(e.Data), &leaf); err != nil {
		t.Fatal(err)
	}
	if e.Kind != "audit" || leaf["kind"] != "audit" || int64(leaf["id"].(float64)) != id || int64(leaf["ts"].(float64)) != ts ||
		leaf["user"] != user || leaf["ip"] != ip || leaf["action"] != action || leaf["target"] != target || leaf["details"] != details {
		t.Fatalf("leaf %d = %s, want audit row %d (%s %s)", idx, mustB64(e.Data), id, action, target)
	}
	// and the audit listing says so
	var rows []struct {
		ID       int64 `json:"id"`
		LogIndex int64 `json:"log_index"`
	}
	f.admin.mustJSON("GET", "/api/audit?limit=500", nil, &rows)
	found := false
	for _, r := range rows {
		if r.ID == id {
			found = true
			if r.LogIndex != idx {
				t.Fatalf("audit listing log_index = %d, want %d", r.LogIndex, idx)
			}
		}
	}
	if !found {
		t.Fatal("the audit row is missing from the listing")
	}
}

func TestStandingApprovalDispatchCarriesItsLeaf(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	ag := f.addAgent("box1")
	var sc Script
	f.admin.mustJSON("POST", "/api/scripts", Script{Name: "hello", Language: "bash", Body: "echo a", TimeoutSec: 30}, &sc)
	var task Task
	f.admin.mustJSON("POST", "/api/tasks", map[string]any{"name": "nightly", "kind": "script", "script_id": sc.ID,
		"targets": Targets{All: true}, "schedule": "", "enabled": true}, &task)
	tid := strconv.FormatInt(task.ID, 10)
	if st, out := signedCall(t, f.admin, f.ka, "POST", "/api/approvals/objects/task/"+tid+"/sign", nil); st != 200 {
		t.Fatalf("sign = %d %s", st, out)
	}
	var stored int64
	if err := f.s.db.QueryRow(`SELECT log_index FROM approvals WHERE object_type = 'task'`).Scan(&stored); err != nil || stored < 0 {
		t.Fatalf("approvals.log_index = %d (%v), want the leaf", stored, err)
	}
	f.admin.mustJSON("POST", "/api/tasks/"+tid+"/run", nil, nil)
	got := ag.wait(protocol.ReqScriptRun, 1)[0]
	if got.Env.A == nil || got.Env.A.L == nil || got.Env.A.L.Index != stored {
		t.Fatalf("the dispatch carries A = %+v, want L index %d", got.Env.A, stored)
	}
	held := checkProof(t, f.logKey(), got.Env.A, nil)

	// A row from before the log is logged on its first dispatch, so devices
	// that require proofs keep running it, and the leaf is remembered.
	f.s.db.Exec(`UPDATE approvals SET log_index = -1`)
	f.admin.mustJSON("POST", "/api/tasks/"+tid+"/run", nil, nil)
	got = ag.wait(protocol.ReqScriptRun, 2)[1]
	if got.Env.A == nil || got.Env.A.L == nil || !got.Dec.Verified {
		t.Fatalf("an approval stored before the log: A=%+v decision=%+v", got.Env.A, got.Dec)
	}
	checkProof(t, f.logKey(), got.Env.A, &held)
	var backfilled int64
	if err := f.s.db.QueryRow(`SELECT log_index FROM approvals WHERE object_type = 'task'`).Scan(&backfilled); err != nil || backfilled != got.Env.A.L.Index {
		t.Fatalf("approvals.log_index = %d (%v), want the backfilled leaf %d", backfilled, err, got.Env.A.L.Index)
	}
}

func TestBundleActivationIsALeaf(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	row, err := f.s.db.currentTrust(trustOrg)
	if err != nil || row == nil {
		t.Fatal("no bundle in force")
	}
	if b, _ := actionauth.ParseBundle(row.Bundle); b.LogKey != f.logKey() {
		t.Fatalf("the composed bundle pins log_key %q, want %q", b.LogKey, f.logKey())
	}
	head, _ := getHead(t, f.admin)
	var found *entry
	for i := int64(0); i < head.Size && found == nil; i++ {
		var e entry
		f.admin.mustJSON("GET", "/api/log/entries/"+strconv.FormatInt(i, 10), nil, &e)
		if e.Kind == "bundle" {
			found = &e
		}
	}
	if found == nil {
		t.Fatal("activation left no bundle leaf")
	}
	var leaf struct {
		Kind   string `json:"kind"`
		Org    string `json:"org"`
		Epoch  int64  `json:"epoch"`
		Bundle string `json:"bundle"`
	}
	json.Unmarshal(mustB64(found.Data), &leaf)
	if leaf.Kind != "bundle" || leaf.Org != trustOrg || leaf.Epoch != 1 || leaf.Bundle != actionauth.EncodeB64(row.Bundle) {
		t.Fatalf("bundle leaf = %s", mustB64(found.Data))
	}
}

func TestLogEndpointsAndSessions(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	anon := &browser{t: t, c: &http.Client{}, base: f.ts.URL}
	head, _ := getHead(t, anon)
	if head.Size < 2 || head.Key == "" || head.Note == "" {
		t.Fatalf("head = %+v", head)
	}
	if _, err := translog.ParseHead(head.Key, mustB64(head.Note)); err != nil {
		t.Fatalf("the served head does not verify: %v", err)
	}
	var pr struct {
		Size  int64    `json:"size"`
		Index int64    `json:"index"`
		Proof []string `json:"proof"`
		Note  string   `json:"note"`
	}
	anon.mustJSON("GET", "/api/log/proof?index=0", nil, &pr)
	if pr.Index != 0 || pr.Size < head.Size || len(pr.Proof) == 0 || pr.Note == "" {
		t.Fatalf("proof = %+v", pr)
	}
	var cr struct {
		From  int64    `json:"from"`
		To    int64    `json:"to"`
		Proof []string `json:"proof"`
	}
	anon.mustJSON("GET", "/api/log/consistency?from=1", nil, &cr)
	if cr.From != 1 || cr.To < head.Size {
		t.Fatalf("consistency = %+v", cr)
	}
	for _, p := range []string{"/api/log/proof?index=-1", "/api/log/proof?index=x", "/api/log/consistency?from=0", "/api/log/consistency?from=2&to=1"} {
		if st, _ := anon.do("GET", p, nil); st != 400 {
			t.Fatalf("GET %s = %d, want 400", p, st)
		}
	}
	if st, _ := anon.do("GET", "/api/log/proof?index=99999999", nil); st != 404 {
		t.Fatalf("a leaf past the end = %d, want 404", st)
	}
	// leaf content needs an administrator
	if st, _ := anon.do("GET", "/api/log/entries/0", nil); st != 401 {
		t.Fatalf("entries without a session = %d, want 401", st)
	}
	if st, _ := f.bob.do("GET", "/api/log/entries/0", nil); st != 403 {
		t.Fatalf("entries as a technician = %d, want 403", st)
	}
	if st, _ := f.admin.do("GET", "/api/log/entries/0", nil); st != 200 {
		t.Fatalf("entries as an administrator = %d, want 200", st)
	}
	if st, _ := f.admin.do("GET", "/api/log/entries/99999999", nil); st != 404 {
		t.Fatalf("a missing entry = %d, want 404", st)
	}
}

func TestBundleLogKeyValidation(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	own := f.logKey()
	in := func(extra map[string]any) map[string]any {
		m := map[string]any{"mode": "enforce", "signers": []any{signerIn("admin", f.ka)},
			"recovery": []any{map[string]string{"id": f.rk.ID, "pub": f.rk.Entry().Pub}}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// the server always pins its own key, and carries the policy bit
	st, body, p := propose(t, f.admin, in(map[string]any{"require_log_proof": true}))
	if st != 201 {
		t.Fatalf("propose = %d %s", st, body)
	}
	if b, err := actionauth.ParseBundle(p.Bundle); err != nil || b.LogKey != own || !b.Policy.RequireLogProof {
		t.Fatalf("composed bundle (%v): log_key %q require_log_proof %v", err, b.LogKey, b.Policy.RequireLogProof)
	}
	st, body, p = propose(t, f.admin, in(map[string]any{"log_key": own}))
	if st != 201 {
		t.Fatalf("a proposal naming the server's own key = %d %s", st, body)
	}
	if b, _ := actionauth.ParseBundle(p.Bundle); b.LogKey != own || b.Policy.RequireLogProof {
		t.Fatalf("composed bundle: log_key %q require_log_proof %v", b.LogKey, b.Policy.RequireLogProof)
	}

	// another server's key is refused, naming both
	_, foreign, err := note.GenerateKey(rand.Reader, "someone-elses-log")
	if err != nil {
		t.Fatal(err)
	}
	st, body, _ = propose(t, f.admin, in(map[string]any{"log_key": foreign, "require_log_proof": true}))
	if st != 400 || !strings.Contains(body, foreign) || !strings.Contains(body, own) {
		t.Fatalf("a foreign log key = %d %s, want a 400 naming both keys", st, body)
	}

	// require_log_proof without any key can only arrive as a stored proposal
	// (this server always adds its key); activation must still refuse it.
	raw, _, err := f.s.buildTrustBundle(trustOrg, trustProposalIn{Mode: "enforce", Signers: []trustSignerIn{{Owner: "admin", CredentialIDs: []string{f.ka.Credential().ID}}},
		Recovery: []trustRecoveryIn{{ID: f.rk.ID, Pub: f.rk.Entry().Pub}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	delete(m, "log_key")
	m["policy"].(map[string]any)["require_log_proof"] = true
	bad, _ := json.Marshal(m)
	bad, _ = actionauth.CanonicalizeJSON(bad)
	if _, err := f.s.db.Exec(`INSERT INTO trust_proposals(id, org_id, epoch, bundle, sigs, recovery_sigs, created_by, created_at, expires_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		"tp_nokey", trustOrg, 1, bad, "[]", "[]", "admin", now(), now()+600); err != nil {
		t.Fatal(err)
	}
	st2, out := f.admin.do("POST", "/api/trust/proposals/tp_nokey/sign", map[string]any{"assertion": protocol.Assertion{}})
	if st2 != 400 || !strings.Contains(string(out), "require_log_proof") {
		t.Fatalf("activating require_log_proof without a log key = %d %s", st2, out)
	}
	// ParseBundle itself refuses it now, so devices and the offline signer
	// never pin such a bundle either.
	if _, err := actionauth.ParseBundle(bad); err == nil {
		t.Fatal("ParseBundle accepted require_log_proof with no log_key")
	}
}

func TestAuditRowSurvivesAFailedLogAppend(t *testing.T) {
	s, _, _ := newTestServer(t)
	real := s.db.logAppend
	s.db.logAppend = func(string, []byte) (int64, error) { return -1, errors.New("disk full") }
	s.db.Audit("admin", "127.0.0.1", "test.failed_append", "x", "details")
	s.db.logAppend = real
	var idx int64
	if err := s.db.QueryRow(`SELECT log_index FROM audit WHERE action = 'test.failed_append'`).Scan(&idx); err != nil {
		t.Fatalf("the audit row was lost: %v", err)
	}
	if idx != -1 {
		t.Fatalf("log_index = %d, want -1", idx)
	}
	s.db.Audit("admin", "127.0.0.1", "test.ok_append", "x", "details")
	if err := s.db.QueryRow(`SELECT log_index FROM audit WHERE action = 'test.ok_append'`).Scan(&idx); err != nil || idx < 0 {
		t.Fatalf("a healthy append gave log_index %d (%v)", idx, err)
	}
	// concurrent audit rows neither deadlock the single connection nor lose leaves
	var wg sync.WaitGroup
	before, _, _ := s.tlog.Head()
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.db.Audit("admin", "ip", "test.concurrent", "x", nil) }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("concurrent audit writes deadlocked")
	}
	after, _, _ := s.tlog.Head()
	if after.N-before.N != 20 {
		t.Fatalf("20 audit rows grew the log by %d", after.N-before.N)
	}
}

func TestExecutedHeadIsStoredFromHelloAndInventory(t *testing.T) {
	head := func(s string) string { d := sha256.Sum256([]byte(s)); return base64.StdEncoding.EncodeToString(d[:]) }
	h1, h2 := head("one"), head("two")
	f := newSignFixture(t, "", 1, 10)
	ag := f.addLogAgent("box1", protocol.Hello{ExecutedHead: h1})
	read := func() string {
		var h string
		f.s.db.QueryRow(`SELECT executed_head FROM agents WHERE id = ?`, ag.raw.id).Scan(&h)
		return h
	}
	waitFor(t, "executed head from hello", func() bool { return read() == h1 })
	ag.raw.ws.WriteJSON(protocol.Envelope{T: protocol.TypeInventory, D: protocol.Must(protocol.Inventory{Hostname: "box1", ExecutedHead: h2})})
	waitFor(t, "executed head from inventory", func() bool { return read() == h2 })
}
