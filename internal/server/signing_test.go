package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- a fake agent that checks what it is sent the way a real one does ----

// sigAgent answers requests after running them through actionauth.Verifier
// against the organization's current bundle, and records every decision.
type sigAgent struct {
	t     *testing.T
	s     *Server
	raw   *rawAgent
	mu    sync.Mutex
	seen  []sigSeen
	nonce *actionauth.MemoryNonceStore
}

type sigSeen struct {
	Env protocol.Envelope
	Dec actionauth.Decision
}

func (a *sigAgent) ID() string { return a.raw.id }

func (a *sigAgent) verifier() *actionauth.Verifier {
	row, _ := a.s.db.currentTrust(trustOrg)
	v := &actionauth.Verifier{AgentID: a.raw.id, Nonces: a.nonce}
	if row != nil {
		v.Bundle, _ = actionauth.ParseBundle(row.Bundle)
	}
	return v
}

func (a *sigAgent) loop() {
	for {
		var env protocol.Envelope
		if err := a.raw.ws.ReadJSON(&env); err != nil {
			return
		}
		if env.T == protocol.ReqAgentConfig || env.T == protocol.ReqTrustUpdate {
			if env.ID != "" {
				a.reply(env.ID, nil)
			}
			continue
		}
		dec := a.verifier().Check(env.T, env.D, env.A)
		a.mu.Lock()
		a.seen = append(a.seen, sigSeen{env, dec})
		a.mu.Unlock()
		if env.ID == "" {
			continue
		}
		switch env.T {
		case protocol.ReqScriptRun:
			var sr protocol.ScriptRun
			json.Unmarshal(dec.Payload, &sr)
			a.reply(env.ID, protocol.ScriptResult{RunID: sr.RunID, ExitCode: 0})
		case protocol.ReqFsRead:
			a.reply(env.ID, protocol.FsReadResult{EOF: true})
		default:
			a.reply(env.ID, map[string]any{})
		}
	}
}

func (a *sigAgent) reply(id string, v any) {
	env := protocol.Envelope{T: protocol.TypeReply, ID: id}
	if v != nil {
		env.D = protocol.Must(v)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.raw.ws.WriteJSON(env)
}

func (a *sigAgent) requests(typ string) []sigSeen {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []sigSeen
	for _, x := range a.seen {
		if x.Env.T == typ {
			out = append(out, x)
		}
	}
	return out
}

// wait returns the requests of a type once at least n have arrived.
func (a *sigAgent) wait(typ string, n int) []sigSeen {
	a.t.Helper()
	var got []sigSeen
	waitFor(a.t, "agent to receive "+typ, func() bool { got = a.requests(typ); return len(got) >= n })
	return got
}

// ---- fixture ----

type signFixture struct {
	t     *testing.T
	s     *Server
	ts    *httptest.Server
	admin *browser
	bob   *browser
	ka    *authtest.Key
	kb    *authtest.Key
	rk    *authtest.RecoveryKey
}

// newSignFixture starts a server with two operators holding a key each and,
// unless mode is empty, an active bundle for the default organization.
func newSignFixture(t *testing.T, mode string, high, bulk int) *signFixture {
	t.Helper()
	s, ts, admin := newTestServerWith(t, Config{WebAuthnRPID: authtest.RPID, WebAuthnOrigins: []string{authtest.Origin}})
	admin.mustJSON("POST", "/api/users", map[string]string{"username": "bob", "password": "password123", "role": "tech"}, nil)
	bob := newBrowser(t, ts)
	bob.mustJSON("POST", "/api/auth/login", map[string]string{"username": "bob", "password": "password123"}, nil)
	f := &signFixture{t: t, s: s, ts: ts, admin: admin, bob: bob,
		ka: authtest.NewKey("admin", actionauth.AlgES256), kb: authtest.NewKey("bob", actionauth.AlgEdDSA), rk: authtest.NewRecoveryKey("")}
	registerKey(t, admin, f.ka)
	registerKey(t, bob, f.kb)
	if mode != "" {
		activate(t, admin, map[string]any{"mode": mode, "high_threshold": high, "bulk_limit": bulk,
			"signers":  []any{signerIn("admin", f.ka), signerIn("bob", f.kb)},
			"recovery": []any{map[string]string{"id": f.rk.ID, "pub": f.rk.Entry().Pub}}}, f.ka)
	}
	return f
}

func (f *signFixture) addAgent(name string) *sigAgent {
	f.t.Helper()
	var tok struct{ Token string }
	f.admin.mustJSON("POST", "/api/enroll", map[string]any{"name": name, "uses": 1}, &tok)
	ra := dialAgentAs(f.t, f.ts, http.Header{"X-Enroll-Token": []string{tok.Token}}, name, "linux")
	a := &sigAgent{t: f.t, s: f.s, raw: ra, nonce: actionauth.NewMemoryNonceStore()}
	go a.loop()
	waitFor(f.t, "agent online", func() bool { return f.s.hub.IsOnline(ra.id) })
	return a
}

// ---- the browser side of the 428 flow ----

func (b *browser) doHdr(method, path string, body any, hdr map[string]string) (int, []byte) {
	b.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		bs, _ := json.Marshal(body)
		rd = bytes.NewReader(bs)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, b.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "fetch")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

type challenge struct {
	Error            string   `json:"error"`
	ManifestID       string   `json:"manifest_id"`
	Manifest         string   `json:"manifest"`
	Summary          string   `json:"summary"`
	Required         bool     `json:"required"`
	RPID             string   `json:"rp_id"`
	AllowCredentials []string `json:"allow_credentials"`
	UV               string   `json:"user_verification"`
}

func (c challenge) bytes(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(c.Manifest)
	if err != nil {
		t.Fatalf("manifest is not base64url: %v", err)
	}
	return raw
}

func (c challenge) parsed(t *testing.T) *actionauth.Manifest {
	t.Helper()
	m, err := actionauth.ParseManifest(c.bytes(t))
	if err != nil {
		t.Fatalf("the manifest the server built does not parse: %v", err)
	}
	return m
}

func authHeader(id string, a protocol.Assertion) map[string]string {
	raw, _ := json.Marshal(map[string]any{"manifest_id": id, "assertion": a})
	return map[string]string{headerActionAuth: base64.RawURLEncoding.EncodeToString(raw)}
}

func (c challenge) signedBy(t *testing.T, k *authtest.Key) map[string]string {
	return authHeader(c.ManifestID, k.Sign(c.bytes(t), authtest.SignOpts{}))
}

// ask sends a request without a signature and expects the 428.
func ask(t *testing.T, b *browser, method, path string, body any) challenge {
	t.Helper()
	st, data := b.do(method, path, body)
	if st != 428 {
		t.Fatalf("%s %s = %d %s, want 428", method, path, st, data)
	}
	var c challenge
	if err := json.Unmarshal(data, &c); err != nil || c.ManifestID == "" || c.Manifest == "" {
		t.Fatalf("428 body = %s (%v)", data, err)
	}
	return c
}

// signedCall is what the console's request() does: ask, sign, repeat.
func signedCall(t *testing.T, b *browser, k *authtest.Key, method, path string, body any) (int, []byte) {
	t.Helper()
	c := ask(t, b, method, path, body)
	return b.doHdr(method, path, body, c.signedBy(t, k))
}

// ---- tests ----

func TestSignedPowerFlow(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	ag := f.addAgent("box1")
	path := "/api/agents/" + ag.ID() + "/power"

	c := ask(t, f.admin, "POST", path, map[string]any{"action": "reboot"})
	if !c.Required || c.RPID != authtest.RPID || c.UV != "preferred" || c.Summary == "" {
		t.Fatalf("challenge = %+v", c)
	}
	if len(c.AllowCredentials) != 1 || c.AllowCredentials[0] != f.ka.Credential().ID {
		t.Fatalf("allow_credentials = %v, want only the caller's own key", c.AllowCredentials)
	}
	m := c.parsed(t)
	if m.Kind != actionauth.KindAction || m.Op != protocol.ReqPower || m.Org != trustOrg || m.Issuer != "admin" ||
		len(m.Targets) != 1 || m.Targets[0] != ag.ID() || m.Exp-m.IAT != 300 || m.ID != c.ManifestID {
		t.Fatalf("manifest = %+v", m)
	}
	var pl protocol.Power
	json.Unmarshal(m.Payload, &pl)
	if pl.Action != "reboot" {
		t.Fatalf("payload = %s", m.Payload)
	}
	if got := ag.requests(protocol.ReqPower); len(got) != 0 {
		t.Fatal("the agent was sent a request before anything was signed")
	}

	// sign and repeat: dispatched, with the signature attached
	hdr := c.signedBy(t, f.ka)
	if st, body := f.admin.doHdr("POST", path, map[string]any{"action": "reboot"}, hdr); st != 200 {
		t.Fatalf("signed retry = %d %s", st, body)
	}
	got := ag.wait(protocol.ReqPower, 1)
	if got[0].Env.A == nil || !got[0].Dec.Verified || !got[0].Dec.Allow || got[0].Dec.ManifestID != c.ManifestID {
		t.Fatalf("agent decision = %+v (A=%v)", got[0].Dec, got[0].Env.A)
	}
	if got[0].Env.A.M != c.Manifest {
		t.Fatal("the agent was sent a manifest other than the one that was signed")
	}
	if len(got[0].Dec.Signers) != 1 || got[0].Dec.Signers[0] != "admin" {
		t.Fatalf("signers = %v", got[0].Dec.Signers)
	}

	// the manifest is consumed: replaying the same header is refused
	if st, _ := f.admin.doHdr("POST", path, map[string]any{"action": "reboot"}, hdr); st != 410 {
		t.Fatalf("replayed header = %d, want 410", st)
	}
	if n := len(ag.requests(protocol.ReqPower)); n != 1 {
		t.Fatalf("agent got %d power requests, want 1", n)
	}

	// a retry that no longer matches what was signed is refused
	c2 := ask(t, f.admin, "POST", path, map[string]any{"action": "reboot"})
	if st, body := f.admin.doHdr("POST", path, map[string]any{"action": "shutdown"}, c2.signedBy(t, f.ka)); st != 409 {
		t.Fatalf("mismatched retry = %d %s, want 409", st, body)
	}
	// ... and so is a different delay: the whole payload is bound
	if st, _ := f.admin.doHdr("POST", path, map[string]any{"action": "reboot", "delay_sec": 5}, c2.signedBy(t, f.ka)); st != 409 {
		t.Fatalf("retry with another delay = %d, want 409", st)
	}

	// someone else's manifest, an expired one, a signature that is not in the bundle
	c3 := ask(t, f.admin, "POST", path, map[string]any{"action": "reboot"})
	if st, _ := f.bob.doHdr("POST", path, map[string]any{"action": "reboot"}, c3.signedBy(t, f.kb)); st != 410 {
		t.Fatalf("another user's manifest = %d, want 410", st)
	}
	stranger := authtest.NewKey("stranger", actionauth.AlgES256)
	st, body := f.admin.doHdr("POST", path, map[string]any{"action": "reboot"}, c3.signedBy(t, stranger))
	if st != 400 || !strings.Contains(string(body), "not in the trust bundle") {
		t.Fatalf("unknown key = %d %s", st, body)
	}
	f.s.signing.mu.Lock()
	f.s.signing.pending[c3.ManifestID].expiresAt = now() - 1
	f.s.signing.mu.Unlock()
	if st, _ := f.admin.doHdr("POST", path, map[string]any{"action": "reboot"}, c3.signedBy(t, f.ka)); st != 410 {
		t.Fatalf("expired manifest = %d, want 410", st)
	}
	if st, _ := f.admin.doHdr("POST", path, map[string]any{"action": "reboot"}, authHeader("nope", f.ka.Sign([]byte("x"), authtest.SignOpts{}))); st != 410 {
		t.Fatalf("unknown manifest id = %d, want 410", st)
	}

	// enforce: declining to sign is not an option
	if st, body := f.admin.doHdr("POST", path, map[string]any{"action": "reboot"}, map[string]string{headerActionAuth: "skip"}); st != 403 || !strings.Contains(string(body), "signature required") {
		t.Fatalf("skip in enforce = %d %s", st, body)
	}
	if n := len(ag.requests(protocol.ReqPower)); n != 1 {
		t.Fatalf("agent got %d power requests, want 1", n)
	}
	// a viewer-less check of the audit trail: the signature is on record
	var n int
	f.s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'action.sign'`).Scan(&n)
	if n == 0 {
		t.Fatal("the signature was not audited")
	}
}

func TestSignedActionAuditModeAndNoBundle(t *testing.T) {
	// audit: the operator may decline; the action runs and the agent reports it
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	ag := f.addAgent("box1")
	path := "/api/agents/" + ag.ID() + "/power"
	c := ask(t, f.admin, "POST", path, map[string]any{"action": "lock"})
	if c.Required {
		t.Fatal("audit mode must say the signature is optional")
	}
	if st, body := f.admin.doHdr("POST", path, map[string]any{"action": "lock"}, map[string]string{headerActionAuth: "skip"}); st != 200 {
		t.Fatalf("skip in audit = %d %s", st, body)
	}
	got := ag.wait(protocol.ReqPower, 1)
	if got[0].Env.A != nil || got[0].Dec.Verified || got[0].Dec.Err == nil || !got[0].Dec.Allow {
		t.Fatalf("unsigned in audit: A=%v decision=%+v", got[0].Env.A, got[0].Dec)
	}

	// no bundle at all: exactly as before, no 428 and nothing attached
	g := newSignFixture(t, "", 1, 10)
	ag2 := g.addAgent("box2")
	if st, body := g.admin.do("POST", "/api/agents/"+ag2.ID()+"/power", map[string]any{"action": "lock"}); st != 200 {
		t.Fatalf("no bundle = %d %s", st, body)
	}
	if got := ag2.wait(protocol.ReqPower, 1); got[0].Env.A != nil {
		t.Fatal("an unsigned org got an authorization attached")
	}
	var gr struct {
		Required *bool `json:"required"`
	}
	g.admin.mustJSON("POST", "/api/agents/"+ag2.ID()+"/grant", map[string]any{"ops": []string{"fs.list"}}, &gr)
	if gr.Required == nil || *gr.Required {
		t.Fatalf("grant without a bundle = %+v, want required:false", gr)
	}
}

// Two approvers, one manifest for several devices, a run_id per device.
func TestSignedThresholdAndMultiAgentRun(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 2, 1)
	a1, a2 := f.addAgent("box1"), f.addAgent("box2")
	body := map[string]any{"agent_ids": []string{a1.ID(), a2.ID()}, "language": "bash", "body": "echo hi", "args": []string{"x"}}

	c := ask(t, f.admin, "POST", "/api/scripts/run", body)
	m := c.parsed(t)
	if m.Op != protocol.ReqScriptRun || len(m.Targets) != 2 || m.Exp-m.IAT != 600 {
		t.Fatalf("manifest = %+v", m)
	}
	var pl map[string]any
	json.Unmarshal(m.Payload, &pl)
	if _, has := pl["run_id"]; has || pl["body"] != "echo hi" || pl["language"] != "bash" {
		t.Fatalf("payload = %s: one manifest serves every device, so it carries no run_id", m.Payload)
	}

	st, data := f.admin.doHdr("POST", "/api/scripts/run", body, c.signedBy(t, f.ka))
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
	if len(a1.requests(protocol.ReqScriptRun))+len(a2.requests(protocol.ReqScriptRun)) != 0 {
		t.Fatal("dispatched before the threshold was met")
	}

	var mine, theirs []struct {
		ManifestID string `json:"manifest_id"`
		Manifest   string `json:"manifest"`
		Have       int    `json:"have"`
		Need       int    `json:"need"`
		CreatedBy  string `json:"created_by"`
		ExpiresAt  int64  `json:"expires_at"`
		Summary    string `json:"summary"`
	}
	f.admin.mustJSON("GET", "/api/approvals", nil, &mine)
	f.bob.mustJSON("GET", "/api/approvals", nil, &theirs)
	if len(mine) != 0 {
		t.Fatalf("the operator who already signed sees %d approvals waiting for them", len(mine))
	}
	if len(theirs) != 1 || theirs[0].ManifestID != c.ManifestID || theirs[0].Manifest != c.Manifest || theirs[0].Have != 1 || theirs[0].Need != 2 || theirs[0].CreatedBy != "admin" || theirs[0].ExpiresAt <= now() {
		t.Fatalf("bob's queue = %+v", theirs)
	}

	// a signature that is not valid for the manifest does not count
	if st, _ := f.bob.do("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.kb.Sign([]byte("another document"), authtest.SignOpts{})}); st != 400 {
		t.Fatalf("a signature over something else = %d, want 400", st)
	}
	// the same person with a second key is still one approver
	st, data = f.admin.do("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.ka.Sign(c.bytes(t), authtest.SignOpts{})})
	if st != 202 {
		t.Fatalf("a repeat signature = %d %s, want 202", st, data)
	}

	st, data = f.bob.do("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.kb.Sign(c.bytes(t), authtest.SignOpts{})})
	if st != 200 {
		t.Fatalf("completing signature = %d %s", st, data)
	}
	var res struct {
		Runs map[string]string `json:"runs"`
	}
	json.Unmarshal(data, &res)
	if len(res.Runs) != 2 || res.Runs[a1.ID()] == "" || res.Runs[a2.ID()] == "" || res.Runs[a1.ID()] == res.Runs[a2.ID()] {
		t.Fatalf("the completing request got %s, want the handler's own response with a run per device", data)
	}
	ids := map[string]bool{}
	for _, ag := range []*sigAgent{a1, a2} {
		got := ag.wait(protocol.ReqScriptRun, 1)[0]
		if got.Env.A == nil || got.Env.A.M != c.Manifest || !got.Dec.Verified || len(got.Dec.Signers) != 2 {
			t.Fatalf("%s: A=%v decision=%+v", ag.ID(), got.Env.A, got.Dec)
		}
		var sr, sent protocol.ScriptRun
		json.Unmarshal(got.Dec.Payload, &sr)
		json.Unmarshal(got.Env.D, &sent)
		if sr.RunID == "" || sr.RunID != sent.RunID || sr.Body != "echo hi" || ids[sr.RunID] {
			t.Fatalf("%s: the agent would run %+v (envelope run_id %q)", ag.ID(), sr, sent.RunID)
		}
		ids[sr.RunID] = true
	}
	// done: nothing is left to sign and the manifest cannot be used again
	if st, _ := f.bob.do("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.kb.Sign(c.bytes(t), authtest.SignOpts{})}); st != 410 {
		t.Fatalf("re-signing a finished manifest = %d, want 410", st)
	}
}

func TestGrantsForFilesAndShell(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	ag := f.addAgent("box1")
	fsPath := "/api/agents/" + ag.ID() + "/fs?path=/"

	// enforce and no grant: refused, and the agent is not even asked
	if st, body := f.admin.do("GET", fsPath, nil); st != 403 || !strings.Contains(string(body), "signature required") {
		t.Fatalf("fs.list without a grant = %d %s", st, body)
	}
	if n := len(ag.requests(protocol.ReqFsList)); n != 0 {
		t.Fatal("the agent was asked to list files without a grant")
	}
	if st, _ := f.admin.do("POST", "/api/agents/"+ag.ID()+"/grant", map[string]any{"ops": []string{"fs.write"}}); st != 400 {
		t.Fatalf("granting an action = %d, want 400", st)
	}
	if st, _ := f.admin.do("POST", "/api/agents/"+ag.ID()+"/grant", map[string]any{"ops": []string{}}); st != 400 {
		t.Fatalf("granting nothing = %d, want 400", st)
	}

	c := ask(t, f.admin, "POST", "/api/agents/"+ag.ID()+"/grant", map[string]any{"ops": []string{"fs.read", "fs.list"}})
	m := c.parsed(t)
	if m.Kind != actionauth.KindGrant || len(m.Ops) != 2 || m.Ops[0] != "fs.list" || m.Exp-m.IAT != 900 || m.Op != "" {
		t.Fatalf("grant manifest = %+v", m)
	}
	var gr struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	st, data := f.admin.doHdr("POST", "/api/agents/"+ag.ID()+"/grant", map[string]any{"ops": []string{"fs.read", "fs.list"}}, c.signedBy(t, f.ka))
	json.Unmarshal(data, &gr)
	if st != 200 || gr.ExpiresAt != m.Exp {
		t.Fatalf("grant = %d %s", st, data)
	}

	// the grant is attached to every list and read, until it expires
	for i := 0; i < 2; i++ {
		if st, body := f.admin.do("GET", fsPath, nil); st != 200 {
			t.Fatalf("fs.list with a grant = %d %s", st, body)
		}
	}
	if st, body := f.admin.do("GET", "/api/agents/"+ag.ID()+"/fs/download?path=/etc/hostname", nil); st != 200 {
		t.Fatalf("fs.read with a grant = %d %s", st, body)
	}
	for _, typ := range []string{protocol.ReqFsList, protocol.ReqFsRead} {
		got := ag.wait(typ, 1)
		for _, x := range got {
			if x.Env.A == nil || x.Env.A.M != c.Manifest || !x.Dec.Verified {
				t.Fatalf("%s: A=%v decision=%+v", typ, x.Env.A, x.Dec)
			}
		}
	}
	if n := len(ag.requests(protocol.ReqFsList)); n != 2 {
		t.Fatalf("the grant is reusable: %d lists, want 2", n)
	}
	// a grant is one operator's, for one device
	if st, _ := f.bob.do("GET", fsPath, nil); st != 403 {
		t.Fatalf("another operator reusing the grant = %d, want 403", st)
	}

	// the shell: no grant for shell.open, so the terminal says why instead of opening
	ws := f.dialWS(t, f.admin, "/ws/shell/"+ag.ID())
	ws.WriteJSON(map[string]any{"t": "open", "cols": 80, "rows": 24})
	var msg map[string]any
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := ws.ReadJSON(&msg); err != nil || msg["t"] != "error" || !strings.Contains(fmt.Sprint(msg["message"]), "signature required: open the session again to sign") {
		t.Fatalf("shell without a grant: %v %v", msg, err)
	}
	if n := len(ag.requests(protocol.ReqShellOpen)); n != 0 {
		t.Fatal("a shell was opened without a grant")
	}
	// with one, shell.open carries it
	gc := ask(t, f.admin, "POST", "/api/agents/"+ag.ID()+"/grant", map[string]any{"ops": []string{"shell.open"}})
	if st, body := f.admin.doHdr("POST", "/api/agents/"+ag.ID()+"/grant", map[string]any{"ops": []string{"shell.open"}}, gc.signedBy(t, f.ka)); st != 200 {
		t.Fatalf("shell grant = %d %s", st, body)
	}
	ws2 := f.dialWS(t, f.admin, "/ws/shell/"+ag.ID())
	ws2.WriteJSON(map[string]any{"t": "open", "cols": 80, "rows": 24})
	got := ag.wait(protocol.ReqShellOpen, 1)[0]
	if got.Env.A == nil || got.Env.A.M != gc.Manifest || !got.Dec.Verified {
		t.Fatalf("shell.open: A=%v decision=%+v", got.Env.A, got.Dec)
	}
}

func (f *signFixture) dialWS(t *testing.T, b *browser, path string) *websocket.Conn {
	t.Helper()
	u, _ := url.Parse(f.ts.URL)
	hdr := http.Header{}
	for _, c := range b.c.Jar.Cookies(u) {
		hdr.Add("Cookie", c.Name+"="+c.Value)
	}
	ws, resp, err := websocket.DefaultDialer.Dial(wsURL(f.ts)+path, hdr)
	if err != nil {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		t.Fatalf("dial %s: %v (%d)", path, err, code)
	}
	t.Cleanup(func() { ws.Close() })
	return ws
}

func TestStandingApprovalOfATask(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	ag := f.addAgent("box1")
	var sc Script
	f.admin.mustJSON("POST", "/api/scripts", Script{Name: "hello", Language: "bash", Body: "echo a", TimeoutSec: 30}, &sc)
	var task Task
	f.admin.mustJSON("POST", "/api/tasks", map[string]any{"name": "nightly", "kind": "script", "script_id": sc.ID, "args": []string{"-v"},
		"targets": Targets{All: true}, "schedule": "", "enabled": true}, &task)
	tid := strconv.FormatInt(task.ID, 10)

	type unsigned struct {
		Type   string `json:"type"`
		ID     any    `json:"id"`
		Name   string `json:"name"`
		Reason string `json:"reason"`
	}
	list := func() []unsigned {
		var out []unsigned
		f.admin.mustJSON("GET", "/api/approvals/unsigned?org="+trustOrg, nil, &out)
		return out
	}
	find := func(typ, id string) *unsigned {
		for _, u := range list() {
			if u.Type == typ && fmt.Sprint(u.ID) == id {
				u := u
				return &u
			}
		}
		return nil
	}
	if u := find("task", tid); u == nil || u.Reason != "missing" || u.Name != "nightly" {
		t.Fatalf("an unsigned task lists as %+v", u)
	}

	// saving never blocked on a signature; signing is its own step
	c := ask(t, f.admin, "POST", "/api/approvals/objects/task/"+tid+"/sign", nil)
	if !c.Required {
		t.Fatal("a standing approval cannot be skipped")
	}
	m := c.parsed(t)
	sum := sha256Hex("echo a")
	if m.Kind != actionauth.KindStanding || len(m.Targets) != 1 || m.Targets[0] != "*" || m.Constraints == nil ||
		m.Constraints.Op != protocol.ReqScriptRun || m.Constraints.BodySHA256 != sum || m.Constraints.Language != "bash" ||
		len(m.Constraints.Args) != 1 || m.Constraints.Args[0] != "-v" || m.Exp-m.IAT != 180*24*3600 {
		t.Fatalf("standing manifest = %+v / %+v", m, m.Constraints)
	}
	var signed struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	st, data := f.admin.doHdr("POST", "/api/approvals/objects/task/"+tid+"/sign", nil, c.signedBy(t, f.ka))
	json.Unmarshal(data, &signed)
	if st != 200 || signed.ExpiresAt != m.Exp {
		t.Fatalf("sign object = %d %s", st, data)
	}
	if u := find("task", tid); u != nil {
		t.Fatalf("a signed task still lists as %+v", u)
	}

	// an unattended run carries the stored approval, and the agent accepts it
	f.admin.mustJSON("POST", "/api/tasks/"+tid+"/run", nil, nil)
	got := ag.wait(protocol.ReqScriptRun, 1)[0]
	if got.Env.A == nil || got.Env.A.M != c.Manifest || !got.Dec.Verified || !got.Dec.Allow {
		t.Fatalf("task run: A=%v decision=%+v", got.Env.A, got.Dec)
	}
	var sr protocol.ScriptRun
	json.Unmarshal(got.Dec.Payload, &sr)
	if sr.Body != "echo a" {
		t.Fatalf("the agent would run %q", sr.Body)
	}

	// edit the script: the approval stops matching, nothing is blocked
	sc.Body = "echo b"
	f.admin.mustJSON("PUT", "/api/scripts/"+strconv.FormatInt(sc.ID, 10), sc, nil)
	if u := find("task", tid); u == nil || u.Reason != "content changed" {
		t.Fatalf("an edited task lists as %+v, want content changed", u)
	}
	f.admin.mustJSON("POST", "/api/tasks/"+tid+"/run", nil, nil)
	got = ag.wait(protocol.ReqScriptRun, 2)[1]
	if got.Env.A != nil || got.Dec.Verified || got.Dec.Err == nil || !got.Dec.Allow {
		t.Fatalf("edited task run: A=%v decision=%+v (audit mode runs it and reports it)", got.Env.A, got.Dec)
	}
	json.Unmarshal(got.Env.D, &sr)
	if sr.Body != "echo b" {
		t.Fatalf("the edited body was not sent: %q", sr.Body)
	}

	// signing again covers the new content
	if st, body := signedCall(t, f.admin, f.ka, "POST", "/api/approvals/objects/task/"+tid+"/sign", nil); st != 200 {
		t.Fatalf("re-sign = %d %s", st, body)
	}
	f.admin.mustJSON("POST", "/api/tasks/"+tid+"/run", nil, nil)
	if got = ag.wait(protocol.ReqScriptRun, 3)[2]; !got.Dec.Verified {
		t.Fatalf("re-signed task run: decision=%+v", got.Dec)
	}
	// an expired approval is reported as expired
	f.s.db.Exec(`UPDATE approvals SET expires_at = ? WHERE object_type = 'task'`, now()-1)
	if u := find("task", tid); u == nil || u.Reason != "expired" {
		t.Fatalf("an expired approval lists as %+v", u)
	}
}

// The software catalog's approval binds the FINAL generated body, per action
// and OS, so the client portal can run it with nobody signing.
func TestStandingApprovalOfACatalogItem(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	ag := f.addAgent("box1")
	it := &SoftwareCatalogItem{ID: "sw_test", Name: "Widget", InstallCmd: "apt-get install -y widget", UninstallCmd: "apt-get remove -y widget", OS: "linux"}
	if err := f.s.db.SaveSoftwareCatalogItem(it); err != nil {
		t.Fatal(err)
	}
	var todo []map[string]any
	f.admin.mustJSON("GET", "/api/approvals/unsigned?org="+trustOrg, nil, &todo)
	n := 0
	for _, u := range todo {
		if u["type"] == "catalog_item" && u["id"] == "sw_test" {
			n++
		}
	}
	// install and uninstall differ; update falls back to the install text and is covered by it
	if n != 2 {
		t.Fatalf("catalog item needs %d approvals, want 2 (install, uninstall): %v", n, todo)
	}
	for i := 0; i < 2; i++ {
		if st, body := signedCall(t, f.admin, f.ka, "POST", "/api/approvals/objects/catalog_item/sw_test/sign", nil); st != 200 {
			t.Fatalf("sign catalog item (%d) = %d %s", i, st, body)
		}
	}
	if st, _ := f.admin.do("POST", "/api/approvals/objects/catalog_item/sw_test/sign", nil); st != 200 {
		t.Fatalf("everything signed: %d", st)
	}
	run := func(body string) sigSeen {
		t.Helper()
		before := len(ag.requests(protocol.ReqScriptRun))
		if _, err := f.s.runs.Start(ag.ID(), RunRequest{Language: "bash", Body: body, Timeout: 600, Trigger: "client-portal", RunBy: "portal:install:x",
			Standing: &standingRef{Type: approvalCatalog, ID: "sw_test"}}); err != nil {
			t.Fatal(err)
		}
		return ag.wait(protocol.ReqScriptRun, before+1)[before]
	}
	if got := run(catalogBody(it, "install", false)); got.Env.A == nil || !got.Dec.Verified {
		t.Fatalf("approved install: A=%v decision=%+v", got.Env.A, got.Dec)
	}
	if got := run(catalogBody(it, "uninstall", false)); got.Env.A == nil || !got.Dec.Verified {
		t.Fatalf("approved uninstall: A=%v decision=%+v", got.Env.A, got.Dec)
	}
	if got := run(catalogBody(it, "install", false) + " --extra"); got.Env.A != nil || got.Dec.Verified {
		t.Fatalf("a body that was not approved carried an approval: %+v", got.Dec)
	}
}

func TestBaselineAuthInAgentConfig(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	ag := f.addAgent("box1")
	approved := createBaseline(t, f.admin, tBaseline{Name: "hygiene", Targets: Targets{All: true}, Enabled: true, IntervalSec: 900,
		Checks: []tCheck{firewallCheck("Firewall on")}})
	other := createBaseline(t, f.admin, tBaseline{Name: "time", Targets: Targets{All: true}, Enabled: true, IntervalSec: 900,
		Checks: []tCheck{timeSyncCheck("Time sync")}})
	key := strconv.FormatInt(approved.ID, 10)

	cfg := f.s.agentConfig(ag.ID())
	if len(cfg.Baselines) != 2 || len(cfg.BaselineAuth) != 0 {
		t.Fatalf("before any approval: %d baselines, %d approvals", len(cfg.Baselines), len(cfg.BaselineAuth))
	}
	if st, body := signedCall(t, f.admin, f.ka, "POST", "/api/approvals/objects/baseline/"+key+"/sign", nil); st != 200 {
		t.Fatalf("sign baseline = %d %s", st, body)
	}
	cfg = f.s.agentConfig(ag.ID())
	if len(cfg.BaselineAuth) != 1 || cfg.BaselineAuth[key] == nil || cfg.BaselineAuth[strconv.FormatInt(other.ID, 10)] != nil {
		t.Fatalf("baseline_auth = %v, want only baseline %s", cfg.BaselineAuth, key)
	}
	// the agent checks each spec exactly as it was delivered
	v := ag.verifier()
	specs := map[int64]json.RawMessage{}
	for _, sp := range cfg.Baselines {
		raw, _ := json.Marshal(sp)
		specs[sp.ID] = raw
	}
	if err := v.ApproveSpec(specs[approved.ID], cfg.BaselineAuth[key]); err != nil {
		t.Fatalf("the approved spec is refused: %v", err)
	}
	if err := v.ApproveSpec(specs[other.ID], cfg.BaselineAuth[key]); err == nil {
		t.Fatal("an approval covered a spec it was not signed for")
	}
	// the wire form (what the agent actually decodes) verifies too
	var wire protocol.AgentConfig
	if err := json.Unmarshal(protocol.Must(cfg), &wire); err != nil {
		t.Fatal(err)
	}
	var rawSpecs struct {
		Baselines []json.RawMessage `json:"baselines"`
	}
	json.Unmarshal(protocol.Must(cfg), &rawSpecs)
	for i, sp := range wire.Baselines {
		if sp.ID == approved.ID {
			if err := v.ApproveSpec(rawSpecs.Baselines[i], wire.BaselineAuth[key]); err != nil {
				t.Fatalf("the spec as received is refused: %v", err)
			}
		}
	}
	// an edit changes the spec: the approval is no longer sent
	putBaseline(t, f.admin, approved.ID, tBaseline{Name: "hygiene", Targets: Targets{All: true}, Enabled: true, IntervalSec: 900,
		Checks: append(checksToInput(approved.Checks), timeSyncCheck("Extra"))})
	cfg = f.s.agentConfig(ag.ID())
	if cfg.BaselineAuth[key] != nil {
		t.Fatal("a stale approval was sent with the edited baseline")
	}
	var todo []map[string]any
	f.admin.mustJSON("GET", "/api/approvals/unsigned?org="+trustOrg, nil, &todo)
	reason := ""
	for _, u := range todo {
		if u["type"] == "baseline" && fmt.Sprint(u["id"]) == key {
			reason, _ = u["reason"].(string)
		}
	}
	if reason != "content changed" {
		t.Fatalf("an edited baseline lists as %q (%v)", reason, todo)
	}
	// the operator-editable defaults can never carry approvals into a config
	f.s.db.SetSettingJSON("agent_defaults", protocol.AgentConfig{MetricsIntervalSec: 30, BaselineAuth: map[string]*protocol.ActionAuth{"9": {M: "x"}}})
	if cfg := f.s.agentConfig(ag.ID()); cfg.BaselineAuth["9"] != nil {
		t.Fatal("approvals leaked in from the settings blob")
	}
}

func TestSignedHighRiskAndRemediate(t *testing.T) {
	// agent.update is high-risk: two approvers even for one device
	f := newSignFixture(t, actionauth.ModeAudit, 2, 10)
	ag := f.addAgent("box1")
	if st, body := f.admin.do("POST", "/api/agents/"+ag.ID()+"/update", nil); st != 404 && st != 428 {
		t.Fatalf("update = %d %s (no binary installed: 404 before signing, or 428)", st, body)
	}
	if need := needSigners(mustBundle(t, f), actionauth.KindAction, protocol.ReqAgentUpdate, nil, []string{"a"}); need != 2 {
		t.Fatalf("agent.update needs %d signers, want high_threshold 2", need)
	}
	if need := needSigners(mustBundle(t, f), actionauth.KindAction, protocol.ReqPower, nil, []string{"a"}); need != 1 {
		t.Fatalf("power needs %d signers, want 1", need)
	}
}

func mustBundle(t *testing.T, f *signFixture) *actionauth.Bundle {
	t.Helper()
	row, err := f.s.db.currentTrust(trustOrg)
	if err != nil || row == nil {
		t.Fatalf("no bundle: %v", err)
	}
	b, err := actionauth.ParseBundle(row.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sha256Hex(s string) string {
	c := scriptConstraints("bash", s, nil)
	return c.BodySHA256
}

// A catalog item has one approval per action, and "Review & sign" signs them one
// at a time: each reply says how many units are still unsigned, and asking for an
// approved unit again must not ask for another key touch.
func TestSignObjectOneUnitAtATime(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 1, 10)
	f.addAgent("box1")
	it := &SoftwareCatalogItem{ID: "sw_two", Name: "Widget", InstallCmd: "apt-get install -y widget", UninstallCmd: "apt-get remove -y widget", OS: "linux"}
	if err := f.s.db.SaveSoftwareCatalogItem(it); err != nil {
		t.Fatal(err)
	}
	var todo []map[string]any
	f.admin.mustJSON("GET", "/api/approvals/unsigned?org="+trustOrg, nil, &todo)
	var purposes []string
	for _, u := range todo {
		if u["type"] == "catalog_item" && u["id"] == "sw_two" {
			purposes = append(purposes, u["purpose"].(string))
		}
	}
	if len(purposes) != 2 {
		t.Fatalf("catalog item needs %d approvals, want 2: %v", len(purposes), todo)
	}
	path := func(p string) string {
		return "/api/approvals/objects/catalog_item/sw_two/sign?org=" + trustOrg + "&purpose=" + url.QueryEscape(p)
	}
	for i, want := range []float64{1, 0} {
		st, body := signedCall(t, f.admin, f.ka, "POST", path(purposes[i]), nil)
		if st != 200 {
			t.Fatalf("sign %q = %d %s", purposes[i], st, body)
		}
		var r map[string]any
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatal(err)
		}
		if r["purpose"] != purposes[i] || r["remaining"] != want {
			t.Fatalf("sign %q replied %v, want purpose %q and remaining %v", purposes[i], r, purposes[i], want)
		}
	}
	// Approved now: no manifest, no signature, nothing left.
	var again map[string]any
	st, body := f.admin.do("POST", path(purposes[0]), nil)
	if err := json.Unmarshal(body, &again); err != nil {
		t.Fatal(err)
	}
	if st != 200 || again["already_approved"] != true || again["remaining"] != float64(0) {
		t.Fatalf("re-sign of an approved unit = %d %v, want 200 already_approved with remaining 0", st, again)
	}
}
