package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/agent"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/translog"
)

// TestSignedActionsEndToEnd runs the real server and the real agent in one
// process and walks the whole Phase 3 contract through the HTTP API with a
// software security key. The other signing tests fake one side or the other;
// this is the one that proves the two halves agree.
func TestSignedActionsEndToEnd(t *testing.T) {
	t.Setenv(agent.EnvConfigDir, t.TempDir()) // the agent's agent.json, trust.json, nonces.json
	s, ts, b := newTestServerWith(t, Config{WebAuthnRPID: authtest.RPID, WebAuthnOrigins: []string{authtest.Origin}})

	// A real agent, enrolled through the API.
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "e2e", "uses": 1}, &tok)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a := agent.New(&agent.Config{ServerURL: ts.URL, EnrollToken: tok.Token})
	go func() { a.Run(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Log("agent did not stop within 10 s")
		}
	}()
	var agentID string
	poll(t, "agent online", 15*time.Second, func() bool {
		var agents []Agent
		b.mustJSON("GET", "/api/agents", nil, &agents)
		for _, ag := range agents {
			if ag.Online {
				agentID = ag.ID
				return true
			}
		}
		return false
	})

	// An operator key and an enforcing bundle with a recovery key; the agent
	// pins it on first use.
	key := authtest.NewKey("admin", actionauth.AlgES256)
	registerKey(t, b, key)
	rk := authtest.NewRecoveryKey("")
	activate(t, b, map[string]any{
		"mode":     "enforce",
		"signers":  []any{signerIn("admin", key)},
		"recovery": []any{map[string]string{"id": rk.ID, "pub": rk.Entry().Pub}},
	}, key)
	poll(t, "agent pinned the bundle", 15*time.Second, func() bool { return trustEpochOf(s, agentID) == 1 })

	lang, body := "sh", "echo signed-e2e-ok"
	if runtime.GOOS == "windows" {
		lang = "cmd"
	}

	// A compromised server sends an unsigned script straight to the device:
	// the agent, not the server, refuses it.
	rctx, rcancel := context.WithTimeout(ctx, 15*time.Second)
	err := s.hub.Request(rctx, agentID, protocol.ReqScriptRun, protocol.ScriptRun{RunID: "direct", Language: lang, Body: body, Timeout: 30}, nil)
	rcancel()
	if err == nil || !strings.Contains(err.Error(), "refused: signature required") {
		t.Fatalf("unsigned script.run sent around the console: err = %v, want the agent's refusal", err)
	}

	// Through the console: 428, sign, retry, and the script really runs.
	path := "/api/agents/" + agentID + "/run"
	req := map[string]any{"language": lang, "body": body, "timeout_sec": 60}
	st, raw := b.do("POST", path, req)
	if st != 428 {
		t.Fatalf("unsigned run = %d %s, want 428", st, raw)
	}
	var ch challenge
	if err := json.Unmarshal(raw, &ch); err != nil || !ch.Required {
		t.Fatalf("428 body %s (err %v), want required=true", raw, err)
	}
	assertion := key.Sign(ch.bytes(t), authtest.SignOpts{})
	hdr := authHeader(ch.ManifestID, assertion)
	st, raw = b.doHdr("POST", path, req, hdr)
	if st != 200 {
		t.Fatalf("signed run = %d %s", st, raw)
	}
	var started struct {
		RunID string `json:"run_id"`
	}
	json.Unmarshal(raw, &started)
	var run Run
	poll(t, "the signed script to finish", 60*time.Second, func() bool {
		b.mustJSON("GET", "/api/runs/"+started.RunID, nil, &run)
		return run.FinishedAt != 0
	})
	if run.ExitCode != 0 || !strings.Contains(run.Stdout, "signed-e2e-ok") {
		t.Fatalf("signed run: status %s exit %d stdout %q stderr %q", run.Status, run.ExitCode, run.Stdout, run.Stderr)
	}

	// The same signature again: the server has finished with that manifest,
	// and a server that replays it to the device anyway is refused there.
	if st, raw := b.doHdr("POST", path, req, hdr); st == 200 {
		t.Fatalf("a used signature was accepted again by the server: %s", raw)
	}
	replay := &protocol.ActionAuth{M: ch.Manifest, S: []protocol.Assertion{assertion}}
	rctx, rcancel = context.WithTimeout(ctx, 15*time.Second)
	err = s.hub.RequestA(rctx, agentID, protocol.ReqScriptRun, protocol.ScriptRun{RunID: "replay", Language: lang, Body: body, Timeout: 30}, nil, replay)
	rcancel()
	if err == nil || !strings.Contains(err.Error(), "refused: ") || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replayed manifest sent to the device: err = %v, want the agent's replay refusal", err)
	}

	// An upload well past the old 1 MiB cap: staged unsigned, committed with
	// a signature over its digest, and on disk byte for byte.
	data := bytes.Repeat([]byte("signed upload "), 190_000) // ~2.5 MiB
	dest := filepath.Join(t.TempDir(), "drop", "payload.bin")
	st, raw = uploadRaw(t, b, agentID, dest, data)
	var sr stagedReply
	if json.Unmarshal(raw, &sr); st != 200 || !sr.CommitRequired {
		t.Fatalf("upload = %d %s", st, raw)
	}
	commit := map[string]any{"upload_id": sr.UploadID}
	cpath := "/api/agents/" + agentID + "/fs/commit"
	st, raw = b.do("POST", cpath, commit)
	if st != 428 {
		t.Fatalf("unsigned commit = %d %s", st, raw)
	}
	var cch challenge
	json.Unmarshal(raw, &cch)
	if st, raw := b.doHdr("POST", cpath, commit, cch.signedBy(t, key)); st != 200 {
		t.Fatalf("signed commit = %d %s", st, raw)
	}
	if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("committed file: err %v, %d bytes, want %d", err, len(got), len(data))
	}

	// A compromised server that asks the device to commit a staged upload
	// under a digest it made up gets a refusal, and nothing lands.
	st, raw = uploadRaw(t, b, agentID, dest+".2", []byte("what was actually staged"))
	json.Unmarshal(raw, &sr)
	fake := protocol.FsCommit{UploadID: sr.UploadID, Path: dest + ".2", Size: 5, SHA256: strings.Repeat("ab", 32)}
	m, err := actionauth.BuildManifest(actionauth.Manifest{V: 1, Kind: actionauth.KindAction, ID: "e2e-fake", Org: "org_default",
		Targets: []string{agentID}, Op: protocol.ReqFsCommit, Payload: protocol.Must(fake), Nonce: "e2e-fake-nonce",
		IAT: time.Now().Unix(), Exp: time.Now().Unix() + 120})
	if err != nil {
		t.Fatal(err)
	}
	signed := &protocol.ActionAuth{M: actionauth.EncodeB64(m), S: []protocol.Assertion{key.Sign(m, authtest.SignOpts{})}}
	rctx, rcancel = context.WithTimeout(ctx, 15*time.Second)
	err = s.hub.RequestA(rctx, agentID, protocol.ReqFsCommit, fake, nil, signed)
	rcancel()
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("commit under a made-up digest: err = %v", err)
	}
	if _, err := os.Stat(dest + ".2"); !os.IsNotExist(err) {
		t.Error("a file landed although its digest did not match")
	}

	// A fleet update in an organization that signs its actions. The device
	// downloads from the server it is configured for and refuses a plain http
	// url from anywhere else, so the server has to advertise itself as this
	// listener before it builds the payload the operator signs. The build is
	// staged only now, so nothing above could have been offered it.
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Logf("fleet update not checked on %s: the server names agent builds for windows and linux only", runtime.GOOS)
		return
	}
	// With this set to 1 an agent without a supervisor replaces its own
	// executable, and in this process that is the test binary.
	t.Setenv("RMM_ALLOW_LEGACY_UPDATE", "")
	if err := s.db.SetSetting("public_url", ts.URL); err != nil {
		t.Fatal(err)
	}
	build, sum := stageAgentBinary(t, s, runtime.GOOS, runtime.GOARCH)
	upd := protocol.AgentUpdate{URL: ts.URL + "/api/agent-download/" + build, SHA256: sum, Version: "x"}

	// Around the console the device itself refuses an unsigned agent.update.
	rctx, rcancel = context.WithTimeout(ctx, 15*time.Second)
	err = s.hub.Request(rctx, agentID, protocol.ReqAgentUpdate, upd, nil)
	rcancel()
	if err == nil || !strings.Contains(err.Error(), "refused: signature required") {
		t.Fatalf("unsigned agent.update sent around the console: err = %v, want the agent's refusal", err)
	}

	// Through the console: 428, sign, retry. The device accepts the signature
	// and consumes the manifest. What it cannot do is install, because this
	// agent runs without a supervisor, and that is the answer that comes back.
	upath := "/api/agents/update-batch"
	ureq := map[string]any{"agent_ids": []string{agentID}}
	st, raw = b.do("POST", upath, ureq)
	if st != 428 {
		t.Fatalf("unsigned update-batch = %d %s, want 428", st, raw)
	}
	var uch challenge
	if err := json.Unmarshal(raw, &uch); err != nil || !uch.Required {
		t.Fatalf("428 body %s (err %v), want required=true", raw, err)
	}
	uassertion := key.Sign(uch.bytes(t), authtest.SignOpts{})
	st, raw = b.doHdr("POST", upath, ureq, authHeader(uch.ManifestID, uassertion))
	if st != 200 {
		t.Fatalf("signed update-batch = %d %s", st, raw)
	}
	var ures fleetBatch
	json.Unmarshal(raw, &ures)
	// A device that answers with an error is a failure, not a dispatch, so
	// dispatched_to (accepted plus still installing) stays at zero.
	if !ures.OK || ures.DispatchedTo != 0 || ures.Accepted != 0 || ures.Installing != 0 || ures.Offline != 0 || len(ures.Failed) != 1 || ures.Failed[0].ID != agentID {
		t.Fatalf("signed update-batch reply = %s, want the one device listed as failed", raw)
	}
	if why := ures.Failed[0].Error; !strings.Contains(why, "standalone mode") || strings.Contains(why, "signature required") {
		t.Fatalf("the device answered %q, want it to have accepted the signature and then failed to install in standalone mode", why)
	}

	// The manifest was consumed before the install was attempted: handing it to
	// the device again is refused as a replay.
	replay = &protocol.ActionAuth{M: uch.Manifest, S: []protocol.Assertion{uassertion}}
	rctx, rcancel = context.WithTimeout(ctx, 15*time.Second)
	err = s.hub.RequestA(rctx, agentID, protocol.ReqAgentUpdate, upd, nil, replay)
	rcancel()
	if err == nil || !strings.Contains(err.Error(), "refused: ") || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replayed update manifest sent to the device: err = %v, want the agent's replay refusal", err)
	}
	if rows := fleetAuditRows(t, s); len(rows) != 1 || rows[0].User != "admin" || rows[0].Details.Accepted != 0 || rows[0].Details.Failed != 1 {
		t.Fatalf("audit = %+v, want one fleet.update entry by admin with one failure", rows)
	}
}

// TestTransparencyLogEndToEnd runs the real server and the real agent under a
// bundle that pins the server's log key and requires log proofs, and checks
// both halves of Phase 3C against each other: the device accepts and stores
// the heads the server presents, records what it ran in a hash chain the
// server learns about, and refuses a signed manifest that was kept out of the
// log or presented at the wrong leaf.
func TestTransparencyLogEndToEnd(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv(agent.EnvConfigDir, cfgDir)
	s, ts, b := newTestServerWith(t, Config{WebAuthnRPID: authtest.RPID, WebAuthnOrigins: []string{authtest.Origin}})

	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "e2e-log", "uses": 1}, &tok)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a := agent.New(&agent.Config{ServerURL: ts.URL, EnrollToken: tok.Token})
	go func() { a.Run(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Log("agent did not stop within 10 s")
		}
	}()
	var agentID string
	poll(t, "agent online", 15*time.Second, func() bool {
		var agents []Agent
		b.mustJSON("GET", "/api/agents", nil, &agents)
		for _, ag := range agents {
			if ag.Online {
				agentID = ag.ID
				return true
			}
		}
		return false
	})

	type headReply struct {
		Size int64  `json:"size"`
		Hash string `json:"hash"`
		Key  string `json:"key"`
		Note string `json:"note"`
	}
	serverHead := func() headReply {
		t.Helper()
		var h headReply
		b.mustJSON("GET", "/api/log/head", nil, &h)
		return h
	}
	logKey := serverHead().Key
	if logKey == "" {
		t.Fatal("GET /api/log/head returned no key")
	}

	key := authtest.NewKey("admin", actionauth.AlgES256)
	registerKey(t, b, key)
	rk := authtest.NewRecoveryKey("")
	activate(t, b, map[string]any{
		"mode":              "enforce",
		"require_log_proof": true,
		"log_key":           logKey,
		"signers":           []any{signerIn("admin", key)},
		"recovery":          []any{map[string]string{"id": rk.ID, "pub": rk.Entry().Pub}},
	}, key)
	poll(t, "agent pinned the bundle", 15*time.Second, func() bool { return trustEpochOf(s, agentID) == 1 })

	lang, body := "sh", "echo log-e2e-ok"
	if runtime.GOOS == "windows" {
		lang = "cmd"
	}
	path := "/api/agents/" + agentID + "/run"
	req := map[string]any{"language": lang, "body": body, "timeout_sec": 60}

	// challengeFor fetches a fresh 428 and signs it, without sending the
	// signature back to the console.
	challengeFor := func() (challenge, protocol.Assertion) {
		t.Helper()
		st, raw := b.do("POST", path, req)
		if st != 428 {
			t.Fatalf("unsigned run = %d %s, want 428", st, raw)
		}
		var ch challenge
		if err := json.Unmarshal(raw, &ch); err != nil || !ch.Required {
			t.Fatalf("428 body %s (err %v), want required=true", raw, err)
		}
		return ch, key.Sign(ch.bytes(t), authtest.SignOpts{})
	}
	signedRun := func() challenge {
		t.Helper()
		ch, as := challengeFor()
		st, raw := b.doHdr("POST", path, req, authHeader(ch.ManifestID, as))
		if st != 200 {
			t.Fatalf("signed run = %d %s", st, raw)
		}
		var started struct {
			RunID string `json:"run_id"`
		}
		json.Unmarshal(raw, &started)
		var run Run
		poll(t, "the signed script to finish", 60*time.Second, func() bool {
			b.mustJSON("GET", "/api/runs/"+started.RunID, nil, &run)
			return run.FinishedAt != 0
		})
		if run.ExitCode != 0 || !strings.Contains(run.Stdout, "log-e2e-ok") {
			t.Fatalf("signed run: status %s exit %d stdout %q stderr %q", run.Status, run.ExitCode, run.Stdout, run.Stderr)
		}
		return ch
	}

	// readDeviceHead parses log_head.json the way an auditor would: the signed
	// note against the pinned key.
	readDeviceHead := func() (size int64, note string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(cfgDir, "log_head.json"))
		if err != nil {
			t.Fatalf("the device has no log_head.json after an executed run: %v", err)
		}
		var h struct {
			Size int64  `json:"size"`
			Hash string `json:"hash"`
			Note string `json:"note"`
		}
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatalf("log_head.json: %v", err)
		}
		n, err := base64.StdEncoding.DecodeString(h.Note)
		if err != nil {
			t.Fatalf("log_head.json note: %v", err)
		}
		tree, err := translog.ParseHead(logKey, n)
		if err != nil || tree.N != h.Size || tree.Hash.String() != h.Hash {
			t.Fatalf("log_head.json does not hold a head signed by the server's key: tree %+v err %v file %+v", tree, err, h)
		}
		return h.Size, h.Note
	}
	// extendsDeviceHead asks the server for a consistency proof from the
	// device's head to its current one and checks it.
	extendsDeviceHead := func(size int64, note string) {
		t.Helper()
		oldNote, _ := base64.StdEncoding.DecodeString(note)
		old, err := translog.ParseHead(logKey, oldNote)
		if err != nil {
			t.Fatal(err)
		}
		cur := serverHead()
		curNote, _ := base64.StdEncoding.DecodeString(cur.Note)
		newTree, err := translog.ParseHead(logKey, curNote)
		if err != nil {
			t.Fatal(err)
		}
		var cr struct {
			Proof []string `json:"proof"`
		}
		b.mustJSON("GET", "/api/log/consistency?from="+strconv.FormatInt(size, 10)+"&to="+strconv.FormatInt(newTree.N, 10), nil, &cr)
		proof, err := translog.DecodeProof(cr.Proof)
		if err != nil {
			t.Fatal(err)
		}
		if err := translog.CheckConsistency(old, newTree, proof); err != nil {
			t.Fatalf("the device's head (size %d) is not a prefix of the server's head (size %d): %v", size, cur.Size, err)
		}
	}
	executedLines := func() []string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(cfgDir, "executed.log"))
		if err != nil {
			t.Fatalf("the device has no executed.log: %v", err)
		}
		var out []string
		for _, l := range strings.Split(string(raw), "\n") {
			if l = strings.TrimRight(l, "\r"); l != "" {
				out = append(out, l)
			}
		}
		return out
	}
	hashOf := func(line string) string {
		sum := sha256.Sum256([]byte(line))
		return base64.StdEncoding.EncodeToString(sum[:])
	}
	type execLine struct {
		Prev       string `json:"prev"`
		ManifestID string `json:"manifest_id"`
		Op         string `json:"op"`
		LogIndex   int64  `json:"log_index"`
	}

	// First signed run: executes, and the device keeps the head it was shown.
	ch1 := signedRun()
	size1, note1 := readDeviceHead()
	if size1 < 1 || size1 > serverHead().Size {
		t.Fatalf("device head size %d, server size %d", size1, serverHead().Size)
	}
	extendsDeviceHead(size1, note1)

	// Second signed run: the request carries a consistency proof from the first
	// head, and the device accepts it and moves forward.
	ch2 := signedRun()
	size2, note2 := readDeviceHead()
	if size2 <= size1 {
		t.Fatalf("device head did not grow after a second logged manifest: %d then %d", size1, size2)
	}
	extendsDeviceHead(size2, note2)

	// executed.log: two chained lines, each naming its manifest and leaf.
	lines := executedLines()
	if len(lines) != 2 {
		t.Fatalf("executed.log has %d lines, want 2: %q", len(lines), lines)
	}
	var l1, l2 execLine
	json.Unmarshal([]byte(lines[0]), &l1)
	json.Unmarshal([]byte(lines[1]), &l2)
	if l1.Prev != "" || l2.Prev != hashOf(lines[0]) {
		t.Fatalf("executed.log is not chained: line 1 prev %q, line 2 prev %q, want %q", l1.Prev, l2.Prev, hashOf(lines[0]))
	}
	if l1.ManifestID != ch1.ManifestID || l2.ManifestID != ch2.ManifestID || l1.Op != protocol.ReqScriptRun || l1.LogIndex < 0 || l2.LogIndex <= l1.LogIndex {
		t.Fatalf("executed.log lines %+v and %+v do not match manifests %s and %s", l1, l2, ch1.ManifestID, ch2.ManifestID)
	}
	wantHead := hashOf(lines[1])

	// The head reaches the server in the next inventory, and is stored.
	rctx, rcancel := context.WithTimeout(ctx, 15*time.Second)
	err := s.hub.Request(rctx, agentID, protocol.ReqInventoryRefresh, nil, nil)
	rcancel()
	if err != nil {
		t.Fatalf("inventory refresh: %v", err)
	}
	poll(t, "the server to hold the device's executed head", 15*time.Second, func() bool {
		var h string
		s.db.QueryRow(`SELECT executed_head FROM agents WHERE id = ?`, agentID).Scan(&h)
		return h == wantHead
	})
	var shown map[string]json.RawMessage
	b.mustJSON("GET", "/api/agents/"+agentID, nil, &shown)
	var inv struct {
		ExecutedHead string `json:"executed_head"`
	}
	json.Unmarshal(shown["inventory"], &inv)
	var topHead string
	json.Unmarshal(shown["executed_head"], &topHead)
	if inv.ExecutedHead != wantHead && topHead != wantHead {
		t.Fatalf("GET /api/agents/{id} shows executed_head %q (inventory %q), want %q", topHead, inv.ExecutedHead, wantHead)
	}
	if topHead != wantHead {
		t.Errorf("GET /api/agents/{id} has no top-level executed_head (got %q, want %q); only inventory.executed_head carries it", topHead, wantHead)
	}

	// Around the log. A manifest the operator signed but the server never
	// logged is refused by the device, and a manifest presented at someone
	// else's leaf is too.
	sendAround := func(ch challenge, as protocol.Assertion, l *protocol.LogProof) error {
		t.Helper()
		var sr protocol.ScriptRun
		if err := json.Unmarshal(ch.parsed(t).Payload, &sr); err != nil {
			t.Fatalf("manifest payload: %v", err)
		}
		sr.RunID = "around-" + ch.ManifestID
		auth := &protocol.ActionAuth{M: ch.Manifest, S: []protocol.Assertion{as}, L: l}
		rctx, rcancel := context.WithTimeout(ctx, 15*time.Second)
		defer rcancel()
		return s.hub.RequestA(rctx, agentID, protocol.ReqScriptRun, sr, nil, auth)
	}
	chA, asA := challengeFor()
	if err := sendAround(chA, asA, nil); err == nil || !strings.Contains(err.Error(), "refused: ") || !strings.Contains(err.Error(), "log proof") {
		t.Fatalf("manifest sent without a log proof: err = %v, want the device's log proof refusal", err)
	}
	chB, asB := challengeFor()
	if err := sendAround(chB, asB, &protocol.LogProof{Index: l1.LogIndex}); err == nil || !strings.Contains(err.Error(), "refused: ") || !strings.Contains(err.Error(), "log proof") {
		t.Fatalf("manifest presented at another manifest's leaf: err = %v, want the device's log proof refusal", err)
	}
	if n := len(executedLines()); n != 2 {
		t.Errorf("executed.log has %d lines after two refusals, want 2", n)
	}
	if size, _ := readDeviceHead(); size != size2 {
		t.Errorf("a refused request moved the device's log head from %d to %d", size2, size)
	}
	poll(t, "a security alert naming the log proof refusal", 15*time.Second, func() bool {
		var alerts []Alert
		b.mustJSON("GET", "/api/alerts", nil, &alerts)
		for _, al := range alerts {
			if al.RuleKind == "security" && al.AgentID == agentID && strings.Contains(al.Message, "log proof") {
				return true
			}
		}
		return false
	})

	// The audit rows of the two runs point at leaves that decode back to them,
	// and the device's executed.log points at the manifests' leaves.
	fetch := func(idx int64) (string, map[string]any) {
		t.Helper()
		var lf struct {
			Kind string `json:"kind"`
			Data string `json:"data"`
		}
		b.mustJSON("GET", "/api/log/entries/"+strconv.FormatInt(idx, 10), nil, &lf)
		raw, err := base64.StdEncoding.DecodeString(lf.Data)
		if err != nil {
			t.Fatalf("leaf %d data: %v", idx, err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("leaf %d is not JSON: %v", idx, err)
		}
		return lf.Kind, m
	}
	for i, e := range []execLine{l1, l2} {
		kind, m := fetch(e.LogIndex)
		want := []string{ch1.Manifest, ch2.Manifest}[i]
		if kind != "manifest" || m["manifest"] != want {
			t.Errorf("leaf %d for run %d is %s %v, want the manifest that run was signed with", e.LogIndex, i+1, kind, m)
		}
	}
	type auditRef struct{ id, idx int64 }
	var audited []auditRef
	poll(t, "two script.run audit rows with log indexes", 15*time.Second, func() bool {
		audited = nil
		rs, err := s.db.Query(`SELECT id, log_index FROM audit WHERE action = 'script.run' AND target = ? ORDER BY id`, agentID)
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Close()
		for rs.Next() {
			var r auditRef
			rs.Scan(&r.id, &r.idx)
			audited = append(audited, r)
		}
		return len(audited) == 2 && audited[0].idx >= 0 && audited[1].idx >= 0
	})
	for _, r := range audited {
		kind, m := fetch(r.idx)
		id, _ := m["id"].(float64)
		if kind != "audit" || m["action"] != "script.run" || m["target"] != agentID || int64(id) != r.id {
			t.Errorf("audit row %d (log_index %d) decodes to %s %v", r.id, r.idx, kind, m)
		}
	}
}

// poll is waitFor with a caller-chosen deadline: a real agent starting a real
// interpreter needs longer than the fake agents' five seconds.
func poll(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}
