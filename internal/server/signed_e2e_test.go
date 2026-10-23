package server

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/agent"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
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
