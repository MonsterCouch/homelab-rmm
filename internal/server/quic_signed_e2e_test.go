package server

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/agent"
)

// TestSignedActionsRunOverQUICWithLogProofs runs the real agent over a real
// QUIC session under a bundle that requires transparency log proofs, with
// signed requests sent one after another and two at once. The proofs only
// verify in the order they were made, so this is the test that the agent's
// in-order accept loop and the hub's single write lock agree.
func TestSignedActionsRunOverQUICWithLogProofs(t *testing.T) {
	t.Setenv(agent.EnvConfigDir, t.TempDir())
	t.Setenv("RMM_TRANSPORT", "")
	s, _, b := newTestServerWith(t, Config{WebAuthnRPID: authtest.RPID, WebAuthnOrigins: []string{authtest.Origin}})
	q := enableQUIC(t, s)

	tok := consoleToken(t, b, "e2e-quic")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	// The host is only used to find the UDP address; the port is the listener's.
	a := agent.New(&agent.Config{ServerURL: "https://127.0.0.1:1", EnrollToken: tok, Fingerprint: s.Fingerprint(),
		Transport: "quic", QUICPort: quicAddrPort(q)})
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
	poll(t, "agent online over QUIC", 20*time.Second, func() bool {
		var rows []agentRowJSON
		b.mustJSON("GET", "/api/agents", nil, &rows)
		for _, r := range rows {
			if r.Online && r.Transport == "quic" {
				agentID = r.ID
				return true
			}
		}
		return false
	})

	var head struct {
		Key string `json:"key"`
	}
	b.mustJSON("GET", "/api/log/head", nil, &head)
	key := authtest.NewKey("admin", actionauth.AlgES256)
	registerKey(t, b, key)
	rk := authtest.NewRecoveryKey("")
	activate(t, b, map[string]any{
		"mode":              "enforce",
		"require_log_proof": true,
		"log_key":           head.Key,
		"signers":           []any{signerIn("admin", key)},
		"recovery":          []any{map[string]string{"id": rk.ID, "pub": rk.Entry().Pub}},
	}, key)
	poll(t, "agent pinned the bundle", 20*time.Second, func() bool { return trustEpochOf(s, agentID) == 1 })

	lang := "sh"
	if runtime.GOOS == "windows" {
		lang = "cmd"
	}
	path := "/api/agents/" + agentID + "/run"
	req := map[string]any{"language": lang, "body": "echo quic-signed-ok", "timeout_sec": 60}
	signed := func() map[string]string {
		t.Helper()
		st, raw := b.do("POST", path, req)
		if st != 428 {
			t.Fatalf("unsigned run = %d %s, want 428", st, raw)
		}
		var ch challenge
		if err := json.Unmarshal(raw, &ch); err != nil || !ch.Required {
			t.Fatalf("428 body %s (err %v), want required=true", raw, err)
		}
		return authHeader(ch.ManifestID, key.Sign(ch.bytes(t), authtest.SignOpts{}))
	}
	finish := func(raw []byte) {
		t.Helper()
		var started struct {
			RunID string `json:"run_id"`
		}
		json.Unmarshal(raw, &started)
		var run Run
		poll(t, "the signed script to finish", 60*time.Second, func() bool {
			b.mustJSON("GET", "/api/runs/"+started.RunID, nil, &run)
			return run.FinishedAt != 0
		})
		if run.ExitCode != 0 || !strings.Contains(run.Stdout, "quic-signed-ok") {
			t.Fatalf("signed run over QUIC: status %s exit %d stdout %q stderr %q", run.Status, run.ExitCode, run.Stdout, run.Stderr)
		}
	}

	// Back to back: the second carries a consistency proof from the first head.
	for i := 0; i < 2; i++ {
		st, raw := b.doHdr("POST", path, req, signed())
		if st != 200 {
			t.Fatalf("signed run %d over QUIC = %d %s", i+1, st, raw)
		}
		finish(raw)
	}

	// Two at once, each with its own request stream.
	hdrs := []map[string]string{signed(), signed()}
	type result struct {
		st  int
		raw []byte
	}
	results := make([]result, len(hdrs))
	var wg sync.WaitGroup
	for i := range hdrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, raw := b.doHdr("POST", path, req, hdrs[i])
			results[i] = result{st, raw}
		}()
	}
	wg.Wait()
	for i, r := range results {
		if r.st != 200 {
			t.Fatalf("concurrent signed run %d over QUIC = %d %s", i+1, r.st, r.raw)
		}
		finish(r.raw)
	}
}
