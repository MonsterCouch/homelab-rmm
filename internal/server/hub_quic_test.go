package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/translog"
)

// connectQUIC enrolls a new device over QUIC and waits until the hub has it.
func connectQUIC(t *testing.T, s *Server, b *browser, q *quicServer, name string) (*quicClient, quicWelcome) {
	t.Helper()
	c := dialQUIC(t, q.addr(), s.Fingerprint())
	wl := c.handshake(protocol.Auth{Token: consoleToken(t, b, name)}, testHello(name))
	if wl.AgentID == "" || wl.Key == "" {
		t.Fatalf("enrollment over QUIC returned id %q key %q", wl.AgentID, wl.Key)
	}
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(wl.AgentID) })
	return c, wl
}

type agentRowJSON struct {
	ID        string `json:"id"`
	Online    bool   `json:"online"`
	Transport string `json:"transport"`
}

func TestQUICEnrollmentAdvertisesAndRecordsTransport(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "quicbox")

	if !wl.Config.QUIC || wl.Config.QUICPort != quicAddrPort(q) {
		t.Fatalf("welcome config advertises quic=%v port=%d, want true and %d", wl.Config.QUIC, wl.Config.QUICPort, quicAddrPort(q))
	}
	ac, _ := s.hub.get(wl.AgentID)
	if ac.transportName() != "quic" {
		t.Fatalf("hub transport = %q", ac.transportName())
	}
	var row agentRowJSON
	b.mustJSON("GET", "/api/agents/"+wl.AgentID, nil, &row)
	if !row.Online || row.Transport != "quic" {
		t.Fatalf("agent row = %+v, want online over quic", row)
	}
	var rows []agentRowJSON
	b.mustJSON("GET", "/api/agents", nil, &rows)
	if len(rows) != 1 || rows[0].Transport != "quic" {
		t.Fatalf("agent list = %+v", rows)
	}
	var audited int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action = 'agent.enrolled' AND target = ?`, wl.AgentID).Scan(&audited)
	if audited != 1 {
		t.Fatalf("agent.enrolled audit rows = %d, want 1 (the shared enrollment path)", audited)
	}

	// A second connection with the key replaces the first, as on WebSocket.
	c2 := dialQUIC(t, q.addr(), s.Fingerprint())
	wl2 := c2.handshake(protocol.Auth{Key: wl.Key}, testHello("quicbox"))
	if wl2.AgentID != wl.AgentID || wl2.Key != "" {
		t.Fatalf("reconnect welcome = %+v, want the same id and no new key", wl2)
	}
	select {
	case <-c.conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the replaced QUIC connection was not closed")
	}
	c2.close()
	waitFor(t, "agent offline", func() bool { return !s.hub.IsOnline(wl.AgentID) })
	row = agentRowJSON{} // a decode into a used struct keeps fields the JSON omits
	b.mustJSON("GET", "/api/agents/"+wl.AgentID, nil, &row)
	if row.Online || row.Transport != "" {
		t.Fatalf("offline row = %+v, want no transport", row)
	}
}

func TestQUICRefusesBadCredentials(t *testing.T) {
	s, _, _, q := newQUICServer(t)
	cases := []struct {
		name  string
		first protocol.Envelope
		want  string
	}{
		{"unknown key", protocol.Envelope{T: protocol.TypeAuth, D: protocol.Must(protocol.Auth{Key: "nope"})}, protocol.ErrUnknownAgentKey},
		{"bad token", protocol.Envelope{T: protocol.TypeAuth, D: protocol.Must(protocol.Auth{Token: "nope"})}, protocol.ErrEnrollmentRefused},
		{"no credentials", protocol.Envelope{T: protocol.TypeAuth, D: protocol.Must(protocol.Auth{})}, protocol.ErrMissingCredentials},
		{"hello before auth", protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(testHello("x"))}, "expected auth"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dialQUIC(t, q.addr(), s.Fingerprint())
			c.sendControl(tc.first)
			env, err := c.readControl(5 * time.Second)
			if err != nil {
				t.Fatalf("reading the refusal: %v", err)
			}
			if env.T != "error" || !strings.HasPrefix(env.Err, tc.want) {
				t.Fatalf("got %s %q, want an error starting %q", env.T, env.Err, tc.want)
			}
			if _, err := c.readControl(5 * time.Second); err == nil {
				t.Fatal("the connection stayed open after a refusal")
			}
		})
	}
	if n := len(s.hub.OnlineIDs()); n != 0 {
		t.Fatalf("%d devices online after refusals", n)
	}
}

func TestQUICRejectsAnotherALPN(t *testing.T) {
	s, _, _, q := newQUICServer(t)
	conf := pinTLS(s.Fingerprint())
	conf.NextProtos = []string{"h3"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := quic.DialAddr(ctx, q.addr(), conf, nil); err == nil {
		conn.CloseWithError(0, "")
		t.Fatal("a client that did not offer the agent ALPN got in")
	}
}

func TestQUICRequestRoundTripUsesItsOwnStream(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")

	got := make(chan *quicReq, 1)
	go func() {
		r, err := c.acceptRequest(5 * time.Second)
		if err != nil {
			t.Error(err)
			close(got)
			return
		}
		got <- r
		r.reply([]protocol.Process{{PID: 7, Name: "init"}})
	}()
	var procs []protocol.Process
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.hub.Request(ctx, wl.AgentID, protocol.ReqProcList, nil, &procs); err != nil {
		t.Fatal(err)
	}
	if len(procs) != 1 || procs[0].PID != 7 {
		t.Fatalf("reply = %+v", procs)
	}
	r := <-got
	if r == nil || r.Env.T != protocol.ReqProcList || r.Env.ID == "" {
		t.Fatalf("request frame = %+v", r)
	}
	// a server-initiated bidirectional stream (ids 1, 5, 9, ...), not the control stream
	if id := int64(r.st.StreamID()); id%4 != 1 || r.st.StreamID() == c.ctrl.StreamID() {
		t.Fatalf("request arrived on stream %d (control is %d), want a server-opened stream of its own", id, c.ctrl.StreamID())
	}
}

func TestQUICNotifyTravelsOnTheControlStream(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	if err := s.hub.Notify(wl.AgentID, protocol.ReqShellInput, protocol.ShellInput{Session: "s1", Data: "ls\n"}); err != nil {
		t.Fatal(err)
	}
	for {
		env, err := c.readControl(5 * time.Second)
		if err != nil {
			t.Fatalf("no notice on the control stream: %v", err)
		}
		if env.T == protocol.ReqShellInput {
			if env.ID != "" {
				t.Fatalf("a notice carries id %q", env.ID)
			}
			return
		}
	}
}

func TestQUICStreamAFramesArriveInOrderWithTheFinalReply(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	c.serve(func(r *quicReq) {
		for _, d := range []string{"a", "b", "c"} {
			r.stream(protocol.ScriptChunk{Stream: "stdout", Data: d})
		}
		r.reply(protocol.ScriptResult{ExitCode: 3})
	})
	var mu sync.Mutex
	var chunks []string
	done := make(chan protocol.Envelope, 1)
	_, _, err := s.hub.Stream(wl.AgentID, protocol.ReqScriptRun, protocol.ScriptRun{Language: "bash", Body: "x"}, func(env protocol.Envelope) {
		if env.T == protocol.TypeReply {
			done <- env
			return
		}
		var ch protocol.ScriptChunk
		json.Unmarshal(env.D, &ch)
		mu.Lock()
		chunks = append(chunks, ch.Data)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case env := <-done:
		var res protocol.ScriptResult
		json.Unmarshal(env.D, &res)
		mu.Lock()
		defer mu.Unlock()
		if strings.Join(chunks, "") != "abc" || res.ExitCode != 3 {
			t.Fatalf("chunks %v, result %+v", chunks, res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no final reply")
	}
}

// The reason QUIC exists: a request whose consumer has stalled must not delay
// another request to the same device. The sink of a streaming request blocks
// the way a slow console viewer does; a second request still completes at once.
// Over a WebSocket this fails by construction, because one read loop feeds
// every sink, so it is asserted for QUIC only.
func TestQUICStalledStreamDoesNotBlockAnotherRequest(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	c.serve(func(r *quicReq) {
		switch r.Env.T {
		case protocol.ReqScriptRun:
			r.stream(protocol.ScriptChunk{Stream: "stdout", Data: "one"})
			r.stream(protocol.ScriptChunk{Stream: "stdout", Data: "two"})
			r.reply(protocol.ScriptResult{})
		case protocol.ReqProcList:
			r.reply([]protocol.Process{{PID: 1, Name: "init"}})
		}
	})

	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	defer release()
	got := make(chan string, 8)
	final := make(chan struct{}, 1)
	_, _, err := s.hub.Stream(wl.AgentID, protocol.ReqScriptRun, protocol.ScriptRun{Language: "bash", Body: "x"}, func(env protocol.Envelope) {
		if env.T == protocol.TypeReply {
			final <- struct{}{}
			return
		}
		var ch protocol.ScriptChunk
		json.Unmarshal(env.D, &ch)
		got <- ch.Data
		if ch.Data == "one" {
			<-gate // the stalled consumer
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-got:
		if d != "one" {
			t.Fatalf("first chunk %q", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first chunk never arrived")
	}

	start := time.Now()
	var procs []protocol.Process
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.hub.Request(ctx, wl.AgentID, protocol.ReqProcList, nil, &procs); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("a request behind a stalled stream took %v, want under 100ms", took)
	}
	select {
	case d := <-got:
		t.Fatalf("chunk %q was delivered although its stream's consumer is stalled", d)
	case <-time.After(100 * time.Millisecond):
	}

	release()
	select {
	case d := <-got:
		if d != "two" {
			t.Fatalf("second chunk %q", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled stream did not resume")
	}
	select {
	case <-final:
	case <-time.After(5 * time.Second):
		t.Fatal("no final reply after the stream resumed")
	}
}

func TestQUICUnansweredRequestTimesOutAndFreesItsStream(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	got := make(chan *quicReq, 1)
	go func() {
		if r, err := c.acceptRequest(5 * time.Second); err == nil {
			got <- r
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := s.hub.Request(ctx, wl.AgentID, protocol.ReqProcList, nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context deadline", err)
	}
	r := <-got
	r.st.SetReadDeadline(time.Now().Add(3 * time.Second))
	var se *quic.StreamError
	if _, err := r.st.Read(make([]byte, 1)); !errors.As(err, &se) {
		// the request frame was already consumed and the server's side closed
		// cleanly (EOF) or was reset; either way the stream must not hang
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read after the timeout = %v, want EOF or a stream reset", err)
		}
	}
	ac, _ := s.hub.get(wl.AgentID)
	ac.pmu.Lock()
	n := len(ac.pending)
	ac.pmu.Unlock()
	if n != 0 {
		t.Fatalf("%d requests still pending", n)
	}
}

func TestQUICRequestStreamEndedWithoutReplyFailsTheRequest(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	c.serve(func(r *quicReq) { r.st.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.hub.Request(ctx, wl.AgentID, protocol.ReqProcList, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "without replying") {
		t.Fatalf("err = %v, want the stream-ended-without-reply error rather than a timeout", err)
	}
}

func TestQUICAgentReplyErrorIsReturned(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	c.serve(func(r *quicReq) { r.replyErr("no such process") })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.hub.Request(ctx, wl.AgentID, protocol.ReqProcKill, nil, nil); err == nil || err.Error() != "no such process" {
		t.Fatalf("err = %v", err)
	}
}

func TestQUICControlPushesReachTheIngestPath(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	c.sendControl(protocol.Envelope{T: protocol.TypeEvent, D: protocol.Must(protocol.Event{Kind: "service", Message: "sshd restarted", TS: time.Now().Unix()})})
	waitFor(t, "the event row", func() bool {
		var n int
		s.db.QueryRow(`SELECT COUNT(*) FROM agent_events WHERE agent_id = ? AND message = 'sshd restarted'`, wl.AgentID).Scan(&n)
		return n == 1
	})
}

func TestQUICSignedActionCarriesTheLogProof(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	q := enableQUIC(t, f.s)
	head0, tree0 := getHead(t, f.admin)
	hello := testHello("box1")
	hello.LogSize = head0.Size
	c := dialQUIC(t, q.addr(), f.s.Fingerprint())
	wl := c.handshake(protocol.Auth{Token: consoleToken(t, f.admin, "box1")}, hello)
	waitFor(t, "agent online", func() bool { return f.s.hub.IsOnline(wl.AgentID) })

	var mu sync.Mutex
	var seen []protocol.Envelope
	logKey := f.logKey()
	c.serve(func(r *quicReq) {
		reply := protocol.Envelope{}
		if r.Env.A != nil && r.Env.A.L != nil {
			mu.Lock()
			seen = append(seen, r.Env)
			mu.Unlock()
			// what the real device does: report the head it now holds
			if tree, err := translog.ParseHead(logKey, mustB64(r.Env.A.L.Head)); err == nil {
				reply.Log = tree.N
			}
		}
		if r.Env.T == protocol.ReqScriptRun {
			var sr protocol.ScriptRun
			json.Unmarshal(r.Env.D, &sr)
			reply.D = protocol.Must(protocol.ScriptResult{RunID: sr.RunID})
		}
		r.replyEnv(reply)
	})
	wait := func(n int) []protocol.Envelope {
		var got []protocol.Envelope
		waitFor(t, "protected requests with a log proof", func() bool {
			mu.Lock()
			defer mu.Unlock()
			got = append([]protocol.Envelope(nil), seen...)
			return len(got) >= n
		})
		return got
	}
	run := func(body string) {
		t.Helper()
		if st, out := signedCall(t, f.admin, f.ka, "POST", "/api/agents/"+wl.AgentID+"/run", map[string]any{"language": "bash", "body": body}); st != 200 {
			t.Fatalf("signed run = %d %s", st, out)
		}
	}

	run("echo one")
	first := wait(1)[0]
	tree1 := checkProof(t, head0.Key, first.A, &tree0)
	waitFor(t, "hub to learn the device's log size", func() bool {
		ac, ok := f.s.hub.get(wl.AgentID)
		return ok && ac.logSize.Load() == tree1.N
	})
	run("echo two")
	second := wait(2)[1]
	checkProof(t, head0.Key, second.A, &tree1)
	if second.A.L.Index == first.A.L.Index {
		t.Fatal("two signed runs share one leaf")
	}
}

func TestQUICKeepaliveDropsASilentAgentAndKeepsAnAnsweringOne(t *testing.T) {
	oldEvery, oldDead := keepaliveEvery, keepaliveDead
	keepaliveEvery, keepaliveDead = 50*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { keepaliveEvery, keepaliveDead = oldEvery, oldDead })
	s, _, b, q := newQUICServer(t)

	silent, silentWL := connectQUIC(t, s, b, q, "silent")
	_ = silent // never reads its control stream, so never pongs

	live, liveWL := connectQUIC(t, s, b, q, "live")
	go func() {
		for {
			env, err := readTestFrame(live.ctrl)
			if err != nil {
				return
			}
			if env.T == protocol.ReqPing {
				writeTestFrame(live.ctrl, protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			}
		}
	}()

	waitFor(t, "the silent agent to be dropped", func() bool { return !s.hub.IsOnline(silentWL.AgentID) })
	time.Sleep(600 * time.Millisecond)
	if !s.hub.IsOnline(liveWL.AgentID) {
		t.Fatal("an agent that answers pings was dropped")
	}
}

func TestQUICOversizedFrameDropsTheAgent(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxAgentFrame+1)
	if _, err := c.ctrl.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the agent to be dropped", func() bool { return !s.hub.IsOnline(wl.AgentID) })
}

func TestQUICClosingTheConnectionFailsPendingRequests(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	got := make(chan struct{})
	go func() {
		if _, err := c.acceptRequest(5 * time.Second); err == nil {
			close(got)
		}
	}()
	errc := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		errc <- s.hub.Request(ctx, wl.AgentID, protocol.ReqProcList, nil, nil)
	}()
	<-got
	c.close()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "disconnected") {
			t.Fatalf("err = %v, want agent disconnected", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request outlived its connection")
	}
}

func TestWebSocketAgentRowShowsItsTransport(t *testing.T) {
	s, ts, b := newTestServer(t)
	a := dialAgent(t, wsURL(ts), http.Header{"X-Enroll-Token": []string{consoleToken(t, b, "wsbox")}})
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(a.id) })
	var row agentRowJSON
	b.mustJSON("GET", "/api/agents/"+a.id, nil, &row)
	if !row.Online || row.Transport != "websocket" {
		t.Fatalf("row = %+v, want online over websocket", row)
	}
	// and the welcome of a server without QUIC does not advertise it
	if cfg := s.agentConfig(a.id); cfg.QUIC || cfg.QUICPort != 0 {
		t.Fatalf("config advertises quic=%v port=%d with the listener off", cfg.QUIC, cfg.QUICPort)
	}
}

func TestDeviceMovesFromQUICToWebSocketOnReconnect(t *testing.T) {
	s, ts, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", http.Header{"Authorization": []string{"Bearer " + wl.Key}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.WriteJSON(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(testHello("box"))})
	waitFor(t, "the websocket to take over", func() bool {
		ac, ok := s.hub.get(wl.AgentID)
		return ok && ac.transportName() == "websocket"
	})
	select {
	case <-c.conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the QUIC connection was not closed when the WebSocket replaced it")
	}
}

func TestNewRefusesQUICWithInsecure(t *testing.T) {
	_, err := New(Config{DataDir: t.TempDir(), Listen: "127.0.0.1:0", Insecure: true, QUIC: true, SkipSeed: true})
	if err == nil || !strings.Contains(err.Error(), "--insecure") || !strings.Contains(err.Error(), "--quic") {
		t.Fatalf("err = %v, want a sentence naming --quic and --insecure", err)
	}
	if err := CheckQUICConfig(Config{QUIC: true, QUICPort: 70000}); err == nil {
		t.Fatal("a UDP port above 65535 was accepted")
	}
	if err := CheckQUICConfig(Config{Insecure: true}); err != nil {
		t.Fatalf("--insecure without --quic was refused: %v", err)
	}
}

func TestQUICAddrFollowsListenAndQUICPort(t *testing.T) {
	s := &Server{cfg: Config{Listen: ":8443"}}
	if a, err := s.quicAddr(); err != nil || a != ":8443" {
		t.Fatalf("default = %q, %v", a, err)
	}
	s.cfg.QUICPort = 9443
	if a, _ := s.quicAddr(); a != ":9443" {
		t.Fatalf("with --quic-port = %q", a)
	}
	s.cfg.Listen = "10.0.0.5:8443"
	if a, _ := s.quicAddr(); a != "10.0.0.5:9443" {
		t.Fatalf("with a bound host = %q", a)
	}
}
