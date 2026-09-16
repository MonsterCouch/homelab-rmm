package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// TestDesktopBridge drives the full desktop handshake: viewer connects, the
// server asks the agent to start a helper, a fake helper connects with the
// token, and binary/text frames flow both ways through the bridge.
func TestDesktopBridge(t *testing.T) {
	s, ts, b := newTestServer(t)
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab"}, &tok)

	helperConnected := make(chan *websocket.Conn, 1)
	// a fake agent whose desktop.start handler spawns a fake helper
	ws, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", http.Header{"X-Enroll-Token": []string{tok.Token}})
	if err != nil {
		t.Fatal(err)
	}
	ws.WriteJSON(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(protocol.Hello{Hostname: "desk", OS: "windows"})})
	var welcome protocol.Envelope
	ws.ReadJSON(&welcome)
	var w struct {
		AgentID string `json:"agent_id"`
	}
	json.Unmarshal(welcome.D, &w)
	go func() {
		for {
			var env protocol.Envelope
			if err := ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqDesktopStart:
				var ds protocol.DesktopStart
				json.Unmarshal(env.D, &ds)
				h, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/desktop-agent?token="+ds.Token, nil)
				if err != nil {
					t.Errorf("helper dial: %v", err)
					return
				}
				helperConnected <- h
				ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.DesktopStartResult{Started: true, Note: "fake helper"})})
			}
		}
	}()
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(w.AgentID) })

	// unknown token is refused
	if _, resp, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/desktop-agent?token=bogus", nil); err == nil || resp == nil || resp.StatusCode != 401 {
		t.Fatalf("bogus helper token must be 401: %v", err)
	}

	hdr := http.Header{}
	u, _ := http.NewRequest("GET", ts.URL, nil)
	for _, c := range b.c.Jar.Cookies(u.URL) {
		hdr.Add("Cookie", c.Name+"="+c.Value)
	}
	hdr.Set("Origin", ts.URL)
	viewer, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/desktop/"+w.AgentID+"?quality=50", hdr)
	if err != nil {
		t.Fatalf("viewer dial: %v", err)
	}
	defer viewer.Close()

	var helper *websocket.Conn
	select {
	case helper = <-helperConnected:
	case <-time.After(5 * time.Second):
		t.Fatal("helper never connected")
	}
	defer helper.Close()

	// the viewer sees the note and the connected marker, in either order
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		var m map[string]any
		viewer.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := viewer.ReadJSON(&m); err != nil {
			t.Fatalf("viewer read %d: %v", i, err)
		}
		seen[m["t"].(string)] = true
	}
	if !seen["connected"] || !seen["note"] {
		t.Fatalf("expected note+connected, got %v", seen)
	}

	// helper -> viewer binary tile passes through untouched
	tile := []byte{1, 0, 0, 0, 0, 64, 0, 64, 0, 0, 0xff, 0xd8}
	helper.WriteMessage(websocket.BinaryMessage, tile)
	mt, data, err := viewer.ReadMessage()
	if err != nil || mt != websocket.BinaryMessage || string(data) != string(tile) {
		t.Fatalf("tile not bridged: %v %d %x", err, mt, data)
	}
	// viewer -> helper input passes through
	viewer.WriteMessage(websocket.TextMessage, []byte(`{"t":"mousemove","x":10,"y":20}`))
	helper.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, data, err = helper.ReadMessage()
	if err != nil || mt != websocket.TextMessage || string(data) != `{"t":"mousemove","x":10,"y":20}` {
		t.Fatalf("input not bridged: %v %s", err, data)
	}
	// closing the helper closes the viewer
	helper.Close()
	viewer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := viewer.ReadMessage(); err == nil {
		t.Fatal("viewer should be closed when the helper goes away")
	}
	waitFor(t, "pending desktop sessions cleaned up", func() bool {
		s.desktops.mu.Lock()
		defer s.desktops.mu.Unlock()
		return len(s.desktops.pending) == 0
	})
}

// TestBridgeForwardsCloseCode pins rd-03: when one side of the desktop bridge
// goes away the server used to just drop the other socket, so the browser saw
// 1006 (abnormal closure) and could not tell a finished session from a network
// fault. The bridge now forwards a Close frame, carrying the peer's code.
func TestBridgeForwardsCloseCode(t *testing.T) {
	s, ts, b := newTestServer(t)
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab"}, &tok)

	helperConnected := make(chan *websocket.Conn, 1)
	ws, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", http.Header{"X-Enroll-Token": []string{tok.Token}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.WriteJSON(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(protocol.Hello{Hostname: "closebox", OS: "windows"})})
	var welcome protocol.Envelope
	if err := ws.ReadJSON(&welcome); err != nil {
		t.Fatal(err)
	}
	var w struct {
		AgentID string `json:"agent_id"`
	}
	json.Unmarshal(welcome.D, &w)
	go func() {
		for {
			var env protocol.Envelope
			if err := ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqDesktopStart:
				var ds protocol.DesktopStart
				json.Unmarshal(env.D, &ds)
				h, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/desktop-agent?token="+ds.Token, nil)
				if err != nil {
					t.Errorf("helper dial: %v", err)
					return
				}
				helperConnected <- h
				ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, D: protocol.Must(protocol.DesktopStartResult{Started: true})})
			}
		}
	}()
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(w.AgentID) })

	hdr := http.Header{}
	u, _ := http.NewRequest("GET", ts.URL, nil)
	for _, c := range b.c.Jar.Cookies(u.URL) {
		hdr.Add("Cookie", c.Name+"="+c.Value)
	}
	hdr.Set("Origin", ts.URL)
	viewer, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/desktop/"+w.AgentID, hdr)
	if err != nil {
		t.Fatalf("viewer dial: %v", err)
	}
	defer viewer.Close()

	var helper *websocket.Conn
	select {
	case helper = <-helperConnected:
	case <-time.After(5 * time.Second):
		t.Fatal("helper never connected")
	}
	// drain the viewer's "connected" marker so the next read is the close
	viewer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := viewer.ReadMessage(); err != nil {
		t.Fatalf("viewer first read: %v", err)
	}

	// The helper shuts down cleanly, the way the real one does at the end of a
	// session, and the viewer must be told the same thing.
	helper.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"),
		time.Now().Add(2*time.Second))
	helper.Close()

	viewer.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = viewer.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("viewer should see a websocket close, got %T %v", err, err)
	}
	if ce.Code != websocket.CloseNormalClosure {
		t.Fatalf("viewer close code = %d, want %d (1006 means the close frame was never forwarded)", ce.Code, websocket.CloseNormalClosure)
	}
}

// ---- terminal relay ----

// shellAgent is a fake device that answers a shell open the way a real one
// does. openErr is what a device replies when it cannot give you the shell
// you asked for ("bash" on Windows, no ConPTY, no /bin/sh); an empty openErr
// means the shell started and its first prompt streams back. closes receives
// every session the server asked it to end.
type shellAgent struct {
	id     string
	ws     *websocket.Conn
	closes chan string
}

func newShellAgent(t *testing.T, ts *httptest.Server, token, hostname, openErr string) *shellAgent {
	t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/agent", http.Header{"X-Enroll-Token": []string{token}})
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	t.Cleanup(func() { ws.Close() })
	a := &shellAgent{ws: ws, closes: make(chan string, 8)}
	var mu sync.Mutex
	send := func(env protocol.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		ws.WriteJSON(env)
	}
	send(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(protocol.Hello{
		Hostname: hostname, OS: "windows", Arch: "amd64", Version: "test", ProtocolVersion: protocol.Version,
	})})
	var welcome protocol.Envelope
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := ws.ReadJSON(&welcome); err != nil {
		t.Fatalf("welcome: %v", err)
	}
	ws.SetReadDeadline(time.Time{})
	var w struct {
		AgentID string `json:"agent_id"`
	}
	json.Unmarshal(welcome.D, &w)
	a.id = w.AgentID
	go func() {
		for {
			var env protocol.Envelope
			if err := ws.ReadJSON(&env); err != nil {
				return
			}
			switch env.T {
			case protocol.ReqPing:
				send(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			case protocol.ReqShellOpen:
				if openErr != "" {
					send(protocol.Envelope{T: protocol.TypeReply, ID: env.ID, Err: openErr})
					continue
				}
				send(protocol.Envelope{T: protocol.TypeStream, ID: env.ID, D: protocol.Must(protocol.ShellChunk{Session: env.ID, Data: "PS> "})})
			case protocol.ReqShellInput:
				var in protocol.ShellInput
				json.Unmarshal(env.D, &in)
				send(protocol.Envelope{T: protocol.TypeStream, ID: in.Session, D: protocol.Must(protocol.ShellChunk{Session: in.Session, Data: "echo:" + in.Data})})
			case protocol.ReqShellClose:
				var in protocol.ShellClose
				json.Unmarshal(env.D, &in)
				select {
				case a.closes <- in.Session:
				default:
				}
			}
		}
	}()
	return a
}

func readShell(t *testing.T, ws *websocket.Conn) map[string]any {
	t.Helper()
	var m map[string]any
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := ws.ReadJSON(&m); err != nil {
		t.Fatalf("terminal read: %v", err)
	}
	return m
}

// {"t":"opened"} used to be sent the moment the open request had been
// written to the agent socket, so a device that refused the shell announced
// the failure as a success first - {"opened"} then {"error"} then {"closed"}
// - and the server went on to ask the device to close a session that had
// never been created.
func TestShellOpenedMeansTheShellExists(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)

	const refusal = `unsupported shell "bash" on Windows (use powershell or cmd)`
	bad := newShellAgent(t, ts, tok.Token, "refusebox", refusal)
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(bad.id) })

	term, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+bad.id, wsCookies(t, ts, b))
	if err != nil {
		t.Fatalf("terminal dial: %v", err)
	}
	term.WriteJSON(map[string]any{"t": "open", "shell": "bash", "cols": 80, "rows": 24})
	first := readShell(t, term)
	if first["t"] == "opened" {
		t.Fatal(`a shell the device refused was announced as {"t":"opened"} first, so a client that reports "connected" on the marker flashes a false success`)
	}
	if first["t"] != "error" || first["message"] != refusal {
		t.Fatalf("expected the device's refusal, got %v", first)
	}
	if m := readShell(t, term); m["t"] != "closed" {
		t.Fatalf("expected closed after the refusal, got %v", m)
	}
	term.Close()
	select {
	case id := <-bad.closes:
		t.Errorf("server told the device to close %q, a session it had just refused to open", id)
	case <-time.After(500 * time.Millisecond):
	}

	// A device that did open the shell is announced, marker first, and the
	// prompt it streamed before the marker still arrives in order behind it.
	good := newShellAgent(t, ts, tok.Token, "goodbox", "")
	waitFor(t, "second agent online", func() bool { return s.hub.IsOnline(good.id) })
	term2, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+good.id, wsCookies(t, ts, b))
	if err != nil {
		t.Fatalf("second terminal dial: %v", err)
	}
	defer term2.Close()
	term2.WriteJSON(map[string]any{"t": "open", "shell": "powershell", "cols": 80, "rows": 24})
	opened := readShell(t, term2)
	if opened["t"] != "opened" {
		t.Fatalf("expected the opened marker, got %v", opened)
	}
	session, _ := opened["session"].(string)
	if session == "" {
		t.Fatalf("opened carries no session id: %v", opened)
	}
	if p := readShell(t, term2); p["t"] != "out" || p["data"] != "PS> " {
		t.Fatalf("expected the prompt behind the marker, got %v", p)
	}
	term2.Close()
	select {
	case id := <-good.closes:
		if id != session {
			t.Errorf("server closed session %q, want the one it opened (%q)", id, session)
		}
	case <-time.After(5 * time.Second):
		t.Error("a session that really existed was never closed on the device")
	}
}

// A terminal socket is bounded like its siblings: one frame cannot be
// unbounded.
func TestShellSocketCapsAFrame(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	agent := newShellAgent(t, ts, tok.Token, "bigbox", "")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(agent.id) })

	term, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+agent.id, wsCookies(t, ts, b))
	if err != nil {
		t.Fatalf("terminal dial: %v", err)
	}
	defer term.Close()
	term.WriteJSON(map[string]any{"t": "open", "shell": "powershell", "cols": 80, "rows": 24})
	if m := readShell(t, term); m["t"] != "opened" {
		t.Fatalf("expected opened, got %v", m)
	}
	// One well-formed input frame past the cap - an enormous paste - written
	// from its own goroutine because the server stops reading the moment the
	// limit is passed.
	paste := `{"t":"in","data":"` + strings.Repeat("A", int(shellFrameLimit)) + `"}`
	go term.WriteMessage(websocket.TextMessage, []byte(paste))
	ce := readUntilClose(t, term)
	if ce.Code != websocket.CloseMessageTooBig {
		t.Errorf("close code = %d (%q), want %d: one authenticated operator must not be able to make the server buffer an arbitrary frame", ce.Code, ce.Text, websocket.CloseMessageTooBig)
	}
}

// An interactive SYSTEM shell must not outlive the viewer that opened it.
// The terminal socket had no read deadline and no ping, so a browser that
// vanished without a TCP FIN - a closed lid, a dropped VPN, a killed VM -
// left the handler parked in ReadJSON for ever and the shell running on the
// device, invisible to everyone.
func TestShellSocketDropsAViewerThatStoppedAnswering(t *testing.T) {
	oldPing, oldIdle := shellPingPeriod, shellIdleTimeout
	t.Cleanup(func() { shellPingPeriod, shellIdleTimeout = oldPing, oldIdle })
	shellPingPeriod, shellIdleTimeout = 60*time.Millisecond, 600*time.Millisecond

	s, ts, b := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	b.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	agent := newShellAgent(t, ts, tok.Token, "idlebox", "")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(agent.id) })

	// A viewer that is merely quiet still answers pings - every websocket
	// client does, from inside its read loop - and keeps its shell.
	live, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+agent.id, wsCookies(t, ts, b))
	if err != nil {
		t.Fatalf("terminal dial: %v", err)
	}
	defer live.Close()
	live.WriteJSON(map[string]any{"t": "open", "shell": "powershell", "cols": 80, "rows": 24})
	msgs := make(chan map[string]any, 32)
	go func() {
		defer close(msgs)
		for {
			var m map[string]any
			if err := live.ReadJSON(&m); err != nil {
				return
			}
			msgs <- m
		}
	}()
	waitShellOut(t, msgs, "PS> ")
	time.Sleep(3 * shellIdleTimeout)
	live.WriteJSON(map[string]any{"t": "in", "data": "whoami\r"})
	waitShellOut(t, msgs, "echo:whoami")

	// A viewer whose host went away answers nothing.
	gone, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+agent.id, wsCookies(t, ts, b))
	if err != nil {
		t.Fatalf("second terminal dial: %v", err)
	}
	defer gone.Close()
	gone.SetPingHandler(func(string) error { return nil })
	gone.WriteJSON(map[string]any{"t": "open", "shell": "powershell", "cols": 80, "rows": 24})
	start := time.Now()
	ce := readUntilClose(t, gone)
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("the server held the session for %s after the viewer stopped answering", waited)
	}
	if ce.Code != websocket.CloseGoingAway {
		t.Errorf("close code = %d (%q), want %d", ce.Code, ce.Text, websocket.CloseGoingAway)
	}
	select {
	case <-agent.closes:
	case <-time.After(5 * time.Second):
		t.Error("the device was never told to end the shell of a viewer that had gone away")
	}
}

// waitShellOut waits for an out frame containing want.
func waitShellOut(t *testing.T, msgs chan map[string]any, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m, ok := <-msgs:
			if !ok {
				t.Fatalf("the terminal closed while waiting for %q", want)
			}
			if m["t"] == "out" && strings.Contains(fmt.Sprint(m["data"]), want) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}
