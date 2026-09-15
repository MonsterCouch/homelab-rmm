package server

import (
	"encoding/json"
	"net/http"
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
