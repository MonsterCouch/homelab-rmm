package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ---- remote shell ----
//
// Browser <-WS-> server <-agent socket-> agent. The browser sends JSON:
//   {"t":"open","shell":"powershell","cols":120,"rows":30}
//   {"t":"in","data":"ls\r"}  {"t":"resize","cols":..,"rows":..}
// and receives {"t":"out","data":...}, {"t":"opened","session":..}, {"t":"closed"}.

func (s *Server) handleShellWS(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if !s.hub.IsOnline(agentID) {
		writeErr(w, 409, "agent is offline")
		return
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	var wmu sync.Mutex
	send := func(v any) {
		wmu.Lock()
		defer wmu.Unlock()
		ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
		ws.WriteJSON(v)
	}

	var (
		session string
		cancel  func()
	)
	defer func() {
		if session != "" {
			s.hub.Notify(agentID, protocol.ReqShellClose, protocol.ShellClose{Session: session})
		}
		if cancel != nil {
			cancel()
		}
	}()
	s.audit(r, "shell.open", agentID, nil)

	for {
		var msg struct {
			T     string `json:"t"`
			Shell string `json:"shell"`
			Data  string `json:"data"`
			Cols  int    `json:"cols"`
			Rows  int    `json:"rows"`
		}
		if err := ws.ReadJSON(&msg); err != nil {
			return
		}
		switch msg.T {
		case "open":
			if session != "" {
				continue
			}
			id, c, err := s.hub.Stream(agentID, protocol.ReqShellOpen, protocol.ShellOpen{Shell: msg.Shell, Cols: msg.Cols, Rows: msg.Rows}, func(env protocol.Envelope) {
				if env.Err != "" {
					send(map[string]any{"t": "error", "message": env.Err})
					send(map[string]any{"t": "closed"})
					return
				}
				var chunk protocol.ShellChunk
				if json.Unmarshal(env.D, &chunk) != nil {
					return
				}
				if chunk.EOF || env.T == protocol.TypeReply {
					send(map[string]any{"t": "closed"})
					return
				}
				send(map[string]any{"t": "out", "data": chunk.Data})
			})
			if err != nil {
				send(map[string]any{"t": "error", "message": err.Error()})
				return
			}
			session, cancel = id, c
			send(map[string]any{"t": "opened", "session": id})
		case "in":
			if session != "" {
				s.hub.Notify(agentID, protocol.ReqShellInput, protocol.ShellInput{Session: session, Data: msg.Data})
			}
		case "resize":
			if session != "" {
				s.hub.Notify(agentID, protocol.ReqShellResize, protocol.ShellResize{Session: session, Cols: msg.Cols, Rows: msg.Rows})
			}
		case "close":
			return
		}
	}
}

// ---- remote desktop ----
//
// The viewer connects to /ws/desktop/{agent}. The server asks the agent to
// start its desktop helper with a one-time token; the helper connects to
// /ws/desktop-agent?token=... and the two sockets are bridged byte for byte:
// binary frames (screen tiles) flow helper->viewer, text frames (input)
// flow viewer->helper. The server never decodes video.

type desktopBroker struct {
	mu      sync.Mutex
	pending map[string]*desktopSession
}

type desktopSession struct {
	agentID string
	viewer  *websocket.Conn
	helper  chan *websocket.Conn
	created time.Time
}

func newDesktopBroker() *desktopBroker { return &desktopBroker{pending: map[string]*desktopSession{}} }

func (s *Server) handleDesktopViewerWS(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if !s.hub.IsOnline(agentID) {
		writeErr(w, 409, "agent is offline")
		return
	}
	viewer, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer viewer.Close()
	viewer.SetReadLimit(1 << 20)

	token := randomToken(24)
	ds := &desktopSession{agentID: agentID, viewer: viewer, helper: make(chan *websocket.Conn, 1), created: time.Now()}
	s.desktops.mu.Lock()
	s.desktops.pending[token] = ds
	s.desktops.mu.Unlock()
	defer func() {
		s.desktops.mu.Lock()
		delete(s.desktops.pending, token)
		s.desktops.mu.Unlock()
	}()
	s.audit(r, "desktop.open", agentID, nil)

	quality := int(queryInt(r, "quality", 60))
	go func() {
		var res protocol.DesktopStartResult
		err := s.hub.Request(r.Context(), agentID, protocol.ReqDesktopStart, protocol.DesktopStart{Token: token, Quality: quality}, &res)
		if err != nil {
			viewer.WriteMessage(websocket.TextMessage, []byte(`{"t":"error","message":`+jsonText(err.Error())+`}`))
			viewer.Close()
		} else if res.Note != "" {
			viewer.WriteMessage(websocket.TextMessage, []byte(`{"t":"note","message":`+jsonText(res.Note)+`}`))
		}
	}()

	var helper *websocket.Conn
	select {
	case helper = <-ds.helper:
	case <-time.After(30 * time.Second):
		viewer.WriteMessage(websocket.TextMessage, []byte(`{"t":"error","message":"desktop helper did not connect within 30 seconds"}`))
		return
	case <-r.Context().Done():
		return
	}
	defer helper.Close()
	viewer.WriteMessage(websocket.TextMessage, []byte(`{"t":"connected"}`))
	bridge(viewer, helper)
}

// handleDesktopAgentWS is where the helper process connects. Its token is the
// only credential: it is single-use, random and expires with the viewer.
func (s *Server) handleDesktopAgentWS(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	s.desktops.mu.Lock()
	ds := s.desktops.pending[token]
	s.desktops.mu.Unlock()
	if ds == nil {
		writeErr(w, 401, "unknown desktop session")
		return
	}
	helper, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	helper.SetReadLimit(32 << 20)
	select {
	case ds.helper <- helper:
	default:
		helper.Close()
		return
	}
	// keep the handler alive until the bridge closes the socket
	<-r.Context().Done()
}

// bridge pumps frames both ways until either side closes.
func bridge(a, b *websocket.Conn) {
	done := make(chan struct{}, 2)
	pump := func(src, dst *websocket.Conn) {
		defer func() { done <- struct{}{} }()
		var mu sync.Mutex
		for {
			mt, data, err := src.ReadMessage()
			if err != nil {
				return
			}
			mu.Lock()
			dst.SetWriteDeadline(time.Now().Add(15 * time.Second))
			err = dst.WriteMessage(mt, data)
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}
	go pump(a, b)
	go pump(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
	slog.Debug("desktop bridge closed")
}
