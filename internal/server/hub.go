package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Hub owns every live agent socket. It is the single place that knows how to
// send a request to an agent and wait for the reply, and it fans streamed
// chunks (shell output, script output, events) out to whoever subscribed.
type Hub struct {
	s      *Server
	mu     sync.RWMutex
	agents map[string]*agentConn
	// listeners receive every agent state change for the UI event stream.
	listeners map[chan hubEvent]struct{}
}

type hubEvent struct {
	Kind    string `json:"kind"` // agent_online, agent_offline, metrics, inventory, alert, event, run
	AgentID string `json:"agent_id,omitempty"`
	Data    any    `json:"data,omitempty"`
}

type agentConn struct {
	id        string
	hello     protocol.Hello
	conn      *websocket.Conn
	writeMu   sync.Mutex
	pending   map[string]chan protocol.Envelope  // request id -> reply
	streams   map[string]func(protocol.Envelope) // request id -> stream sink
	pmu       sync.Mutex
	ip        string
	connected time.Time
	closed    chan struct{}
	closeOnce sync.Once
	lastPong  time.Time
}

func newHub(s *Server) *Hub {
	return &Hub{s: s, agents: map[string]*agentConn{}, listeners: map[chan hubEvent]struct{}{}}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  64 << 10,
	WriteBufferSize: 64 << 10,
	CheckOrigin:     func(r *http.Request) bool { return true }, // agents have no origin; browser sockets are cookie+header gated
}

// ErrAgentOffline is returned when a request targets an agent that is not connected.
var ErrAgentOffline = errors.New("agent is offline")

// ---- browser event stream ----

func (h *Hub) subscribe() (chan hubEvent, func()) {
	ch := make(chan hubEvent, 64)
	h.mu.Lock()
	h.listeners[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.listeners, ch)
		h.mu.Unlock()
	}
}

func (h *Hub) broadcast(ev hubEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.listeners {
		select {
		case ch <- ev:
		default: // slow consumer: drop rather than block the agent loop
		}
	}
}

// ---- connection lifecycle ----

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// handleAgentWS is the agent endpoint. Two ways in:
//   - Authorization: Bearer <agent key>  (an enrolled agent)
//   - X-Enroll-Token: <token>            (first contact; the reply carries the new id+key)
func (h *Hub) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	var agentID string
	authz := r.Header.Get("Authorization")
	enroll := r.Header.Get("X-Enroll-Token")
	switch {
	case strings.HasPrefix(authz, "Bearer "):
		key := strings.TrimPrefix(authz, "Bearer ")
		id, ok := h.s.db.agentByKey(key)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unknown agent key")
			return
		}
		agentID = id
	case enroll != "":
		// enrolment is completed after hello so the record has a hostname
	default:
		writeErr(w, http.StatusUnauthorized, "missing credentials")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(64 << 20)

	// first frame must be hello
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var env protocol.Envelope
	if err := conn.ReadJSON(&env); err != nil || env.T != protocol.TypeHello {
		conn.WriteJSON(protocol.Envelope{T: "error", Err: "expected hello"})
		conn.Close()
		return
	}
	var hello protocol.Hello
	if err := json.Unmarshal(env.D, &hello); err != nil {
		conn.Close()
		return
	}

	var newKey string
	if agentID == "" {
		id, key, err := h.s.db.enrollAgent(enroll, hello, ip)
		if err != nil {
			conn.WriteJSON(protocol.Envelope{T: "error", Err: "enrolment refused: " + err.Error()})
			conn.Close()
			slog.Warn("enrolment refused", "ip", ip, "host", hello.Hostname, "err", err)
			return
		}
		agentID, newKey = id, key
		h.s.db.Audit("system", ip, "agent.enrolled", agentID, hello.Hostname)
	}
	hello.AgentID = agentID

	ac := &agentConn{
		id: agentID, hello: hello, conn: conn, ip: ip,
		pending: map[string]chan protocol.Envelope{}, streams: map[string]func(protocol.Envelope){},
		connected: time.Now(), closed: make(chan struct{}), lastPong: time.Now(),
	}

	// welcome: identity (for a new enrolment) + config
	welcome := map[string]any{"agent_id": agentID, "config": h.s.agentConfig(agentID)}
	if newKey != "" {
		welcome["agent_key"] = newKey
	}
	if err := ac.send(protocol.Envelope{T: "welcome", D: protocol.Must(welcome)}); err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	// replace any stale socket for the same id
	h.mu.Lock()
	if old := h.agents[agentID]; old != nil {
		old.close()
	}
	h.agents[agentID] = ac
	h.mu.Unlock()

	h.s.db.markOnline(agentID, hello, ip, true)
	slog.Info("agent connected", "id", agentID, "host", hello.Hostname, "ip", ip, "version", hello.Version)
	h.broadcast(hubEvent{Kind: "agent_online", AgentID: agentID})
	h.s.onAgentOnline(agentID)

	go h.keepalive(ac)
	h.readLoop(ac)

	h.mu.Lock()
	if h.agents[agentID] == ac {
		delete(h.agents, agentID)
	}
	h.mu.Unlock()
	ac.close()
	h.s.db.markOnline(agentID, hello, ip, false)
	slog.Info("agent disconnected", "id", agentID, "host", hello.Hostname)
	h.broadcast(hubEvent{Kind: "agent_offline", AgentID: agentID})
	h.s.onAgentOffline(agentID)
}

func (h *Hub) keepalive(ac *agentConn) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ac.closed:
			return
		case <-t.C:
			if time.Since(ac.lastPong) > 90*time.Second {
				slog.Warn("agent unresponsive, dropping", "id", ac.id)
				ac.close()
				return
			}
			ac.send(protocol.Envelope{T: protocol.ReqPing, ID: "ka"})
		}
	}
}

func (h *Hub) readLoop(ac *agentConn) {
	for {
		_, data, err := ac.conn.ReadMessage()
		if err != nil {
			return
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			slog.Warn("bad frame from agent", "id", ac.id, "err", err)
			continue
		}
		ac.lastPong = time.Now()
		switch env.T {
		case protocol.TypePong:
		case protocol.TypeReply:
			if env.ID == "ka" {
				continue
			}
			ac.pmu.Lock()
			ch := ac.pending[env.ID]
			delete(ac.pending, env.ID)
			sink := ac.streams[env.ID]
			delete(ac.streams, env.ID)
			ac.pmu.Unlock()
			if ch != nil {
				ch <- env
			} else if sink != nil {
				sink(env)
			}
		case protocol.TypeStream:
			ac.pmu.Lock()
			sink := ac.streams[env.ID]
			ac.pmu.Unlock()
			if sink != nil {
				sink(env)
			}
		case protocol.TypeInventory:
			var inv protocol.Inventory
			if err := json.Unmarshal(env.D, &inv); err == nil {
				h.s.onInventory(ac.id, &inv)
			}
		case protocol.TypeMetrics:
			var m protocol.Metrics
			if err := json.Unmarshal(env.D, &m); err == nil {
				h.s.onMetrics(ac.id, &m)
			}
		case protocol.TypeEvent:
			var ev protocol.Event
			if err := json.Unmarshal(env.D, &ev); err == nil {
				h.s.onAgentEvent(ac.id, &ev)
			}
		default:
			slog.Debug("unhandled agent frame", "type", env.T)
		}
	}
}

func (ac *agentConn) send(env protocol.Envelope) error {
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()
	ac.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return ac.conn.WriteJSON(env)
}

func (ac *agentConn) close() {
	ac.closeOnce.Do(func() {
		close(ac.closed)
		ac.conn.Close()
		ac.pmu.Lock()
		for id, ch := range ac.pending {
			ch <- protocol.Envelope{ID: id, Err: "agent disconnected"}
			delete(ac.pending, id)
		}
		for id, sink := range ac.streams {
			sink(protocol.Envelope{T: protocol.TypeReply, ID: id, Err: "agent disconnected"})
			delete(ac.streams, id)
		}
		ac.pmu.Unlock()
	})
}

// ---- requests ----

func (h *Hub) get(agentID string) (*agentConn, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ac, ok := h.agents[agentID]
	return ac, ok
}

// IsOnline reports whether an agent socket is live.
func (h *Hub) IsOnline(agentID string) bool {
	_, ok := h.get(agentID)
	return ok
}

// OnlineIDs returns the ids of every connected agent.
func (h *Hub) OnlineIDs() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]string, 0, len(h.agents))
	for id := range h.agents {
		out = append(out, id)
	}
	return out
}

// Request sends a request and waits for its single reply, decoding D into out
// (which may be nil). The context bounds the wait.
func (h *Hub) Request(ctx context.Context, agentID, typ string, payload any, out any) error {
	ac, ok := h.get(agentID)
	if !ok {
		return ErrAgentOffline
	}
	id := randomHex(8)
	ch := make(chan protocol.Envelope, 1)
	ac.pmu.Lock()
	ac.pending[id] = ch
	ac.pmu.Unlock()
	var d json.RawMessage
	if payload != nil {
		d = protocol.Must(payload)
	}
	if err := ac.send(protocol.Envelope{T: typ, ID: id, D: d}); err != nil {
		ac.pmu.Lock()
		delete(ac.pending, id)
		ac.pmu.Unlock()
		return fmt.Errorf("send to agent: %w", err)
	}
	select {
	case <-ctx.Done():
		ac.pmu.Lock()
		delete(ac.pending, id)
		ac.pmu.Unlock()
		return ctx.Err()
	case env := <-ch:
		if env.Err != "" {
			return errors.New(env.Err)
		}
		if out != nil && len(env.D) > 0 {
			return json.Unmarshal(env.D, out)
		}
		return nil
	}
}

// Stream sends a request whose answer arrives as a sequence of TypeStream
// frames followed by one TypeReply; every frame is passed to sink. It returns
// the request id so the caller can address follow-up messages (shell input)
// and a cancel that detaches the sink.
func (h *Hub) Stream(agentID, typ string, payload any, sink func(protocol.Envelope)) (string, func(), error) {
	ac, ok := h.get(agentID)
	if !ok {
		return "", nil, ErrAgentOffline
	}
	id := randomHex(8)
	ac.pmu.Lock()
	ac.streams[id] = sink
	ac.pmu.Unlock()
	var d json.RawMessage
	if payload != nil {
		d = protocol.Must(payload)
	}
	if err := ac.send(protocol.Envelope{T: typ, ID: id, D: d}); err != nil {
		ac.pmu.Lock()
		delete(ac.streams, id)
		ac.pmu.Unlock()
		return "", nil, err
	}
	cancel := func() {
		ac.pmu.Lock()
		delete(ac.streams, id)
		ac.pmu.Unlock()
	}
	return id, cancel, nil
}

// Notify sends a fire-and-forget message (shell input, resize, close, config).
func (h *Hub) Notify(agentID, typ string, payload any) error {
	ac, ok := h.get(agentID)
	if !ok {
		return ErrAgentOffline
	}
	var d json.RawMessage
	if payload != nil {
		d = protocol.Must(payload)
	}
	return ac.send(protocol.Envelope{T: typ, D: d})
}

// Disconnect drops an agent's socket; it will reconnect on its own schedule.
func (h *Hub) Disconnect(agentID string) {
	if ac, ok := h.get(agentID); ok {
		ac.close()
	}
}
