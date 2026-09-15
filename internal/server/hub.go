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
	"sync/atomic"
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
	Kind    string `json:"kind"` // agent_online, agent_offline, metrics, inventory, alert, event, run, baseline
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
	lastPong  atomic.Int64 // unix nanos of the last PONG from the agent
	// ingest is the bounded queue between the read loop and the goroutine
	// that writes inventory/metrics/events to SQLite. Without it a device
	// that talks fast enough monopolises the single database connection from
	// inside the read loop and starves every HTTP request (see SRV-14).
	ingest  chan protocol.Envelope
	dropped atomic.Int64
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

// maxAgentFrame caps one agent frame. The largest legitimate payload is a
// file-read reply (fsChunk raw bytes, ~4/3 of that once base64-encoded inside
// JSON), so this leaves ample room while refusing to buffer the 64 MB a
// runaway or hostile agent used to be allowed to pin per socket.
const maxAgentFrame = 16 << 20

// ingestQueue is how many inventory/metrics/event frames may wait for the
// database before the newest metrics samples start being dropped. Metrics are
// the only frame kind that is safe to drop: the next sample supersedes it.
const ingestQueue = 64

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
	ip := h.s.clientIP(r)
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
		// enrolment is completed after hello so the record has a hostname,
		// but the token is checked now so a bad one never gets a socket
		if err := h.s.db.checkEnrollToken(enroll); err != nil {
			writeErr(w, http.StatusUnauthorized, "enrolment refused: "+err.Error())
			return
		}
	default:
		writeErr(w, http.StatusUnauthorized, "missing credentials")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(maxAgentFrame)

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
	justEnrolled := agentID == ""
	if agentID == "" {
		en, err := h.s.db.enrollAgent(enroll, hello, ip, h.IsOnline)
		if err != nil {
			conn.WriteJSON(protocol.Envelope{T: "error", Err: "enrolment refused: " + err.Error()})
			conn.Close()
			slog.Warn("enrolment refused", "ip", ip, "host", hello.Hostname, "err", err)
			return
		}
		agentID, newKey = en.ID, en.Key
		switch {
		case en.Rekeyed:
			// distinct from a fresh enrolment so an operator can spot a device
			// that took over another's record by claiming its hostname
			h.s.db.Audit("system", ip, "agent.rekeyed", agentID, hello.Hostname)
			h.s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, agentID, now(), "enrol",
				"Device record re-keyed by a new enrolment from "+ip+" (reinstall, or another device claiming this hostname)", "{}")
			slog.Warn("agent record re-keyed by enrolment", "id", agentID, "host", hello.Hostname, "ip", ip)
		case en.DuplicateHostname:
			// The same takeover attempt against a device that happened to be
			// ONLINE: no record was adopted, a second one with the same name
			// was created instead. Two "workstation-7" rows in the console is
			// the confusing outcome, so it gets its own audit action.
			h.s.db.Audit("system", ip, "agent.duplicate_hostname", agentID, hello.Hostname)
			h.s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, agentID, now(), "enrol",
				"Enrolled from "+ip+" under a hostname another device is already using (reinstall with a stale record, or a device claiming this hostname)", "{}")
			slog.Warn("enrolment duplicated an existing hostname", "id", agentID, "host", hello.Hostname, "ip", ip)
		default:
			h.s.db.Audit("system", ip, "agent.enrolled", agentID, hello.Hostname)
		}
	}
	hello.AgentID = agentID

	ac := &agentConn{
		id: agentID, hello: hello, conn: conn, ip: ip,
		pending: map[string]chan protocol.Envelope{}, streams: map[string]func(protocol.Envelope){},
		connected: time.Now(), closed: make(chan struct{}), ingest: make(chan protocol.Envelope, ingestQueue),
	}
	ac.lastPong.Store(time.Now().UnixNano())

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

	// Replace any stale socket for the same id. The old connection is swapped
	// out under the lock and closed AFTER releasing it: close() hands the
	// synthetic "agent disconnected" reply to every registered sink, and a
	// sink (a live script run) calls back into the hub through broadcast(),
	// which takes h.mu.RLock(). sync.RWMutex is not reentrant, so closing
	// while holding the write lock wedged the hub forever - and the path is
	// the ordinary one for a half-open socket after a sleep or a wifi drop.
	h.mu.Lock()
	old := h.agents[agentID]
	h.agents[agentID] = ac
	h.mu.Unlock()
	if old != nil {
		old.close()
	}

	h.s.db.markOnline(agentID, hello, ip, true)
	slog.Info("agent connected", "id", agentID, "host", hello.Hostname, "ip", ip, "version", hello.Version)
	h.broadcast(hubEvent{Kind: "agent_online", AgentID: agentID})
	h.s.onAgentOnline(agentID)
	if justEnrolled {
		// Fired here, not from a defer: a deferred call runs when this socket
		// finally drops (hours or days later, after the agent_offline
		// automation), so an onboarding automation never ran at enrolment.
		h.s.sched.automation("enrolled", agentID, map[string]any{"hostname": hello.Hostname})
	}

	go h.keepalive(ac)
	go h.ingestLoop(ac)
	h.readLoop(ac)

	// Only the socket that is still the device's current one may declare it
	// offline. A replaced socket's teardown would otherwise race the new
	// socket's markOnline(true) and leave a live device recorded as offline,
	// flapping the UI and firing a spurious agent_offline automation.
	h.mu.Lock()
	mine := h.agents[agentID] == ac
	if mine {
		delete(h.agents, agentID)
	}
	h.mu.Unlock()
	ac.close()
	if !mine {
		slog.Info("stale agent socket closed", "id", agentID, "host", hello.Hostname)
		return
	}
	if h.IsOnline(agentID) {
		// a replacement registered while this teardown was running
		return
	}
	h.s.db.markOnline(agentID, hello, ip, false)
	slog.Info("agent disconnected", "id", agentID, "host", hello.Hostname)
	h.broadcast(hubEvent{Kind: "agent_offline", AgentID: agentID})
	h.s.onAgentOffline(agentID)
	h.s.sched.automation("agent_offline", agentID, nil)
}

func (h *Hub) keepalive(ac *agentConn) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ac.closed:
			return
		case <-t.C:
			if time.Since(time.Unix(0, ac.lastPong.Load())) > 90*time.Second {
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
		switch env.T {
		case protocol.TypePong:
			// Liveness tracks PONGS, not traffic: an agent that floods frames
			// but never answers a ping is exactly the one keepalive must drop.
			ac.lastPong.Store(time.Now().UnixNano())
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
		case protocol.TypeInventory, protocol.TypeMetrics, protocol.TypeEvent, protocol.TypeBaseline:
			// A baseline report is not droppable like a metrics sample: it is
			// the only record of a pass that may have run while the device was
			// offline, so it follows the inventory path (push back, then warn).
			ac.enqueue(env)
		default:
			slog.Debug("unhandled agent frame", "type", env.T)
		}
	}
}

// enqueue hands a data frame to the ingest goroutine. Metrics are dropped
// when the queue is full (the next sample is the one that matters); inventory
// and events are kept because they are rare and not reproducible.
func (ac *agentConn) enqueue(env protocol.Envelope) {
	select {
	case ac.ingest <- env:
		return
	default:
	}
	if env.T == protocol.TypeMetrics {
		if n := ac.dropped.Add(1); n%100 == 1 {
			slog.Warn("agent ingest queue full, dropping metrics", "id", ac.id, "dropped", n)
		}
		return
	}
	// Inventory and events are rare and not reproducible, so they push back on
	// the read loop rather than being dropped - but only for a bounded time,
	// because this socket's replies and shell output queue behind them.
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case ac.ingest <- env:
	case <-ac.closed:
	case <-timer.C:
		slog.Warn("agent ingest queue stalled, dropping frame", "id", ac.id, "type", env.T)
	}
}

// ingestLoop writes agent data frames to SQLite off the read loop, so one
// chatty device cannot hold the single database connection while every HTTP
// request and every other agent waits behind it.
func (h *Hub) ingestLoop(ac *agentConn) {
	handle := func(env protocol.Envelope) {
		switch env.T {
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
		case protocol.TypeBaseline:
			var rep protocol.BaselineReport
			if err := json.Unmarshal(env.D, &rep); err == nil {
				h.s.onBaselineReport(ac.id, &rep)
			} else {
				slog.Warn("bad baseline report", "id", ac.id, "err", err)
			}
		}
	}
	for {
		select {
		case env := <-ac.ingest:
			handle(env)
		case <-ac.closed:
			// drain what is already queued: a device that sends its inventory
			// and immediately drops should not lose it
			for {
				select {
				case env := <-ac.ingest:
					handle(env)
				default:
					return
				}
			}
		}
	}
}

func (ac *agentConn) send(env protocol.Envelope) error {
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()
	ac.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return ac.conn.WriteJSON(env)
}

// closeGraceful tells the agent why the socket is going away before dropping
// it, so a planned restart shows as a clean close in agent.log instead of a
// 1006 fault that costs the device a reconnect backoff.
func (ac *agentConn) closeGraceful() {
	ac.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseServiceRestart, "server shutting down"),
		time.Now().Add(2*time.Second))
	ac.close()
}

func (ac *agentConn) close() {
	ac.closeOnce.Do(func() {
		close(ac.closed)
		ac.conn.Close()
		ac.pmu.Lock()
		pending, streams := ac.pending, ac.streams
		ac.pending, ac.streams = map[string]chan protocol.Envelope{}, map[string]func(protocol.Envelope){}
		ac.pmu.Unlock()
		// Delivered on a goroutine of its own: a sink calls back into the hub
		// (a run sink broadcasts, which takes h.mu) and a shell sink can block
		// for its full write deadline on a stuck viewer. Neither may run on
		// the caller's stack - close() is reached from the hub's own lock
		// region and from HTTP handlers.
		go func() {
			for id, ch := range pending {
				ch <- protocol.Envelope{ID: id, Err: "agent disconnected"}
			}
			for id, sink := range streams {
				sink(protocol.Envelope{T: protocol.TypeReply, ID: id, Err: "agent disconnected"})
			}
		}()
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

// CloseAll sends every connected agent a close frame and drops the socket.
// Used at shutdown so devices see a planned close rather than a TCP reset.
func (h *Hub) CloseAll() {
	h.mu.RLock()
	conns := make([]*agentConn, 0, len(h.agents))
	for _, ac := range h.agents {
		conns = append(conns, ac)
	}
	h.mu.RUnlock()
	for _, ac := range conns {
		ac.closeGraceful()
	}
}

// waitClosed waits (at most d) for the agent read loops to finish their
// teardown, so shutdown does not close the database under them.
func (h *Hub) waitClosed(d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		h.mu.RLock()
		n := len(h.agents)
		h.mu.RUnlock()
		if n == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Disconnect drops an agent's socket; it will reconnect on its own schedule.
func (h *Hub) Disconnect(agentID string) {
	if ac, ok := h.get(agentID); ok {
		ac.close()
	}
}
