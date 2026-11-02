package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/MonsterCouch/homelab-rmm/internal/translog"
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
	OrgID   string `json:"org_id,omitempty"`
	Data    any    `json:"data,omitempty"`
}

type agentConn struct {
	id        string
	hello     protocol.Hello
	tr        agentTransport // the socket or QUIC connection, see transport.go
	writeMu   sync.Mutex
	pending   map[string]chan protocol.Envelope  // request id -> reply
	streams   map[string]func(protocol.Envelope) // request id -> stream sink
	pmu       sync.Mutex
	ip        string
	connected time.Time
	closed    chan struct{}
	closeOnce sync.Once
	lastPong  atomic.Int64 // unix nanos of the last PONG from the agent
	// tl is the server's transparency log (nil in a bare test connection) and
	// logSize the size of the newest head this device says it holds: from its
	// hello, raised by every reply that carries Envelope.Log. send completes a
	// log proof from them.
	tl      *translog.Log
	logSize atomic.Int64
	// logSent is the largest log head this connection has been sent. Requests
	// to one device are written back to back, before the first reply can raise
	// logSize, and the device checks them in arrival order, so each consistency
	// proof starts where the previous one ended rather than where the last
	// reply said the device was. A refused proof resets it (see readLoop).
	logSent atomic.Int64
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

// credentials are what an agent presents to get in: an enrolled device's key
// or the token of a first contact. The WebSocket path reads them from HTTP
// headers and the QUIC path from the auth frame; authenticate treats both the
// same.
type credentials struct {
	key    string
	hasKey bool
	token  string
}

// authenticate checks credentials before any socket or stream is committed to
// the device. For an enrolled agent it returns the device id; for a valid
// enrollment token it returns an empty id (the record is created after hello,
// so it has a hostname). A non-empty refusal is the sentence to send back.
func (h *Hub) authenticate(c credentials) (agentID, refusal string) {
	switch {
	case c.hasKey:
		id, ok := h.s.db.agentByKey(c.key)
		if !ok {
			return "", protocol.ErrUnknownAgentKey
		}
		return id, ""
	case c.token != "":
		// enrollment is completed after hello so the record has a hostname,
		// but the token is checked now so a bad one never gets a socket
		if err := h.s.db.checkEnrollToken(c.token); err != nil {
			return "", protocol.ErrEnrollmentRefused + err.Error()
		}
		return "", ""
	default:
		return "", protocol.ErrMissingCredentials
	}
}

// handleAgentWS is the WebSocket agent endpoint. Two ways in:
//   - Authorization: Bearer <agent key>  (an enrolled agent)
//   - X-Enroll-Token: <token>            (first contact; the reply carries the new id+key)
func (h *Hub) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	ip := h.s.clientIP(r)
	var creds credentials
	if authz := r.Header.Get("Authorization"); strings.HasPrefix(authz, "Bearer ") {
		creds.key, creds.hasKey = strings.TrimPrefix(authz, "Bearer "), true
	}
	creds.token = r.Header.Get("X-Enroll-Token")
	agentID, refusal := h.authenticate(creds)
	if refusal != "" {
		writeErr(w, http.StatusUnauthorized, refusal)
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

	id, newKey, justEnrolled, err := h.identify(agentID, creds.token, &hello, ip)
	if err != nil {
		conn.WriteJSON(protocol.Envelope{T: "error", Err: protocol.ErrEnrollmentRefused + err.Error()})
		conn.Close()
		return
	}
	ac := h.newConn(&wsTransport{conn: conn}, id, hello, ip)
	h.serve(ac, newKey, justEnrolled)
}

// identify settles who a device is once its hello has arrived: an enrolled
// agent keeps its id, a first contact is enrolled now. It is the part of the
// old handleAgentWS that both transports share before they have a connection
// object, including the audit rows that tell an operator about a re-keyed or
// duplicated record.
func (h *Hub) identify(agentID, enrollToken string, hello *protocol.Hello, ip string) (id, newKey string, justEnrolled bool, err error) {
	justEnrolled = agentID == ""
	if agentID == "" {
		en, err := h.s.db.enrollAgent(enrollToken, *hello, ip, h.IsOnline)
		if err != nil {
			slog.Warn("enrollment refused", "ip", ip, "host", hello.Hostname, "err", err)
			return "", "", false, err
		}
		agentID, newKey = en.ID, en.Key
		switch {
		case en.Rekeyed:
			// distinct from a fresh enrollment so an operator can spot a device
			// that took over another's record by claiming its hostname
			h.s.db.Audit("system", ip, "agent.rekeyed", agentID, hello.Hostname)
			h.s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, agentID, now(), "enroll",
				"Device record re-keyed by a new enrollment from "+ip+" (reinstall, or another device claiming this hostname)", "{}")
			slog.Warn("agent record re-keyed by enrollment", "id", agentID, "host", hello.Hostname, "ip", ip)
		case en.DuplicateHostname:
			// The same takeover attempt against a device that happened to be
			// ONLINE: no record was adopted, a second one with the same name
			// was created instead. Two "workstation-7" rows in the console is
			// the confusing outcome, so it gets its own audit action.
			h.s.db.Audit("system", ip, "agent.duplicate_hostname", agentID, hello.Hostname)
			h.s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, agentID, now(), "enroll",
				"Enrolled from "+ip+" under a hostname another device is already using (reinstall with a stale record, or a device claiming this hostname)", "{}")
			slog.Warn("enrollment duplicated an existing hostname", "id", agentID, "host", hello.Hostname, "ip", ip)
		default:
			h.s.db.Audit("system", ip, "agent.enrolled", agentID, hello.Hostname)
		}
	}
	hello.AgentID = agentID
	return agentID, newKey, justEnrolled, nil
}

// newConn builds the hub's record of one live connection over tr.
func (h *Hub) newConn(tr agentTransport, agentID string, hello protocol.Hello, ip string) *agentConn {
	ac := &agentConn{
		id: agentID, hello: hello, tr: tr, ip: ip,
		pending: map[string]chan protocol.Envelope{}, streams: map[string]func(protocol.Envelope){},
		connected: time.Now(), closed: make(chan struct{}), ingest: make(chan protocol.Envelope, ingestQueue),
	}
	ac.tl = h.s.tlog
	ac.logSize.Store(max(hello.LogSize, 0))
	ac.logSent.Store(max(hello.LogSize, 0))
	ac.lastPong.Store(time.Now().UnixNano())
	tr.bind(ac)
	return ac
}

// serve runs an authenticated, identified connection to its end: welcome,
// registration, the online bookkeeping, the read side, and the teardown. It is
// the transport-neutral half of the old handleAgentWS.
func (h *Hub) serve(ac *agentConn, newKey string, justEnrolled bool) {
	agentID, hello, ip := ac.id, ac.hello, ac.ip

	// welcome: identity (for a new enrollment) + config
	welcome := map[string]any{"agent_id": agentID, "config": h.s.agentConfig(agentID)}
	if newKey != "" {
		welcome["agent_key"] = newKey
	}
	if err := ac.send(protocol.Envelope{T: "welcome", D: protocol.Must(welcome)}); err != nil {
		ac.tr.close()
		return
	}
	ac.tr.welcomed()

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
	h.s.db.setAgentTrust(agentID, hello.TrustEpoch, hello.TrustHash)
	h.s.db.setExecutedHead(agentID, hello.ExecutedHead)
	slog.Info("agent connected", "id", agentID, "host", hello.Hostname, "ip", ip, "version", hello.Version, "transport", ac.transportName())
	h.broadcast(hubEvent{Kind: "agent_online", AgentID: agentID})
	h.s.onAgentOnline(agentID)
	if justEnrolled {
		// Fired here, not from a defer: a deferred call runs when this socket
		// finally drops (hours or days later, after the agent_offline
		// automation), so an onboarding automation never ran at enrollment.
		h.s.sched.automation("enrolled", agentID, map[string]any{"hostname": hello.Hostname})
	}

	// Bundle sync waits for the agent's reply, which the read loop below
	// delivers, so it runs beside it and never inside it.
	h.s.goJob(func() { h.s.syncTrust(agentID) })

	go h.keepalive(ac)
	go h.ingestLoop(ac)
	ac.tr.readLoop()

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

// keepaliveEvery and keepaliveDead are how often the hub pings a device and
// how long it tolerates silence before dropping the connection. Variables so a
// test can shrink them; nothing else writes them.
var (
	keepaliveEvery = 30 * time.Second
	keepaliveDead  = 90 * time.Second
)

func (h *Hub) keepalive(ac *agentConn) {
	t := time.NewTicker(keepaliveEvery)
	defer t.Stop()
	for {
		select {
		case <-ac.closed:
			return
		case <-t.C:
			if time.Since(time.Unix(0, ac.lastPong.Load())) > keepaliveDead {
				slog.Warn("agent unresponsive, dropping", "id", ac.id)
				ac.close()
				return
			}
			ac.send(protocol.Envelope{T: protocol.ReqPing, ID: "ka"})
		}
	}
}

// handleFrame is the transport-neutral body of the read side: every frame an
// agent sends, from whichever stream or socket it arrived on, lands here. A
// transport may call it from several goroutines at once (QUIC runs one pump
// per stream), so it touches shared state only under the locks it always did.
func (ac *agentConn) handleFrame(env protocol.Envelope) {
	if env.Log > 0 {
		ac.noteLogSize(env.Log)
		if env.Err != "" && strings.Contains(env.Err, "log proof") {
			// The device refused a proof, so it did not move to the head
			// that was sent: start the next proof from what it holds.
			ac.logSent.Store(env.Log)
		}
	}
	switch env.T {
	case protocol.TypePong:
		// Liveness tracks PONGS, not traffic: an agent that floods frames
		// but never answers a ping is exactly the one keepalive must drop.
		ac.lastPong.Store(time.Now().UnixNano())
	case protocol.TypeReply:
		if env.ID == "ka" {
			return
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

// failRequest ends a request that can no longer be answered, such as a QUIC
// request stream the agent finished without sending its final reply. It is a
// no-op when the request already completed, so the stream's normal end after a
// reply is harmless.
func (ac *agentConn) failRequest(id, msg string) {
	ac.pmu.Lock()
	ch := ac.pending[id]
	delete(ac.pending, id)
	sink := ac.streams[id]
	delete(ac.streams, id)
	ac.pmu.Unlock()
	if ch != nil {
		ch <- protocol.Envelope{ID: id, Err: msg}
	} else if sink != nil {
		sink(protocol.Envelope{T: protocol.TypeReply, ID: id, Err: msg})
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
				h.s.db.setExecutedHead(ac.id, inv.ExecutedHead)
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

// noteLogSize raises the size of the log head the device holds. It never
// lowers it: replies can arrive out of order, and a consistency proof from an
// older size than the device now holds would be refused by it.
func (ac *agentConn) noteLogSize(n int64) {
	for {
		cur := ac.logSize.Load()
		if n <= cur || ac.logSize.CompareAndSwap(cur, n) {
			return
		}
	}
}

// setExecutedHead stores the head of the device's executed.log as it last
// reported it. An empty value (an older agent, or a device that has run
// nothing) leaves the stored one alone.
func (d *DB) setExecutedHead(agentID, head string) {
	if head == "" {
		return
	}
	// A genuine head is the base64 of a SHA-256 digest. Anything else is a
	// confused or hostile device and must not grow its row.
	if raw, err := base64.StdEncoding.DecodeString(head); err != nil || len(raw) != sha256.Size {
		slog.Warn("ignored a malformed executed-log head from a device", "agent", agentID, "length", len(head))
		return
	}
	var old string
	d.QueryRow(`SELECT executed_head FROM agents WHERE id = ?`, agentID).Scan(&old)
	if old == head {
		return
	}
	if _, err := d.Exec(`UPDATE agents SET executed_head = ? WHERE id = ?`, head, agentID); err != nil {
		slog.Warn("cannot store the device's executed-log head", "agent", agentID, "err", err)
		return
	}
	// The server cannot check that a head extends the previous one, but the
	// change is recorded: a device whose executed.log was wiped starts a new
	// chain, and the operator can see that in the audit log as a head that
	// stops following the ones before it.
	if old != "" {
		d.Audit("system", "", "device.executed_head", agentID, map[string]string{"from": old, "to": head})
	}
}

// withLogProof returns env with the transparency log proof completed for this
// connection. The handler only names the manifest's leaf; the head and the
// proofs depend on what the device already holds, so they are made per send.
// The ActionAuth and LogProof are copied: the originals are shared by every
// device of one dispatch (and by a cached grant) and must not be written to.
func (ac *agentConn) withLogProof(env protocol.Envelope) (protocol.Envelope, error) {
	if ac.tl == nil || env.A == nil || env.A.L == nil {
		return env, nil
	}
	l := *env.A.L
	a := *env.A
	a.L = &l
	env.A = &a
	tree, note, err := ac.tl.Head()
	if err != nil {
		return env, fmt.Errorf("transparency log head: %w", err)
	}
	inc, err := ac.tl.ProveInclusion(l.Index, tree.N)
	if err != nil {
		return env, fmt.Errorf("transparency log inclusion proof: %w", err)
	}
	l.Head = base64.StdEncoding.EncodeToString(note)
	l.Proof = translog.EncodeProof(inc)
	l.From, l.Consistency = 0, nil
	from := max(ac.logSize.Load(), ac.logSent.Load())
	if from > 0 && from < tree.N {
		cons, err := ac.tl.ProveConsistency(from, tree.N)
		if err != nil {
			return env, fmt.Errorf("transparency log consistency proof: %w", err)
		}
		l.From, l.Consistency = from, translog.EncodeProof(cons)
	}
	if tree.N > ac.logSent.Load() {
		ac.logSent.Store(tree.N)
	}
	return env, nil
}

// send writes env on the control path: the one ordered channel that carries
// everything not tied to a request id (the welcome, pings, config pushes and
// fire-and-forget notices). withLogProof runs here for every frame, so a
// signed notice carries its proof no matter which transport sends it.
func (ac *agentConn) send(env protocol.Envelope) error {
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()
	env, err := ac.withLogProof(env)
	if err != nil {
		return err
	}
	return ac.tr.writeControl(env)
}

// sendRequest writes a request that expects an answer and returns the stream
// it travels on (nil on a transport with a single socket). The write lock is
// held across the proof and the write, so proofs are made and put on the wire
// in one order.
func (ac *agentConn) sendRequest(env protocol.Envelope) (requestStream, error) {
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()
	prev := ac.logSent.Load()
	env, err := ac.withLogProof(env)
	if err != nil {
		return nil, err
	}
	rs, err := ac.tr.openRequest(env)
	if err != nil {
		// On QUIC a failed open leaves the connection alive and the agent never
		// saw this proof, so the next one must be made from the head the agent
		// does hold. A concurrent reset from an agent refusal wins over this.
		if cur := ac.logSent.Load(); cur != prev {
			ac.logSent.CompareAndSwap(cur, prev)
		}
		return nil, err
	}
	return rs, nil
}

// transportName is "websocket" or "quic", and empty for a bare test record.
func (ac *agentConn) transportName() string {
	if ac.tr == nil {
		return ""
	}
	return ac.tr.name()
}

// closeGraceful tells the agent why the connection is going away before
// dropping it, so a planned restart shows as a clean close in agent.log
// instead of a fault that costs the device a reconnect backoff.
func (ac *agentConn) closeGraceful() {
	if ac.tr != nil {
		ac.tr.closeGraceful()
	}
	ac.close()
}

func (ac *agentConn) close() {
	ac.closeOnce.Do(func() {
		close(ac.closed)
		if ac.tr != nil {
			ac.tr.close()
		}
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
	return h.RequestA(ctx, agentID, typ, payload, out, nil)
}

// RequestA is Request carrying the operator signatures (Envelope.A) that
// authorize the request; nil sends it unsigned.
func (h *Hub) RequestA(ctx context.Context, agentID, typ string, payload any, out any, auth *protocol.ActionAuth) error {
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
	rs, err := ac.sendRequest(protocol.Envelope{T: typ, ID: id, D: d, A: auth})
	if err != nil {
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
		if rs != nil {
			// Nobody is waiting any more: free the stream (QUIC) so a late
			// reply from the agent has nowhere to go.
			rs.abort()
		}
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
	return h.StreamA(agentID, typ, payload, sink, nil)
}

// StreamA is Stream carrying the operator signatures that authorize it.
func (h *Hub) StreamA(agentID, typ string, payload any, sink func(protocol.Envelope), auth *protocol.ActionAuth) (string, func(), error) {
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
	rs, err := ac.sendRequest(protocol.Envelope{T: typ, ID: id, D: d, A: auth})
	if err != nil {
		ac.pmu.Lock()
		delete(ac.streams, id)
		ac.pmu.Unlock()
		return "", nil, err
	}
	cancel := func() {
		ac.pmu.Lock()
		delete(ac.streams, id)
		ac.pmu.Unlock()
		if rs != nil {
			// Nobody listens any more: free the QUIC stream so a wedged
			// script or shell does not keep one of the agent's stream slots.
			rs.abort()
		}
	}
	return id, cancel, nil
}

// Notify sends a fire-and-forget message (shell input, resize, close, config).
func (h *Hub) Notify(agentID, typ string, payload any) error {
	return h.NotifyA(agentID, typ, payload, nil)
}

// NotifyA is Notify carrying the operator signatures that authorize it.
func (h *Hub) NotifyA(agentID, typ string, payload any, auth *protocol.ActionAuth) error {
	ac, ok := h.get(agentID)
	if !ok {
		return ErrAgentOffline
	}
	var d json.RawMessage
	if payload != nil {
		d = protocol.Must(payload)
	}
	return ac.send(protocol.Envelope{T: typ, D: d, A: auth})
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
