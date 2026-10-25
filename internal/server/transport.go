package server

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// agentTransport is what the hub needs from the thing an agent is connected
// over. Two implementations exist: one WebSocket (every frame shares the
// socket, replies are matched by id) and one QUIC connection (a control stream
// plus one stream per request, see hub_quic.go). Everything above this seam -
// requests, sinks, keepalive, log proofs, ingest - is the same for both.
//
// Writers are serialised by agentConn.writeMu, so the write methods need no
// locking of their own. readLoop and the per-stream pumps a transport starts
// call agentConn.handleFrame, which may run from several goroutines.
type agentTransport interface {
	// name is "websocket" or "quic"; it is shown on the device row.
	name() string
	// bind gives the transport the connection record its read side feeds.
	// It runs before the connection is registered, so no locking is needed.
	bind(ac *agentConn)
	// writeControl sends a frame that belongs to no request: welcome, ping,
	// config pushes, notices with an empty id.
	writeControl(env protocol.Envelope) error
	// openRequest sends a request frame that has an id and expects an answer.
	// A transport with one socket writes it there and returns a nil
	// requestStream; QUIC opens a stream of its own, starts reading answers
	// from it and returns it.
	openRequest(env protocol.Envelope) (requestStream, error)
	// welcomed runs once the welcome frame is out, to lift the handshake-only
	// read deadline.
	welcomed()
	// readLoop reads the control path until the connection ends, handing each
	// frame to the bound connection.
	readLoop()
	// closeGraceful tells the agent the server is going away on purpose.
	closeGraceful()
	// close drops the connection; it is idempotent.
	close()
}

// requestStream is the handle on one request's stream.
type requestStream interface {
	// abort resets the stream because nobody waits for its answer any more.
	abort()
}

// wsTransport is today's transport: one WebSocket, every frame on it, with
// replies and stream chunks demultiplexed by Envelope.ID.
type wsTransport struct {
	conn *websocket.Conn
	ac   *agentConn
}

func (t *wsTransport) name() string { return "websocket" }

func (t *wsTransport) bind(ac *agentConn) { t.ac = ac }

func (t *wsTransport) writeControl(env protocol.Envelope) error {
	t.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return t.conn.WriteJSON(env)
}

func (t *wsTransport) openRequest(env protocol.Envelope) (requestStream, error) {
	return nil, t.writeControl(env)
}

func (t *wsTransport) welcomed() { t.conn.SetReadDeadline(time.Time{}) }

func (t *wsTransport) readLoop() {
	for {
		_, data, err := t.conn.ReadMessage()
		if err != nil {
			return
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			slog.Warn("bad frame from agent", "id", t.ac.id, "err", err)
			continue
		}
		t.ac.handleFrame(env)
	}
}

func (t *wsTransport) closeGraceful() {
	t.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseServiceRestart, "server shutting down"),
		time.Now().Add(2*time.Second))
}

func (t *wsTransport) close() { t.conn.Close() }
