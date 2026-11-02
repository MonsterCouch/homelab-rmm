package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// A control-stream write that fails must take the connection with it, because
// a frame cut short leaves the stream unreadable for every frame after it.
func TestQUICControlWriteFailureClosesTheConnection(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	// STOP_SENDING on the control stream makes the server's next write fail.
	c.ctrl.CancelRead(9)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && c.conn.Context().Err() == nil {
		s.hub.Notify(wl.AgentID, protocol.ReqShellInput, protocol.ShellInput{Session: "s1", Data: "x"})
		time.Sleep(20 * time.Millisecond)
	}
	if c.conn.Context().Err() == nil {
		t.Fatal("the connection stayed open after the control stream write failed")
	}
	var ae *quic.ApplicationError
	if err := context.Cause(c.conn.Context()); !errors.As(err, &ae) || ae.ErrorCode != quicCodeProtocol {
		t.Fatalf("connection closed with %v, want application code %d", context.Cause(c.conn.Context()), quicCodeProtocol)
	}
}

// Cancelling a Stream must free the request's QUIC stream, or a wedged script
// keeps one of the agent's stream slots for good.
func TestQUICStreamACancelAbortsTheRequestStream(t *testing.T) {
	s, _, b, q := newQUICServer(t)
	c, wl := connectQUIC(t, s, b, q, "box")
	_, cancel, err := s.hub.StreamA(wl.AgentID, protocol.ReqShellInput, nil, func(protocol.Envelope) {}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.acceptRequest(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.st.SetWriteDeadline(time.Now().Add(time.Second))
		if err := writeTestFrame(r.st, protocol.Envelope{T: protocol.TypeStream, ID: r.Env.ID}); err != nil {
			var se *quic.StreamError
			if !errors.As(err, &se) || se.ErrorCode != quicCodeAbort {
				t.Fatalf("write after cancel failed with %v, want the abort code %d", err, quicCodeAbort)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the request stream was still writable after the Stream was cancelled")
}

// Connections that have shaken hands but not authenticated are capped, and a
// slot comes back when one of them goes.
func TestQUICPreAuthConnectionsAreCapped(t *testing.T) {
	old := maxPreAuthConns
	maxPreAuthConns = 2
	t.Cleanup(func() { maxPreAuthConns = old })
	s, _, _, q := newQUICServer(t)

	c1 := dialQUIC(t, q.addr(), s.Fingerprint())
	c2 := dialQUIC(t, q.addr(), s.Fingerprint())
	waitFor(t, "two connections to hold slots", func() bool { return len(q.preauth) == 2 })
	c3 := dialQUIC(t, q.addr(), s.Fingerprint())
	select {
	case <-c3.conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a third unauthenticated connection was not turned away")
	}
	var ae *quic.ApplicationError
	if err := context.Cause(c3.conn.Context()); !errors.As(err, &ae) || ae.ErrorCode != quicCodeRefused {
		t.Fatalf("third connection closed with %v, want application code %d", err, quicCodeRefused)
	}
	if c1.conn.Context().Err() != nil || c2.conn.Context().Err() != nil {
		t.Fatal("the cap closed a connection that was within it")
	}
	c1.close()
	waitFor(t, "a slot to come back", func() bool { return len(q.preauth) < 2 })
}

// With the Retry threshold at zero every handshake goes through address
// validation, and an honest client must still get in.
func TestQUICHandshakeSucceedsThroughRetry(t *testing.T) {
	oldG, oldIP := quicRetryAbove, quicRetryAbovePerIP
	quicRetryAbove, quicRetryAbovePerIP = 0, 0
	t.Cleanup(func() { quicRetryAbove, quicRetryAbovePerIP = oldG, oldIP })
	s, _, b, q := newQUICServer(t)
	connectQUIC(t, s, b, q, "box")
}
