package agent

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ptySession is what the platform shell file returns: a pseudo-terminal
// wrapping an interactive shell. Windows uses ConPTY, Linux a pty.
type ptySession interface {
	io.Reader
	io.Writer
	Resize(cols, rows int) error
	Close() error
}

// shellManager tracks open terminal sessions keyed by the request id the
// server used to open them, so input/resize/close frames can find them.
type shellManager struct {
	mu       sync.Mutex
	sessions map[string]ptySession
	rtcs     map[string]*shellRTC // WebRTC byte path of sessions opened with RTC
}

func newShellManager() *shellManager {
	return &shellManager{sessions: map[string]ptySession{}, rtcs: map[string]*shellRTC{}}
}

func (m *shellManager) open(id string, req protocol.ShellOpen, c *conn) error {
	if req.Cols <= 0 {
		req.Cols = 120
	}
	if req.Rows <= 0 {
		req.Rows = 30
	}
	p, err := startPTY(req.Shell, req.Cols, req.Rows)
	if err != nil {
		return err
	}
	m.attach(id, p, req, c.stream, c.reply)
	return nil
}

// attach registers a started pty under id and pumps its output until it ends.
// stream sends a frame on the open request's stream (the WebSocket relay path)
// and reply ends it.
func (m *shellManager) attach(id string, p ptySession, req protocol.ShellOpen, stream, reply func(id string, v any) error) {
	var rtc *shellRTC
	if req.RTC {
		rtc = newShellRTC(id, p, req.ICEServers, func(v any) error { return stream(id, v) }, func() { m.close(id) })
	}
	m.mu.Lock()
	m.sessions[id] = p
	if rtc != nil {
		m.rtcs[id] = rtc
	}
	m.mu.Unlock()
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := p.Read(buf)
			if n > 0 {
				via := func(b []byte) { stream(id, protocol.ShellChunk{Session: id, Data: string(b)}) }
				if rtc != nil {
					rtc.emit(buf[:n], via)
				} else {
					via(buf[:n])
				}
			}
			if err != nil {
				break
			}
		}
		m.mu.Lock()
		delete(m.sessions, id)
		delete(m.rtcs, id)
		m.mu.Unlock()
		if rtc != nil {
			rtc.drain(2 * time.Second)
			rtc.close()
		}
		p.Close()
		reply(id, protocol.ShellChunk{Session: id, EOF: true})
	}()
}

func (m *shellManager) get(id string) ptySession {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

func (m *shellManager) input(id, data string) {
	if p := m.get(id); p != nil {
		p.Write([]byte(data))
	}
}

func (m *shellManager) resize(id string, cols, rows int) {
	if p := m.get(id); p != nil {
		p.Resize(cols, rows)
	}
}

// rtcSignal handles one ReqShellRTC frame. A session that does not exist, or
// was not opened with RTC, refuses it.
func (m *shellManager) rtcSignal(sig protocol.ShellRTC) error {
	m.mu.Lock()
	r := m.rtcs[sig.Session]
	m.mu.Unlock()
	if r == nil {
		return errNoShell
	}
	return r.handleSignal(sig)
}

func (m *shellManager) close(id string) {
	m.mu.Lock()
	p := m.sessions[id]
	r := m.rtcs[id]
	delete(m.sessions, id)
	delete(m.rtcs, id)
	m.mu.Unlock()
	if r != nil {
		r.close()
	}
	if p != nil {
		p.Close()
	}
}

func (m *shellManager) closeAll() {
	m.mu.Lock()
	all := m.sessions
	rtcs := m.rtcs
	m.sessions = map[string]ptySession{}
	m.rtcs = map[string]*shellRTC{}
	m.mu.Unlock()
	for _, r := range rtcs {
		r.close()
	}
	for _, p := range all {
		p.Close()
	}
}

var errNoShell = errors.New("no such shell session")
