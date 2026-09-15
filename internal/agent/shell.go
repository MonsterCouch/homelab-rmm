package agent

import (
	"errors"
	"io"
	"sync"

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
}

func newShellManager() *shellManager { return &shellManager{sessions: map[string]ptySession{}} }

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
	m.mu.Lock()
	m.sessions[id] = p
	m.mu.Unlock()
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := p.Read(buf)
			if n > 0 {
				c.stream(id, protocol.ShellChunk{Session: id, Data: string(buf[:n])})
			}
			if err != nil {
				break
			}
		}
		m.mu.Lock()
		delete(m.sessions, id)
		m.mu.Unlock()
		p.Close()
		c.reply(id, protocol.ShellChunk{Session: id, EOF: true})
	}()
	return nil
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

func (m *shellManager) close(id string) {
	m.mu.Lock()
	p := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if p != nil {
		p.Close()
	}
}

func (m *shellManager) closeAll() {
	m.mu.Lock()
	all := m.sessions
	m.sessions = map[string]ptySession{}
	m.mu.Unlock()
	for _, p := range all {
		p.Close()
	}
}

var errNoShell = errors.New("no such shell session")
