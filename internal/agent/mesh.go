package agent

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/cache"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// defaultCachePort is the port a leader binds when the server names none; the
// documented firewall rule is TCP and UDP on it from the subnet.
const defaultCachePort = 7443

// cacheDirName is the content-addressable store under the config directory.
const cacheDirName = "cache"

// meshState is the agent's side of the subnet cache (docs/plans/2026-10-24-
// phase4b-mesh-cache.md): what the server assigned, the leader server when this
// device is the leader, and the counters reported in inventory. Everything is
// optional: a device that cannot make a certificate or bind the port is simply
// not cache capable, and the agent behaves exactly as it did before.
type meshState struct {
	mu sync.Mutex

	idOnce      sync.Once
	cert        tls.Certificate
	fingerprint string
	capable     bool

	cfg    *protocol.CacheConfig
	tokens []string // newest first, at most two, so a leader outlives the midnight rollover
	srv    *cache.Server
	srvKey string
	store  *cache.Store
	fwPort int

	// serveFailed is set when this device was assigned to lead but could not
	// (the store would not open or the port would not bind). It is reported so
	// the server picks another leader, and it keeps this device's own updates
	// off a leader that is not there.
	serveFailed bool

	// fwMu guards the queue of firewall calls, which run on one background
	// goroutine so that netsh never holds mu or the session reader.
	fwMu    sync.Mutex
	fwQueue []func()
	fwBusy  bool

	// served counts what the leader's handlers did; fetched what this device's
	// own fetches through a leader did. Role decides which is reported.
	served  cache.Stats
	fetched cache.Stats
}

// identity prepares the leader certificate once and reports whether this
// device could act as a leader, with the fingerprint members will pin. It is
// lazy so an agent that never reaches the server (and every unit test that
// builds an Agent) leaves nothing in the config directory.
func (m *meshState) identity() (capable bool, fingerprint string) {
	m.idOnce.Do(func() {
		if os.Getenv("RMM_MESH_CACHE") == "off" {
			return
		}
		if err := EnsureConfigDir(); err != nil {
			slog.Warn("the subnet cache is unavailable: the configuration directory cannot be prepared", "err", err)
			return
		}
		cert, fp, err := cache.LoadOrCreateCert(ConfigDir())
		if err != nil {
			slog.Warn("the subnet cache is unavailable: no certificate", "err", err)
			return
		}
		m.cert, m.fingerprint, m.capable = cert, fp, true
	})
	return m.capable, m.fingerprint
}

// currentTokens is what the leader accepts: the token of the latest config and
// the one before it.
func (m *meshState) currentTokens() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.tokens...)
}

// apply puts a pushed cache assignment into effect: it starts, retunes or
// stops the leader server and rebuilds the member client. A nil assignment
// turns everything off.
func (m *meshState) apply(a *Agent, c *protocol.CacheConfig) {
	m.mu.Lock()
	ops, failedNow := m.applyLocked(a, c)
	m.mu.Unlock()
	// netsh can take many seconds and is best effort, so it runs outside the
	// lock and off the goroutine that dispatches server messages.
	m.runFirewall(ops)
	if failedNow {
		// Say so now rather than at the next hourly inventory, so the server can
		// replace this leader while members still point at it.
		go a.sendInventory()
	}
}

// applyLocked does apply's work under m.mu and returns the firewall calls to
// make afterwards, and whether this call is the one that found the device
// unable to lead.
func (m *meshState) applyLocked(a *Agent, c *protocol.CacheConfig) (ops []func(), failedNow bool) {
	wasFailed := m.serveFailed
	m.serveFailed = false
	fail := func() ([]func(), bool) {
		// A leader that cannot serve must not send its own updates to itself, or
		// every download pays the failed attempts before the origin fallback.
		m.serveFailed = true
		updateCache.Store(nil)
		return ops, !wasFailed
	}
	if c == nil || c.LeaderAddr == "" {
		m.cfg = nil
		updateCache.Store(nil)
		ops = append(ops, m.stopServerLocked()...)
		return ops, false
	}
	cp := *c
	m.cfg = &cp
	if c.Token != "" && (len(m.tokens) == 0 || m.tokens[0] != c.Token) {
		m.tokens = append([]string{c.Token}, m.tokens...)
		if len(m.tokens) > 2 {
			m.tokens = m.tokens[:2]
		}
	}
	updateCache.Store(&cache.Client{
		Leader: &cache.Leader{Addr: c.LeaderAddr, ID: c.LeaderID, Fingerprint: c.Fingerprint, Token: c.Token},
		Stats:  &m.fetched,
	})

	capable, _ := m.identity()
	if !c.Serve || !capable {
		ops = append(ops, m.stopServerLocked()...)
		if c.Serve {
			return fail()
		}
		return ops, false
	}
	port := c.Port
	if port <= 0 || port > 65535 {
		port = defaultCachePort
	}
	key := strconv.Itoa(port)
	if m.srv != nil && m.srvKey == key {
		m.store.SetMax(c.MaxBytes)
		return ops, false
	}
	ops = append(ops, m.stopServerLocked()...)
	store, err := cache.OpenStore(filepath.Join(ConfigDir(), cacheDirName), c.MaxBytes, &m.served)
	if err != nil {
		slog.Warn("the subnet cache cannot open its store, so this device will not lead", "err", err)
		return fail()
	}
	srv := cache.NewServer(cache.ServerConfig{
		Store:        store,
		Origin:       a.cfg.ServerURL,
		OriginClient: &http.Client{Transport: &http.Transport{TLSClientConfig: TLSConfig(a.cfg.Fingerprint)}},
		Tokens:       m.currentTokens,
		Cert:         m.cert,
		Stats:        &m.served,
	})
	if err := srv.Start(port); err != nil {
		slog.Warn("the subnet cache leader cannot start", "port", port, "err", err)
		return fail()
	}
	m.srv, m.srvKey, m.store = srv, key, store
	slog.Info("this device is now the subnet cache leader", "port", srv.Port(), "http3", srv.HTTP3(), "max_bytes", c.MaxBytes)
	m.fwPort = srv.Port()
	fwPort := m.fwPort
	return append(ops, func() { meshFirewallHook(true, fwPort) }), false
}

// stopServerLocked closes the leader server and returns the firewall call that
// takes its rule back, for the caller to make once m.mu is released.
func (m *meshState) stopServerLocked() []func() {
	if m.srv == nil {
		return nil
	}
	m.srv.Close()
	m.srv, m.store, m.srvKey = nil, nil, ""
	slog.Info("this device stopped serving the subnet cache")
	if m.fwPort != 0 {
		port := m.fwPort
		m.fwPort = 0
		return []func(){func() { meshFirewallHook(false, port) }}
	}
	return nil
}

// runFirewall queues firewall calls and drains the queue on one goroutine, so
// the calls of successive assignments still happen in the order they were made.
func (m *meshState) runFirewall(ops []func()) {
	if len(ops) == 0 {
		return
	}
	m.fwMu.Lock()
	m.fwQueue = append(m.fwQueue, ops...)
	if m.fwBusy {
		m.fwMu.Unlock()
		return
	}
	m.fwBusy = true
	m.fwMu.Unlock()
	go func() {
		for {
			m.fwMu.Lock()
			if len(m.fwQueue) == 0 {
				m.fwBusy = false
				m.fwMu.Unlock()
				return
			}
			op := m.fwQueue[0]
			m.fwQueue = m.fwQueue[1:]
			m.fwMu.Unlock()
			op()
		}
	}()
}

// stop shuts the leader down at process exit and takes its firewall rule back.
func (m *meshState) stop() {
	m.mu.Lock()
	ops := m.stopServerLocked()
	m.mu.Unlock()
	// Synchronously: the process is exiting and a background call would be lost.
	for _, op := range ops {
		op()
	}
}

// stats is what inventory reports, nil when the device has no cache role.
func (m *meshState) stats() *protocol.CacheStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg == nil {
		return nil
	}
	s, role := &m.fetched, "member"
	if m.srv != nil {
		s, role = &m.served, "leader"
	}
	return &protocol.CacheStats{
		ServeFailed: m.serveFailed, Serving: m.srv != nil,
		Role: role, Hits: s.Hits.Load(), Misses: s.Misses.Load(),
		BytesServed: m.served.BytesServed.Load(), BytesStored: m.served.BytesStored.Load(),
	}
}

// meshFirewallHook is the platform firewall call; tests replace it so they never
// touch the host firewall.
var meshFirewallHook = meshFirewall

// meshFirewallTimeout bounds the netsh calls; they are best effort.
const meshFirewallTimeout = 20 * time.Second

func meshFirewallCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), meshFirewallTimeout)
}
