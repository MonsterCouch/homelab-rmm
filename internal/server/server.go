// Package server is the RMM control plane: HTTPS API and web UI for
// operators, WebSocket endpoint for agents, SQLite persistence, alerting,
// scheduling and the relays that bridge a browser to a shell or desktop
// session on an agent.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Version is stamped by the build (-ldflags "-X ...server.Version=v1.2.3").
var Version = "dev"

type Server struct {
	cfg         Config
	db          *DB
	hub         *Hub
	alerts      *alertEngine
	sched       *scheduler
	mail        *mailer
	runs        *runTracker
	desktops    *desktopBroker
	fingerprint string
	httpSrv     *http.Server
	startedAt   time.Time
}

// New opens the database, prepares the certificate and wires every subsystem.
func New(cfg Config) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	db, err := openDB(cfg.path("rmm.db"))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if !cfg.SkipSeed {
		if err := seedDefaults(db); err != nil {
			return nil, fmt.Errorf("seed defaults: %w", err)
		}
	}
	s := &Server{cfg: cfg, db: db, startedAt: time.Now()}
	s.hub = newHub(s)
	s.mail = newMailer(db)
	s.alerts = newAlertEngine(s)
	s.runs = newRunTracker(s)
	s.desktops = newDesktopBroker()
	s.sched = newScheduler(s)
	db.markAllOffline()
	if !cfg.Insecure {
		hosts := localHostnames()
		if cfg.PublicURL != "" {
			if h := hostOf(cfg.PublicURL); h != "" {
				hosts = append([]string{h}, hosts...)
			}
		}
		_, fp, err := loadOrCreateCert(cfg, hosts)
		if err != nil {
			return nil, err
		}
		s.fingerprint = fp
	}
	return s, nil
}

func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, "/"); i >= 0 {
		u = u[:i]
	}
	if h, _, err := net.SplitHostPort(u); err == nil {
		return h
	}
	return u
}

// PublicURL is what agents connect to and what install commands embed.
func (s *Server) PublicURL() string {
	if s.cfg.PublicURL != "" {
		return strings.TrimRight(s.cfg.PublicURL, "/")
	}
	if v := s.db.Setting("public_url", ""); v != "" {
		return strings.TrimRight(v, "/")
	}
	host, port, _ := net.SplitHostPort(s.cfg.Listen)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host, _ = os.Hostname()
	}
	scheme := "https"
	if s.cfg.Insecure {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.httpSrv = &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if !s.cfg.Insecure {
		cert, _, err := loadOrCreateCert(s.cfg, nil)
		if err != nil {
			return err
		}
		s.httpSrv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}
	s.sched.start(ctx)
	go s.alerts.run(ctx)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", s.cfg.Listen, "tls", !s.cfg.Insecure, "fingerprint", s.fingerprint, "data", s.cfg.DataDir, "version", Version)
		var err error
		if s.cfg.Insecure {
			err = s.httpSrv.ListenAndServe()
		} else {
			err = s.httpSrv.ListenAndServeTLS("", "")
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpSrv.Shutdown(shutCtx)
		s.db.markAllOffline()
		s.db.Close()
		return nil
	}
}

// DB exposes the store for the CLI (user management).
func (s *Server) DB() *DB { return s.db }

// ---- agent callbacks from the hub ----

func (s *Server) agentConfig(agentID string) protocol.AgentConfig {
	cfg := protocol.AgentConfig{MetricsIntervalSec: 30, InventoryIntervalSec: 3600, PatchScanIntervalSec: 6 * 3600}
	s.db.SettingJSON("agent_defaults", &cfg)
	if a, err := s.db.GetAgent(agentID); err == nil {
		cfg.MonitoredServices = a.MonitoredServices
	}
	return cfg
}

func (s *Server) pushAgentConfig(agentID string) {
	s.hub.Notify(agentID, protocol.ReqAgentConfig, s.agentConfig(agentID))
}

func (s *Server) onAgentOnline(id string) {
	s.alerts.agentOnline(id)
	s.sched.agentOnline(id)
}

func (s *Server) onAgentOffline(id string) {
	s.alerts.agentOffline(id)
}

func (s *Server) onInventory(id string, inv *protocol.Inventory) {
	if err := s.db.saveInventory(id, inv); err != nil {
		slog.Warn("save inventory", "agent", id, "err", err)
		return
	}
	s.hub.broadcast(hubEvent{Kind: "inventory", AgentID: id})
	s.alerts.inventory(id, inv)
}

func (s *Server) onMetrics(id string, m *protocol.Metrics) {
	if m.TS == 0 {
		m.TS = now()
	}
	if err := s.db.saveMetrics(id, m); err != nil {
		slog.Warn("save metrics", "agent", id, "err", err)
		return
	}
	s.hub.broadcast(hubEvent{Kind: "metrics", AgentID: id, Data: m})
	s.alerts.metrics(id, m)
}

func (s *Server) onAgentEvent(id string, ev *protocol.Event) {
	if ev.TS == 0 {
		ev.TS = now()
	}
	s.db.Exec(`INSERT INTO agent_events(agent_id, ts, kind, message, fields) VALUES(?,?,?,?,?)`, id, ev.TS, ev.Kind, ev.Message, jsonText(ev.Fields))
	s.hub.broadcast(hubEvent{Kind: "event", AgentID: id, Data: ev})
	s.alerts.event(id, ev)
}
