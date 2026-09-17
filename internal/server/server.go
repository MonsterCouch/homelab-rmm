// Package server is the RMM control plane: HTTPS API and web UI for
// operators, WebSocket endpoint for agents, SQLite persistence, alerting,
// scheduling and the relays that bridge a browser to a shell or desktop
// session on an agent.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/winsec"
)

// Version is stamped by the build (-ldflags "-X ...server.Version=v1.2.3").
var Version = "dev"

type Server struct {
	cfg         Config
	db          *DB
	hub         *Hub
	alerts      *alertEngine
	baselines   *baselineEngine
	sched       *scheduler
	mail        *mailer
	runs        *runTracker
	desktops    *desktopBroker
	desktopCap  *desktopCount
	fingerprint string
	// pubkeyPin is base64(sha256(SPKI)) of the same certificate, which is what
	// the Linux install script gives curl --pinnedpubkey.
	pubkeyPin string
	// setupCode is the one-time code required to create the first
	// administrator. It is minted at startup when the user table is empty and
	// cleared the moment an account exists; setupMu also makes the
	// "no users yet?" check and the insert in handleSetup one step.
	setupMu   sync.Mutex
	setupCode string
	// trustedProxies are the peers whose X-Forwarded-For header is believed.
	trustedProxies []*net.IPNet
	httpSrv        *http.Server
	startedAt      time.Time
	// cert is the certificate loaded at New, reused by Run so a file that
	// vanishes in between cannot be regenerated with no SANs at all.
	cert      *tls.Certificate
	certHosts []string
	certMu    sync.Mutex
	certWarn  string
	// patchJobs serialises patch work per device: overlapping scans and
	// installs used to trample each other's status rows.
	patchMu   sync.Mutex
	patchJobs map[string]bool
	// jobCtx bounds long background work (a patch install carries a
	// three-hour context) so shutdown does not have to wait it out, and jobs
	// counts what is still running.
	jobCtx    context.Context
	jobCancel context.CancelFunc
	jobs      sync.WaitGroup
}

// jobContext is the context long background work runs under. It is cancelled
// at shutdown, before the database is closed.
func (s *Server) jobContext() context.Context {
	if s.jobCtx == nil {
		return context.Background()
	}
	return s.jobCtx
}

// goJob runs fn in the background and makes shutdown aware of it.
func (s *Server) goJob(fn func()) {
	s.jobs.Add(1)
	go func() {
		defer s.jobs.Done()
		fn()
	}()
}

// waitJobs waits (at most d) for background work to finish.
func (s *Server) waitJobs(d time.Duration) {
	done := make(chan struct{})
	go func() {
		s.jobs.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		slog.Warn("background jobs did not finish in time; stopping anyway", "waited", d.String())
	}
}

// New opens the database, prepares the certificate and wires every subsystem.
func New(cfg Config) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	// 0o750 is a no-op on Windows, where the default data directory is a child
	// of %ProgramData% and inherits "BUILTIN\Users: read and execute" - which
	// would make rmm.db (sessions, password hashes, every script and baseline
	// parameter) and server.key (the certificate every agent pins) readable by
	// any local account. A directory that cannot be secured is a warning, not
	// a failure: the server still has to run (acl-01).
	if err := winsec.SecureDir(cfg.DataDir); err != nil {
		slog.Warn("cannot restrict permissions on the data directory", "dir", cfg.DataDir, "err", err)
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
	s := &Server{cfg: cfg, db: db, startedAt: time.Now(), patchJobs: map[string]bool{}}
	s.jobCtx, s.jobCancel = context.WithCancel(context.Background())
	if db.UserCount() == 0 {
		s.setupCode = randomHex(4)
	}
	s.trustedProxies = parseTrustedProxies(cfg.TrustedProxies)
	s.hub = newHub(s)
	s.mail = newMailer(db)
	s.alerts = newAlertEngine(s)
	s.baselines = newBaselineEngine(s)
	s.runs = newRunTracker(s)
	s.desktops = newDesktopBroker()
	s.desktopCap = newDesktopCount()
	s.sched = newScheduler(s)
	db.markAllOffline()
	// --public-url / RMM_PUBLIC_URL is the FIRST-RUN DEFAULT for the
	// public_url setting, not a permanent override: every quick start tells
	// the operator to pass the flag, which used to make the Settings field
	// permanently dead (it saved, and nothing ever read it).
	if cfg.PublicURL != "" {
		stored := db.Setting("public_url", "")
		switch {
		case stored == "":
			db.SetSetting("public_url", strings.TrimRight(cfg.PublicURL, "/"))
		case strings.TrimRight(stored, "/") != strings.TrimRight(cfg.PublicURL, "/"):
			slog.Warn("the public_url saved in the console overrides --public-url/RMM_PUBLIC_URL; clear the Settings field to go back to the flag",
				"settings", stored, "flag", cfg.PublicURL)
		}
	}
	if !cfg.Insecure {
		hosts := localHostnames()
		if h := hostOf(s.PublicURL()); h != "" {
			hosts = append([]string{h}, hosts...)
		}
		cert, fp, err := loadOrCreateCert(cfg, hosts)
		if err != nil {
			return nil, err
		}
		s.cert, s.certHosts = &cert, hosts
		s.fingerprint = fp
		s.pubkeyPin = PublicKeyPin(cert.Certificate[0])
		s.checkCertHost()
	}
	return s, nil
}

// checkCertHost compares the certificate in use with the host agents and
// browsers are told to reach. The SANs are fixed when the certificate is
// generated, but PublicURL() can change at any time from the Settings page,
// and nothing used to say that the new name is not covered.
func (s *Server) checkCertHost() {
	warn := ""
	defer func() {
		s.certMu.Lock()
		s.certWarn = warn
		s.certMu.Unlock()
	}()
	if s.cfg.Insecure || s.cert == nil || len(s.cert.Certificate) == 0 {
		return
	}
	host := hostOf(s.PublicURL())
	if host == "" {
		return
	}
	leaf, err := x509.ParseCertificate(s.cert.Certificate[0])
	if err != nil {
		return
	}
	if leaf.VerifyHostname(host) == nil {
		return
	}
	warn = fmt.Sprintf("the server certificate does not cover %q: browsers report a name mismatch and an agent enrolled without a fingerprint pin refuses to connect. "+
		"Supply your own certificate with --cert/--key, or delete server.crt and server.key from %s and restart to regenerate one (every agent must then re-pin the new fingerprint).", host, s.cfg.DataDir)
	slog.Warn("certificate does not cover the public URL", "host", host,
		"dns_sans", leaf.DNSNames, "ip_sans", ipStrings(leaf.IPAddresses))
}

// CertWarning is the empty string when the certificate covers the public URL.
func (s *Server) CertWarning() string {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	return s.certWarn
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// agentsWithLiveness is every device with the hub's view of "online" stamped
// over the agents.online column. The column is only written at connect and
// disconnect and is wiped at every startup, so it is a convenience, never the
// answer: every read path goes through here so the rule cannot be forgotten.
func (s *Server) agentsWithLiveness() ([]*Agent, error) {
	agents, err := s.db.ListAgents()
	if err != nil {
		return nil, err
	}
	for _, a := range agents {
		a.Online = s.hub.IsOnline(a.ID)
	}
	return agents, nil
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

// PublicURL is what agents connect to and what install commands embed. The
// setting saved in the console wins: the flag seeded it on first run (see
// New), so the Settings field an operator edits is the one that takes effect.
func (s *Server) PublicURL() string {
	if v := s.db.Setting("public_url", ""); v != "" {
		return strings.TrimRight(v, "/")
	}
	if s.cfg.PublicURL != "" {
		return strings.TrimRight(s.cfg.PublicURL, "/")
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
		if s.cert == nil {
			cert, fp, err := loadOrCreateCert(s.cfg, s.certHosts)
			if err != nil {
				return err
			}
			s.cert, s.fingerprint = &cert, fp
			s.checkCertHost()
		}
		s.httpSrv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*s.cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Bind BEFORE announcing it. "listening" is the documented startup
	// success signal, and logging it first meant a port collision produced a
	// success line followed by the failure - a false positive for anyone (or
	// any monitoring rule) grepping the log.
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		// Nothing will run, so release the database the way the other exits
		// do; a caller (or a test) that retries must not find rmm.db held open.
		s.jobCancel()
		s.db.Close()
		return err
	}
	if !s.cfg.Insecure {
		ln = tls.NewListener(ln, s.httpSrv.TLSConfig)
	}
	slog.Info("listening", "addr", ln.Addr().String(), "tls", !s.cfg.Insecure, "fingerprint", s.fingerprint, "data", s.cfg.DataDir, "version", Version)
	if w := s.CertWarning(); w != "" {
		slog.Warn("certificate name mismatch", "detail", w)
	}
	if code := s.SetupCode(); code != "" {
		slog.Warn("FIRST RUN: no users yet. Open the console and create the administrator. The setup form asks for this one-time code", "setup_code", code)
		fmt.Fprintf(os.Stderr, "\n==== FIRST-RUN SETUP CODE: %s ====\n\n", code)
	}

	s.sched.start(ctx)
	s.goJob(func() { s.alerts.run(ctx) })

	errCh := make(chan error, 1)
	go func() {
		err := s.httpSrv.Serve(ln)
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		// The listener died under us. Stop the background work and close the
		// database so the write-ahead log is checkpointed on the way out.
		slog.Error("listener stopped", "err", err)
		s.jobCancel()
		s.db.Close()
		return err
	case <-ctx.Done():
		slog.Info("shutting down", "addr", ln.Addr().String())
		// Order matters. Cancel long jobs first so nothing is still writing
		// when the handle closes, tell the agents why their socket is going
		// away (a bare reset costs each one a reconnect backoff of up to a
		// minute), let their read loops finish their teardown, and only then
		// touch the database.
		s.jobCancel()
		s.hub.CloseAll()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpSrv.Shutdown(shutCtx)
		s.hub.waitClosed(3 * time.Second)
		s.waitJobs(10 * time.Second)
		s.db.markAllOffline()
		s.db.Close()
		slog.Info("stopped", "version", Version)
		return nil
	}
}

// DB exposes the store for the CLI (user management).
func (s *Server) DB() *DB { return s.db }

// ---- agent callbacks from the hub ----

func (s *Server) agentConfig(agentID string) protocol.AgentConfig {
	cfg := protocol.AgentConfig{MetricsIntervalSec: 30, InventoryIntervalSec: 3600, PatchScanIntervalSec: 6 * 3600}
	s.db.SettingJSON("agent_defaults", &cfg)
	// Baselines are resolved AFTER the settings blob is unmarshalled, and the
	// field is cleared on the way into settings (handlePutSettings): the
	// operator-editable agent_defaults row must never be able to freeze a
	// baseline set and push it to every device regardless of targets.
	cfg.Baselines = nil
	if a, err := s.db.GetAgent(agentID); err == nil {
		cfg.MonitoredServices = a.MonitoredServices
		// Always the COMPLETE matching set: the agent replaces its whole set
		// on every config, so anything left out is stopped on the device.
		cfg.Baselines = s.baselineSpecsFor(a)
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
