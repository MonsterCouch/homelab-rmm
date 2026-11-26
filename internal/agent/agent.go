// Package agent is the device-side daemon. It keeps one outbound WebSocket to
// the server, answers requests (inventory, scripts, shell, files, services,
// updates, power, desktop) and pushes metrics on a timer. It runs as a
// Windows service or a systemd unit; see service.go.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/MonsterCouch/homelab-rmm/internal/netscan"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/supervisor"
)

type Agent struct {
	cfg *Config
	// c is the live socket, or nil before the first connection. It is read
	// from goroutines that outlive a session - the baseline engine runs for
	// the whole process, online or not - so it is only ever touched through
	// socket()/setConn.
	c      *conn
	cmu    sync.RWMutex
	remote protocol.AgentConfig
	rmu    sync.RWMutex
	// qmu guards the QUIC fields of cfg (QUICPort, QUICFailedAt): the session
	// reads them while a config push on a reader goroutine may rewrite them.
	qmu    sync.Mutex
	shells *shellManager
	runs   *scriptRunner
	// baselines is the desired-state engine: its own goroutine, its own
	// on-disk state, running whether or not there is a server to talk to.
	baselines *baselineEngine
	// trust is the pinned trust bundle and nonce store (Phase 3); see trust.go.
	trust *trustState
	// mesh is the subnet cache role (Phase 4B); see mesh.go.
	mesh *meshState
	// wake is signalled when the config changes so tickers restart
	wake chan struct{}

	// Supervisor IPC integration (Milestone 6)
	ipcClient         *supervisor.IPCClient
	ipcMu             sync.Mutex
	ipcPath           string
	heartbeatInterval time.Duration
	stopHeartbeat     chan struct{}
	heartbeatDone     chan struct{}
}

// socket returns the live connection, or nil when the agent is offline. Every
// caller outside the read loop has to handle nil: a send that cannot happen
// is normal, not an error.
func (a *Agent) socket() *conn {
	a.cmu.RLock()
	defer a.cmu.RUnlock()
	return a.c
}

func (a *Agent) setConn(c *conn) {
	if c != nil && a.trust != nil {
		c.logSize = a.trust.logSize
	}
	a.cmu.Lock()
	a.c = c
	a.cmu.Unlock()
}

func New(cfg *Config) *Agent {
	a := &Agent{cfg: cfg, wake: make(chan struct{}, 1)}
	a.shells = newShellManager()
	a.runs = newScriptRunner()
	a.baselines = newBaselineEngine(a)
	a.trust = loadTrust()
	a.mesh = &meshState{}
	a.remote = protocol.AgentConfig{MetricsIntervalSec: 30, InventoryIntervalSec: 3600, PatchScanIntervalSec: 6 * 3600}
	return a
}

// Run connects and reconnects until ctx ends. Backoff starts at 2s and caps
// at 60s with jitter so a fleet does not hammer a restarting server.
func (a *Agent) Run(ctx context.Context) error {
	// The baseline engine starts before the first dial and keeps running
	// between sessions: a device that boots with the server down still
	// evaluates the baselines it was last told about, and reports them when
	// the socket comes back.
	a.baselines.start(ctx)
	a.startPortalPipe(ctx)
	// A leader's listeners and Windows firewall rules go with the process.
	defer a.mesh.stop()

	// Supervisor IPC integration (Milestone 6)
	a.initSupervisorIPC(ctx)
	defer a.closeSupervisorIPC()

	backoff := 2 * time.Second
	for {
		err := a.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			slog.Warn("session ended", "err", err, "retry_in", backoff)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff + time.Duration(rand.Int63n(int64(backoff/2)))):
		}
		if backoff < 60*time.Second {
			backoff *= 2
		}
		if err == nil {
			backoff = 2 * time.Second
		}
	}
}

func (a *Agent) hello() protocol.Hello {
	host, _ := os.Hostname()
	h := protocol.Hello{
		AgentID: a.cfg.AgentID, Hostname: host, OS: runtime.GOOS, Platform: platformName(),
		Arch: runtime.GOARCH, Version: Version, ProtocolVersion: protocol.Version,
	}
	if a.trust != nil {
		h.TrustEpoch, h.TrustHash = a.trust.epochHash()
		h.LogSize, h.ExecutedHead = a.trust.logSize(), a.trust.executedHead()
	}
	if a.mesh != nil {
		h.CacheCapable, h.CacheFingerprint = a.mesh.identity()
	}
	return h
}

// transportMode is how this process was asked to reach the server:
// RMM_TRANSPORT wins over the config file, and anything unrecognised means
// auto, with a warning, so a typo never strands a device offline.
func (a *Agent) transportMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("RMM_TRANSPORT")))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(a.cfg.Transport))
	}
	switch mode {
	case "websocket", "quic", "auto":
		return mode
	case "":
		return "auto"
	}
	slog.Warn("unknown transport, using auto", "transport", mode, "want", "websocket, quic or auto")
	return "auto"
}

// quicState reads the remembered QUIC port and last failure time.
func (a *Agent) quicState() (port int, failedAt int64) {
	a.qmu.Lock()
	defer a.qmu.Unlock()
	return a.cfg.QUICPort, a.cfg.QUICFailedAt
}

// setQUICFailedAt records (or, with 0, clears) the last QUIC failure and
// saves it, so a restart does not forget that this network drops UDP.
func (a *Agent) setQUICFailedAt(ts int64) {
	a.qmu.Lock()
	defer a.qmu.Unlock()
	if a.cfg.QUICFailedAt == ts {
		return
	}
	a.cfg.QUICFailedAt = ts
	if err := a.cfg.Save(); err != nil {
		slog.Warn("cannot save the QUIC failure time", "err", err)
	}
}

// rememberQUIC stores what the server says about its QUIC listener. A server
// that stopped advertising it (QUIC turned off) clears the port, and the
// failure memory with it: the next time it comes back is a fresh start.
func (a *Agent) rememberQUIC(cfg protocol.AgentConfig) {
	if a.cfg == nil {
		return
	}
	port := 0
	if cfg.QUIC {
		port = cfg.QUICPort
	}
	a.qmu.Lock()
	defer a.qmu.Unlock()
	if a.cfg.QUICPort == port {
		return
	}
	a.cfg.QUICPort = port
	if port == 0 {
		a.cfg.QUICFailedAt = 0
	}
	if err := a.cfg.Save(); err != nil {
		slog.Warn("cannot save the QUIC port", "err", err)
	}
}

func (a *Agent) session(ctx context.Context) error {
	if a.cfg.Key == "" && a.cfg.EnrollToken == "" {
		return errors.New("no agent key and no enrollment token; run `rmm-agent install`")
	}
	mode := a.transportMode()
	port, failedAt := a.quicState()
	if chooseQUIC(mode, port, failedAt, time.Now()) {
		link, welcome, err := a.dialQUIC(ctx, port)
		if err == nil {
			return a.sessionQUIC(ctx, link, welcome)
		}
		var te *quicTransportError
		if !errors.As(err, &te) || mode == "quic" {
			return err
		}
		if ctx.Err() != nil {
			// A stop or a cancelled dial says nothing about the UDP path, and
			// remembering it would hold the device on WebSocket for ten minutes.
			return ctx.Err()
		}
		slog.Warn("QUIC failed, falling back to WebSocket", "err", err, "retry_quic_in", quicRetryAfter)
		a.setQUICFailedAt(time.Now().Unix())
	}
	return a.sessionWS(ctx)
}

// dialQUIC is the agent's QUIC attempt: the address, the credentials, and the
// refusal handling. An unknown-key refusal is the 401 equivalent and gets the
// same re-enrollment treatment; it is returned as a plain error so it is
// never mistaken for a transport failure.
func (a *Agent) dialQUIC(ctx context.Context, port int) (*quicLink, protocol.Envelope, error) {
	addr, err := quicAddress(a.cfg.ServerURL, port)
	if err != nil {
		return nil, protocol.Envelope{}, err
	}
	auth := protocol.Auth{Token: a.cfg.EnrollToken}
	if a.cfg.Key != "" {
		auth = protocol.Auth{Key: a.cfg.Key}
	}
	link, env, err := dialQUIC(ctx, addr, a.cfg.Fingerprint, auth, a.hello())
	var ref *quicRefusal
	if errors.As(err, &ref) && ref.msg == protocol.ErrUnknownAgentKey && a.cfg.Key != "" && a.cfg.EnrollToken != "" {
		slog.Warn("agent key rejected, re-enrolling with stored token")
		a.forgetKey()
	}
	return link, env, err
}

func (a *Agent) sessionWS(ctx context.Context) error {
	hdr := http.Header{}
	if a.cfg.Key != "" {
		hdr.Set("Authorization", "Bearer "+a.cfg.Key)
	} else {
		hdr.Set("X-Enroll-Token", a.cfg.EnrollToken)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ws, resp, err := Dial(dialCtx, a.cfg.WSURL("/ws/agent"), a.cfg.Fingerprint, hdr)
	cancel()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized && a.cfg.Key != "" && a.cfg.EnrollToken != "" {
			// key revoked (device deleted on the server) but we still hold a token: re-enroll
			slog.Warn("agent key rejected, re-enrolling with stored token")
			a.forgetKey()
		}
		return err
	}
	ws.SetReadLimit(64 << 20)
	c := &conn{ws: ws}
	a.setConn(c)
	defer a.setConn(nil)
	defer ws.Close()

	if err := c.send(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(a.hello())}); err != nil {
		return err
	}
	ws.SetReadDeadline(time.Now().Add(20 * time.Second))
	var env protocol.Envelope
	if err := ws.ReadJSON(&env); err != nil {
		return err
	}
	if err := a.welcomed(env); err != nil {
		return err
	}
	ws.SetReadDeadline(time.Time{})

	sessCtx, stop := a.startSession(ctx)
	defer stop()
	// a cancelled context (service stop, SIGTERM) must unblock ReadMessage
	go func() {
		<-sessCtx.Done()
		ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "shutting down"), time.Now().Add(time.Second))
		ws.Close()
	}()

	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			a.shells.closeAll()
			return err
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}
		a.dispatch(sessCtx, env)
	}
}

// sessionQUIC runs a session over an established QUIC connection whose welcome
// has already been read.
func (a *Agent) sessionQUIC(ctx context.Context, link *quicLink, welcome protocol.Envelope) error {
	c := &conn{q: link}
	a.setConn(c)
	defer a.setConn(nil)
	defer link.close(quicCodeNormal, "agent stopping")

	if err := a.welcomed(welcome); err != nil {
		return err
	}
	a.setQUICFailedAt(0)

	sessCtx, stop := a.startSession(ctx)
	defer stop()
	// a cancelled context (service stop, SIGTERM) must unblock the readers
	go func() {
		<-sessCtx.Done()
		link.close(quicCodeNormal, "shutting down")
	}()
	err := link.serve(sessCtx, a)
	a.shells.closeAll()
	return err
}

// forgetKey drops a key the server rejected so the next dial enrolls with the
// stored token. The identity that went with it is remembered until that
// enrollment lands (see welcomed).
func (a *Agent) forgetKey() {
	if a.cfg.AgentID != "" {
		a.cfg.PrevAgentID = a.cfg.AgentID
	}
	a.cfg.Key, a.cfg.AgentID = "", ""
	a.cfg.Save()
}

// welcomed handles the server's answer to hello, whichever transport carried
// it: a refusal is an error, an enrollment saves the key it brings, and the
// pushed configuration is applied.
func (a *Agent) welcomed(env protocol.Envelope) error {
	if env.T != "welcome" {
		return errors.New("server refused: " + env.Err)
	}
	var welcome struct {
		AgentID  string          `json:"agent_id"`
		AgentKey string          `json:"agent_key"`
		Config   json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(env.D, &welcome); err != nil {
		return err
	}
	if welcome.AgentKey != "" {
		// A new identity is only ever the answer to an enrollment. The server
		// sends agent_key when the device dialled with a token and never when
		// it dialled with its key, so a keyed session that is handed one is a
		// server rewriting which device this is - and with it, which signed
		// manifests and grants the device will accept as addressed to itself.
		if a.cfg.Key != "" {
			return errors.New("server sent a new device identity on a session that was not an enrollment; refused")
		}
		// Re-enrolling after a rejected key is the other way to be renamed:
		// the server decides whether the key is rejected and which ID comes
		// back. Under an enforcing trust bundle the device keeps the identity
		// approvals were signed for, or none.
		if prev := a.cfg.PrevAgentID; prev != "" && welcome.AgentID != prev && a.trust.identityPinned() {
			return fmt.Errorf("server assigned device identity %s in place of %s while an enforcing trust bundle is pinned; refused. "+
				"Signed approvals name devices by identity. If this device was removed on purpose and should enroll as new, delete trust.json and log_head.json in %s and restart the agent",
				welcome.AgentID, prev, ConfigDir())
		}
		a.cfg.AgentID, a.cfg.Key, a.cfg.PrevAgentID = welcome.AgentID, welcome.AgentKey, ""
		if err := a.cfg.Save(); err != nil {
			slog.Error("cannot save enrollment; the device will re-enroll next start", "err", err)
		} else {
			slog.Info("enrolled", "agent_id", welcome.AgentID)
		}
	}
	a.applyConfigRaw(welcome.Config)
	slog.Info("connected", "server", a.cfg.ServerURL, "agent_id", a.cfg.AgentID)
	return nil
}

// startSession is what follows a successful welcome on either transport. The
// returned context ends with the session; stop ends it early.
func (a *Agent) startSession(ctx context.Context) (context.Context, context.CancelFunc) {
	// Notify supervisor that TLS handshake, WS upgrade, and check-in succeeded (Milestone 6)
	a.notifyHealthy()

	// Catch-up is exactly one re-send of the cached last report per baseline,
	// with its original timestamp and version; the start-up pass that follows
	// supersedes it server-side (A14).
	go a.baselines.resend()

	sessCtx, stop := context.WithCancel(ctx)
	go a.pushLoop(sessCtx)
	return sessCtx, stop
}

// applyConfigRaw applies a pushed config from its JSON, keeping each baseline
// spec's bytes as received so their standing approvals can be checked.
func (a *Agent) applyConfigRaw(data json.RawMessage) {
	if len(data) == 0 {
		// No config says nothing about QUIC either, so the remembered port stays.
		port, _ := a.quicState()
		a.applyConfig(protocol.AgentConfig{QUIC: port > 0, QUICPort: port, Cache: a.config().Cache}, nil, nil)
		return
	}
	cfg, raws, auth, err := splitConfig(data)
	if err != nil {
		slog.Warn("agent config ignored", "err", err)
		return
	}
	specs, rm, am := a.filterSpecs(cfg, raws, auth)
	cfg.Baselines = specs
	a.applyConfig(cfg, rm, am)
}

func (a *Agent) applyConfig(cfg protocol.AgentConfig, raws map[int64]json.RawMessage, auths map[int64]*protocol.ActionAuth) {
	if cfg.MetricsIntervalSec < 5 {
		cfg.MetricsIntervalSec = 30
	}
	if cfg.InventoryIntervalSec < 60 {
		cfg.InventoryIntervalSec = 3600
	}
	a.rmu.Lock()
	a.remote = cfg
	a.rmu.Unlock()
	a.rememberQUIC(cfg)
	if a.mesh != nil {
		a.mesh.apply(a, cfg.Cache)
	}
	// The pushed set is always complete: a baseline that is missing here was
	// unassigned, disabled or deleted, and the engine stops it at once (A10).
	if a.baselines != nil {
		a.baselines.setSpecsApproved(cfg.Baselines, raws, auths)
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *Agent) config() protocol.AgentConfig {
	a.rmu.RLock()
	defer a.rmu.RUnlock()
	return a.remote
}

// pushLoop sends inventory immediately, then metrics and inventory on their
// intervals. Intervals are re-read whenever the server pushes a new config.
func (a *Agent) pushLoop(ctx context.Context) {
	a.sendInventory()
	a.sendMetrics()
	go a.autoUpdateLoop(ctx)
	for {
		cfg := a.config()
		mt := time.NewTicker(time.Duration(cfg.MetricsIntervalSec) * time.Second)
		it := time.NewTicker(time.Duration(cfg.InventoryIntervalSec) * time.Second)
	inner:
		for {
			select {
			case <-ctx.Done():
				mt.Stop()
				it.Stop()
				return
			case <-a.wake:
				break inner
			case <-mt.C:
				a.sendMetrics()
			case <-it.C:
				a.sendInventory()
			}
		}
		mt.Stop()
		it.Stop()
	}
}

type agentUpdateCheckResp struct {
	UpdateAvailable bool   `json:"update_available"`
	Version         string `json:"version"`
	SHA256          string `json:"sha256"`
	URL             string `json:"url"`
	// SignedUpdateRequired is what the server sends, instead of advertising a
	// build, to devices of organizations that enforce signatures: a newer
	// build is staged, but it reaches the device as a signed agent.update from
	// the console, never through this unsigned poll.
	SignedUpdateRequired bool `json:"signed_update_required"`
}

func (a *Agent) autoUpdateLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(8 * time.Second):
		a.checkAutoUpdate(ctx)
	}

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.checkAutoUpdate(ctx)
		}
	}
}

func (a *Agent) checkAutoUpdate(ctx context.Context) {
	if a.cfg == nil || a.cfg.ServerURL == "" || a.cfg.Key == "" {
		return
	}
	curSHA := currentBinarySHA256()
	checkURL := fmt.Sprintf("%s/api/agent/update-check?os=%s&arch=%s&version=%s&sha256=%s",
		a.cfg.ServerURL, runtime.GOOS, runtime.GOARCH, Version, curSHA)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.Key)

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: TLSConfig(a.cfg.Fingerprint)},
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var res agentUpdateCheckResp
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}

	if res.SignedUpdateRequired {
		// The server withholds the binary from an unsigned poll, so there is
		// nothing to install here. Say so once per build, not every five
		// minutes.
		if a.trust == nil || a.trust.once("autoupdate-info/"+res.SHA256) {
			slog.Info("agent auto-update: a new build is staged on the server; this organization requires a signed update from the console", "target_version", res.Version)
		}
		return
	}

	if res.UpdateAvailable && res.URL != "" && res.SHA256 != "" {
		uReq := protocol.AgentUpdate{
			URL:     res.URL,
			SHA256:  res.SHA256,
			Version: res.Version,
		}
		// An advertised binary is an agent.update nobody signed, so an
		// organization that signs actions gets to refuse it, before anything
		// says an update is under way.
		if !a.autoUpdateAllowed(uReq) {
			return
		}
		slog.Info("agent auto-update: new binary available on server, updating...", "target_version", res.Version)
		if err := selfUpdate(ctx, a.cfg, uReq, a.IPCClient()); err != nil {
			slog.Warn("agent auto-update failed", "err", err)
		}
	}
}

func (a *Agent) sendInventory() {
	inv, err := collectInventory()
	if err != nil {
		slog.Warn("inventory", "err", err)
		return
	}
	if a.trust != nil {
		inv.ExecutedHead = a.trust.executedHead()
	}
	if a.mesh != nil {
		inv.Cache = a.mesh.stats()
	}
	if c := a.socket(); c != nil {
		c.send(protocol.Envelope{T: protocol.TypeInventory, D: protocol.Must(inv)})
	}
}

func (a *Agent) sendMetrics() {
	m := collectMetrics(a.config().MonitoredServices)
	if c := a.socket(); c != nil {
		c.send(protocol.Envelope{T: protocol.TypeMetrics, D: protocol.Must(m)})
	}
}

// dispatch answers one server frame. Every request runs on its own goroutine
// so a slow update scan never blocks shell keystrokes.
func (a *Agent) dispatch(ctx context.Context, env protocol.Envelope) {
	c := a.socket()
	if c == nil {
		return
	}
	// Authorization comes first, ahead of the fast path below: agent.config
	// and shell input are handled there and must not skip the gate.
	env, ok := a.authorize(c, env)
	if !ok {
		return
	}
	switch env.T {
	case protocol.ReqPing:
		c.send(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
		return
	case protocol.ReqAgentConfig:
		a.applyConfigRaw(env.D)
		return
	case protocol.ReqShellInput:
		var in protocol.ShellInput
		if json.Unmarshal(env.D, &in) == nil {
			a.shells.input(in.Session, in.Data)
		}
		return
	case protocol.ReqShellResize:
		var in protocol.ShellResize
		if json.Unmarshal(env.D, &in) == nil {
			a.shells.resize(in.Session, in.Cols, in.Rows)
		}
		return
	case protocol.ReqShellClose:
		var in protocol.ShellClose
		if json.Unmarshal(env.D, &in) == nil {
			a.shells.close(in.Session)
		}
		return
	case protocol.ReqShellRTC:
		var in protocol.ShellRTC
		if json.Unmarshal(env.D, &in) == nil {
			if err := a.shells.rtcSignal(in); err != nil {
				slog.Debug("shell webrtc: signal refused", "err", err)
			}
		}
		return
	case protocol.ReqScriptCancel:
		var in struct {
			RunID string `json:"run_id"`
		}
		if json.Unmarshal(env.D, &in) == nil {
			a.runs.cancel(in.RunID)
		}
		return
	}
	go a.handle(ctx, env)
}

func (a *Agent) handle(ctx context.Context, env protocol.Envelope) {
	c := a.socket()
	if c == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("handler panicked", "type", env.T, "panic", r)
			c.replyErr(env.ID, errors.New("agent handler panicked"))
		}
	}()
	var (
		out any
		err error
	)
	switch env.T {
	case protocol.ReqInventoryRefresh:
		a.sendInventory()
	case protocol.ReqShellOpen:
		var in protocol.ShellOpen
		if err = json.Unmarshal(env.D, &in); err == nil {
			err = a.shells.open(env.ID, in, c)
			if err == nil {
				return // the session replies when it ends
			}
		}
	case protocol.ReqScriptRun:
		var in protocol.ScriptRun
		if err = json.Unmarshal(env.D, &in); err == nil {
			res := a.runs.run(ctx, in, func(chunk protocol.ScriptChunk) { c.stream(env.ID, chunk) })
			out = res
			if in.Env != nil && (in.Env["RMM_TRIGGER"] == "client-portal" || strings.HasPrefix(in.Env["RMM_TRIGGER"], "software")) {
				go func() {
					time.Sleep(1 * time.Second)
					a.sendInventory()
				}()
			}
		}
	case protocol.ReqProcList:
		out, err = listProcesses()
	case protocol.ReqProcKill:
		var in protocol.ProcKill
		if err = json.Unmarshal(env.D, &in); err == nil {
			err = killProcess(in.PID)
		}
	case protocol.ReqSvcList:
		out, err = listServices()
	case protocol.ReqSvcAction:
		var in protocol.SvcAction
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = serviceAction(in.Name, in.Action)
		}
	case protocol.ReqUpdatesScan:
		out, err = scanUpdates(ctx)
	case protocol.ReqUpdatesInstall:
		var in protocol.UpdatesInstall
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = installUpdates(ctx, in, func(line string) { c.event("patch", line, nil) })
		}
	case protocol.ReqServicingRepair:
		var in protocol.ServicingRepair
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = servicingRepair(ctx, a.cfg, in, func(line string) { c.event("patch", line, nil) })
		}
	case protocol.ReqEventLogQuery:
		var in protocol.EventLogQuery
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = queryEventLog(in)
		}
	case protocol.ReqFsList:
		var in protocol.FsList
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = fsList(in.Path)
		}
	case protocol.ReqFsRead:
		var in protocol.FsRead
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = fsRead(in)
		}
	case protocol.ReqFsWrite:
		var in protocol.FsWrite
		if err = json.Unmarshal(env.D, &in); err == nil {
			err = fsWrite(in)
		}
	case protocol.ReqFsStage:
		var in protocol.FsStage
		if err = json.Unmarshal(env.D, &in); err == nil {
			err = fsStage(in)
		}
	case protocol.ReqFsCommit:
		var in protocol.FsCommit
		if err = json.Unmarshal(env.D, &in); err == nil {
			err = fsCommit(in)
		}
	case protocol.ReqFsDelete:
		var in protocol.FsPath
		if err = json.Unmarshal(env.D, &in); err == nil {
			err = fsDelete(in.Path)
		}
	case protocol.ReqFsMkdir:
		var in protocol.FsPath
		if err = json.Unmarshal(env.D, &in); err == nil {
			err = fsMkdir(in.Path)
		}
	case protocol.ReqFsRename:
		var in protocol.FsRename
		if err = json.Unmarshal(env.D, &in); err == nil {
			err = fsRename(in.From, in.To)
		}
	case protocol.ReqPower:
		var in protocol.Power
		if err = json.Unmarshal(env.D, &in); err == nil {
			err = powerAction(in)
		}
	case protocol.ReqWakeOnLan:
		var in protocol.WakeOnLan
		if err = json.Unmarshal(env.D, &in); err == nil {
			err = sendMagicPacket(in.MAC, in.Broadcast)
		}
	case protocol.ReqDesktopStart:
		var in protocol.DesktopStart
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = a.startDesktop(in)
		}
	case protocol.ReqBaselineEvaluate:
		// The reply is an ACK, never a report: the pass sends exactly one
		// TypeBaseline frame when it finishes, and a reply carrying the same
		// results would make the server ingest every transition twice (A6).
		var in protocol.BaselineEvaluate
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = a.baselines.requestEvaluate(in.BaselineIDs)
		}
	case protocol.ReqBaselineRemediate:
		var in protocol.BaselineRemediate
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = a.baselines.requestRemediate(in)
		}
	case protocol.ReqBaselinePreview:
		// The one exception: a preview's reply IS the report, and no frame
		// is sent, because nothing about it is ever stored.
		var in protocol.BaselinePreview
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = a.baselines.preview(ctx, in.Spec)
		}
	case protocol.ReqAgentUpdate:
		var in protocol.AgentUpdate
		if err = json.Unmarshal(env.D, &in); err == nil {
			var res protocol.AgentUpdateResult
			res, err = selfUpdateResult(ctx, a.cfg, in, a.IPCClient())
			if err == nil {
				// Where the bytes came from, so the operator can tell a
				// cache hit from a WAN download.
				out = res
			}
		}
	case protocol.ReqTrustUpdate:
		out, err = a.trustUpdate(env)
	case protocol.ReqDeviceIsolate:
		var in protocol.DeviceIsolate
		if err = json.Unmarshal(env.D, &in); err == nil {
			out, err = a.handleIsolate(in)
		}
	case protocol.ReqNetworkScan:
		var in protocol.NetworkScanReq
		if err = json.Unmarshal(env.D, &in); err == nil {
			var hosts []netscan.HostResult
			hosts, err = netscan.ScanSubnet(ctx, in.Subnet, 32)
			if err == nil {
				protoHosts := make([]protocol.DiscoveredHost, 0, len(hosts))
				for _, h := range hosts {
					protoHosts = append(protoHosts, protocol.DiscoveredHost{
						IP:            h.IP,
						MAC:           h.MAC,
						Hostname:      h.Hostname,
						Vendor:        h.Vendor,
						OS:            h.OS,
						DeviceType:    h.DeviceType,
						OpenPorts:     h.OpenPorts,
						SNMPEnabled:   h.SNMPEnabled,
						SNMPSysName:   h.SNMPSysName,
						SNMPSysDescr:  h.SNMPSysDescr,
						SNMPSysUpTime: h.SNMPSysUpTime,
					})
				}
				out = protocol.NetworkScanResp{Hosts: protoHosts}
			}
		}
	case protocol.ReqSNMPPoll:
		var in protocol.SNMPPollReq
		if err = json.Unmarshal(env.D, &in); err == nil {
			var snmpRes *netscan.SNMPResult
			snmpRes, err = netscan.QuerySNMP(in.IP, in.Community, 1500*time.Millisecond)
			if err == nil && snmpRes != nil {
				out = protocol.SNMPPollResp{
					SysName:   snmpRes.SysName,
					SysDescr:  snmpRes.SysDescr,
					SysUpTime: snmpRes.SysUpTime,
				}
			}
		}
	default:
		err = errors.New("unknown request " + env.T)
	}
	if err != nil {
		c.replyErr(env.ID, err)
		return
	}
	c.reply(env.ID, out)
}

// detectSupervisorIPC detects if the worker was spawned under supervisor IPC.
// The platform's own endpoint wins: on Windows the named pipe
// (HOMELAB_RMM_IPC_PIPE, RMM_SUPERVISOR_PIPE), elsewhere the Unix socket
// (HOMELAB_RMM_IPC_SOCKET, RMM_SUPERVISOR_SOCKET); the other kind is only a
// fallback for a supervisor that exported just one of them.
func detectSupervisorIPC() (string, bool) {
	pipe := []string{"HOMELAB_RMM_IPC_PIPE", "RMM_SUPERVISOR_PIPE"}
	sock := []string{"HOMELAB_RMM_IPC_SOCKET", "RMM_SUPERVISOR_SOCKET"}
	order := append(sock, pipe...)
	if runtime.GOOS == "windows" {
		order = append(pipe, sock...)
	}
	for _, name := range order {
		if v := os.Getenv(name); v != "" {
			return v, true
		}
	}
	return "", false
}

func (a *Agent) initSupervisorIPC(ctx context.Context) {
	a.ipcMu.Lock()
	client := a.ipcClient
	a.ipcMu.Unlock()

	if client == nil {
		path, found := detectSupervisorIPC()
		if !found {
			slog.Debug("standalone mode: no supervisor IPC environment detected")
			return
		}

		c, err := supervisor.ConnectIPC(path)
		if err != nil {
			slog.Warn("failed to connect to supervisor IPC, falling back to standalone mode",
				"path", path, "err", err)
			return
		}
		a.ipcMu.Lock()
		a.ipcClient = c
		a.ipcPath = path
		a.ipcMu.Unlock()
		slog.Info("connected to supervisor IPC", "path", path)
	}

	a.ipcMu.Lock()
	if a.heartbeatInterval <= 0 {
		a.heartbeatInterval = 5 * time.Second
	}
	if a.stopHeartbeat == nil {
		a.stopHeartbeat = make(chan struct{})
		a.heartbeatDone = make(chan struct{})
		go a.heartbeatLoop(ctx)
	}
	a.ipcMu.Unlock()
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	a.ipcMu.Lock()
	interval := a.heartbeatInterval
	stopCh := a.stopHeartbeat
	doneCh := a.heartbeatDone
	a.ipcMu.Unlock()

	defer close(doneCh)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Emit immediate first heartbeat
	a.sendHeartbeat()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case <-ticker.C:
			a.sendHeartbeat()
		}
	}
}

func (a *Agent) sendHeartbeat() {
	a.ipcMu.Lock()
	client := a.ipcClient
	a.ipcMu.Unlock()

	if client == nil {
		return
	}

	msg := &supervisor.IPCMessage{
		Type:     supervisor.MsgHeartbeat,
		PID:      os.Getpid(),
		RSSBytes: getProcessRSS(),
	}

	if err := client.Send(msg); err != nil {
		slog.Debug("failed to emit heartbeat to supervisor", "err", err)
	}
}

func (a *Agent) notifyHealthy() {
	a.ipcMu.Lock()
	client := a.ipcClient
	a.ipcMu.Unlock()

	if client == nil {
		return
	}

	msg := &supervisor.IPCMessage{
		Type:    supervisor.MsgNotifyHealthy,
		PID:     os.Getpid(),
		Version: Version,
	}

	if err := client.Send(msg); err != nil {
		slog.Warn("failed to emit notify_healthy to supervisor", "err", err)
	} else {
		slog.Info("emitted notify_healthy to supervisor", "version", Version, "pid", os.Getpid())
	}
}

func (a *Agent) closeSupervisorIPC() {
	a.ipcMu.Lock()
	client := a.ipcClient
	stopCh := a.stopHeartbeat
	doneCh := a.heartbeatDone
	a.ipcClient = nil
	a.stopHeartbeat = nil
	a.heartbeatDone = nil
	a.ipcMu.Unlock()

	if stopCh != nil {
		close(stopCh)
	}
	if doneCh != nil {
		select {
		case <-doneCh:
		case <-time.After(1 * time.Second):
		}
	}
	if client != nil {
		_ = client.Close()
	}
}

func getProcessRSS() uint64 {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err == nil && p != nil {
		if mi, err := p.MemoryInfo(); err == nil && mi != nil {
			return mi.RSS
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys
}

// SetIPCClient allows test fixtures to inject an in-memory or mock supervisor IPC client.
func (a *Agent) SetIPCClient(c *supervisor.IPCClient) {
	a.ipcMu.Lock()
	defer a.ipcMu.Unlock()
	a.ipcClient = c
}

// IPCClient exposes the active IPCClient for update staging flows.
func (a *Agent) IPCClient() *supervisor.IPCClient {
	a.ipcMu.Lock()
	defer a.ipcMu.Unlock()
	return a.ipcClient
}

// SetHeartbeatInterval configures the heartbeat emission frequency.
func (a *Agent) SetHeartbeatInterval(d time.Duration) {
	a.ipcMu.Lock()
	defer a.ipcMu.Unlock()
	a.heartbeatInterval = d
}
