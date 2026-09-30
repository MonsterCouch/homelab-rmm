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

	"github.com/MonsterCouch/homelab-rmm/internal/netscan"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
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
	shells *shellManager
	runs   *scriptRunner
	// baselines is the desired-state engine: its own goroutine, its own
	// on-disk state, running whether or not there is a server to talk to.
	baselines *baselineEngine
	// wake is signalled when the config changes so tickers restart
	wake chan struct{}
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
	a.cmu.Lock()
	a.c = c
	a.cmu.Unlock()
}

func New(cfg *Config) *Agent {
	a := &Agent{cfg: cfg, wake: make(chan struct{}, 1)}
	a.shells = newShellManager()
	a.runs = newScriptRunner()
	a.baselines = newBaselineEngine(a)
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
	return protocol.Hello{
		AgentID: a.cfg.AgentID, Hostname: host, OS: runtime.GOOS, Platform: platformName(),
		Arch: runtime.GOARCH, Version: Version, ProtocolVersion: protocol.Version,
	}
}

func (a *Agent) session(ctx context.Context) error {
	hdr := http.Header{}
	if a.cfg.Key != "" {
		hdr.Set("Authorization", "Bearer "+a.cfg.Key)
	} else if a.cfg.EnrollToken != "" {
		hdr.Set("X-Enroll-Token", a.cfg.EnrollToken)
	} else {
		return errors.New("no agent key and no enrollment token; run `rmm-agent install`")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ws, resp, err := Dial(dialCtx, a.cfg.WSURL("/ws/agent"), a.cfg.Fingerprint, hdr)
	cancel()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized && a.cfg.Key != "" && a.cfg.EnrollToken != "" {
			// key revoked (device deleted on the server) but we still hold a token: re-enroll
			slog.Warn("agent key rejected, re-enrolling with stored token")
			a.cfg.Key, a.cfg.AgentID = "", ""
			a.cfg.Save()
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
	if env.T != "welcome" {
		return errors.New("server refused: " + env.Err)
	}
	var welcome struct {
		AgentID  string               `json:"agent_id"`
		AgentKey string               `json:"agent_key"`
		Config   protocol.AgentConfig `json:"config"`
	}
	if err := json.Unmarshal(env.D, &welcome); err != nil {
		return err
	}
	if welcome.AgentKey != "" {
		a.cfg.AgentID, a.cfg.Key = welcome.AgentID, welcome.AgentKey
		if err := a.cfg.Save(); err != nil {
			slog.Error("cannot save enrollment; the device will re-enroll next start", "err", err)
		} else {
			slog.Info("enrolled", "agent_id", welcome.AgentID)
		}
	}
	a.applyConfig(welcome.Config)
	ws.SetReadDeadline(time.Time{})
	slog.Info("connected", "server", a.cfg.ServerURL, "agent_id", a.cfg.AgentID)
	// Catch-up is exactly one re-send of the cached last report per baseline,
	// with its original timestamp and version; the start-up pass that follows
	// supersedes it server-side (A14).
	go a.baselines.resend()

	sessCtx, stop := context.WithCancel(ctx)
	defer stop()
	go a.pushLoop(sessCtx)
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

func (a *Agent) applyConfig(cfg protocol.AgentConfig) {
	if cfg.MetricsIntervalSec < 5 {
		cfg.MetricsIntervalSec = 30
	}
	if cfg.InventoryIntervalSec < 60 {
		cfg.InventoryIntervalSec = 3600
	}
	a.rmu.Lock()
	a.remote = cfg
	a.rmu.Unlock()
	// The pushed set is always complete: a baseline that is missing here was
	// unassigned, disabled or deleted, and the engine stops it at once (A10).
	if a.baselines != nil {
		a.baselines.setSpecs(cfg.Baselines)
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

	if res.UpdateAvailable && res.URL != "" && res.SHA256 != "" {
		slog.Info("agent auto-update: new binary available on server, updating...", "target_version", res.Version)
		uReq := protocol.AgentUpdate{
			URL:     res.URL,
			SHA256:  res.SHA256,
			Version: res.Version,
		}
		if err := selfUpdate(ctx, a.cfg, uReq); err != nil {
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
	switch env.T {
	case protocol.ReqPing:
		c.send(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
		return
	case protocol.ReqAgentConfig:
		var cfg protocol.AgentConfig
		if json.Unmarshal(env.D, &cfg) == nil {
			a.applyConfig(cfg)
		}
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
			err = selfUpdate(ctx, a.cfg, in)
		}
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
