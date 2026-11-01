package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// SupervisorState indicates the lifecycle status of the supervisor daemon.
type SupervisorState string

const (
	StateStopped    SupervisorState = "stopped"
	StateStarting   SupervisorState = "starting"
	StateRunning    SupervisorState = "running"
	StateRestarting SupervisorState = "restarting"
	StateStopping   SupervisorState = "stopping"
)

// MaxRestartDelayCap strictly bounds restart delay to <= 5.0 seconds per Requirement R1.
const MaxRestartDelayCap = 5 * time.Second

type exitIntent int

const (
	intentUnexpected exitIntent = iota
	intentRestart
	intentWatchdog
	intentRollback
	intentShutdown
)

// SupervisorConfig contains all configuration parameters for the supervisor daemon.
type SupervisorConfig struct {
	// BaseDir is the root application directory (e.g. C:\Program Files\HomelabRMM or /opt/homelab-rmm).
	BaseDir string

	// WorkerCommand is the path to the worker executable. Defaults to slots.GetCurrentBinaryPath().
	WorkerCommand string

	// WorkerBinary is an alias for WorkerCommand.
	WorkerBinary string

	// WorkerArgs specifies arguments passed to the worker command (defaults to ["run"]).
	WorkerArgs []string

	// RestartDelay is the initial delay before restarting a terminated worker (default: 500ms, cap: 5s).
	RestartDelay time.Duration

	// MaxRestartDelay is the maximum backoff delay ceiling (default: 5s, capped at 5s).
	MaxRestartDelay time.Duration

	// ResetCrashAfter is the period of stable operation after which crash counters reset (default: 10s).
	ResetCrashAfter time.Duration

	// HeartbeatTimeout is the silence threshold before the watchdog kills the worker (default: 30s).
	HeartbeatTimeout time.Duration

	// HeartbeatCheckInterval is the polling interval for watchdog heartbeat verification (default: 2s or timeout/4).
	HeartbeatCheckInterval time.Duration

	// RollbackTimeout is the trial timeout for candidate update verification (default: 60s).
	RollbackTimeout time.Duration

	// RollbackCheckInterval is the polling interval for rollback circuit checks (default: 1s or timeout/4).
	RollbackCheckInterval time.Duration

	// Listener allows injecting a pre-created net.Listener (e.g. NewInMemoryPipe() or test listener).
	Listener net.Listener

	// Slots provides an existing SlotManager instance; if nil, InitSlots(BaseDir) is invoked.
	Slots *SlotManager

	// IPCServer provides an existing IPCServer instance; if nil, a new one is initialized.
	IPCServer *IPCServer

	// PipeName overrides the default Windows Named Pipe path.
	PipeName string

	// SocketPath overrides the default Linux Unix Domain Socket path.
	SocketPath string

	// SDDL overrides the default Windows Named Pipe security descriptor.
	SDDL string

	// Env specifies additional environment variables for the worker process.
	Env []string

	// Stdout optionally captures or redirects worker standard output.
	Stdout io.Writer

	// Stderr optionally captures or redirects worker standard error.
	Stderr io.Writer

	// Logger provides structured logging; defaults to slog.Default() if nil.
	Logger *slog.Logger
}

// Supervisor supervises the worker agent process, managing IPC communications,
// heartbeat watchdog monitoring, and the automated 60-second rollback circuit.
type Supervisor struct {
	cfg      SupervisorConfig
	slots    *SlotManager
	ipc      *IPCServer
	listener net.Listener
	ownsIPC  bool
	logger   *slog.Logger

	mu                 sync.RWMutex
	state              SupervisorState
	workerCmd          *exec.Cmd
	workerPID          int
	workerRSS          uint64
	workerStartedAt    time.Time
	lastHeartbeat      time.Time
	heartbeatCounter   uint64
	watchdogTriggered  bool
	watchdogKills      uint64
	restarts           uint64
	consecutiveCrashes int
	expectedIntent     exitIntent
	workerRunning      bool

	workerExitCh chan error
	restartCh    chan string
	stopCh       chan struct{}
	doneCh       chan struct{}
	readyCh      chan struct{}
	readyOnce    sync.Once
	stopped      atomic.Bool
}

// NewSupervisor instantiates a Supervisor with validated configuration and registered IPC handlers.
func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	if cfg.BaseDir == "" && cfg.Slots == nil {
		cfg.BaseDir = DefaultInstallBaseDir
	}
	if cfg.WorkerCommand == "" && cfg.WorkerBinary != "" {
		cfg.WorkerCommand = cfg.WorkerBinary
	}
	if len(cfg.WorkerArgs) == 0 {
		cfg.WorkerArgs = []string{"run"}
	}
	if cfg.RestartDelay <= 0 {
		cfg.RestartDelay = 500 * time.Millisecond
	}
	if cfg.RestartDelay > MaxRestartDelayCap {
		cfg.RestartDelay = MaxRestartDelayCap
	}
	if cfg.MaxRestartDelay <= 0 || cfg.MaxRestartDelay > MaxRestartDelayCap {
		cfg.MaxRestartDelay = MaxRestartDelayCap
	}
	if cfg.ResetCrashAfter <= 0 {
		cfg.ResetCrashAfter = 10 * time.Second
	}
	if cfg.HeartbeatTimeout <= 0 {
		cfg.HeartbeatTimeout = 30 * time.Second
	}
	if cfg.HeartbeatCheckInterval <= 0 {
		cfg.HeartbeatCheckInterval = cfg.HeartbeatTimeout / 4
		if cfg.HeartbeatCheckInterval > 2*time.Second {
			cfg.HeartbeatCheckInterval = 2 * time.Second
		}
		if cfg.HeartbeatCheckInterval < 20*time.Millisecond {
			cfg.HeartbeatCheckInterval = 20 * time.Millisecond
		}
	}
	if cfg.RollbackTimeout <= 0 {
		cfg.RollbackTimeout = 60 * time.Second
	}
	if cfg.RollbackCheckInterval <= 0 {
		cfg.RollbackCheckInterval = cfg.RollbackTimeout / 4
		if cfg.RollbackCheckInterval > 1*time.Second {
			cfg.RollbackCheckInterval = 1 * time.Second
		}
		if cfg.RollbackCheckInterval < 20*time.Millisecond {
			cfg.RollbackCheckInterval = 20 * time.Millisecond
		}
	}
	if cfg.PipeName == "" {
		cfg.PipeName = DefaultPipeName
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultLinuxSocketPath
	}
	if cfg.SDDL == "" && runtime.GOOS == "windows" {
		if cfg.PipeName != "" && cfg.PipeName != DefaultPipeName {
			if sddl, err := CurrentUserSDDL(); err == nil {
				cfg.SDDL = sddl
			} else {
				cfg.SDDL = DefaultSDDL
			}
		} else {
			cfg.SDDL = DefaultSDDL
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default().With("component", "supervisor")
	}

	slotMgr := cfg.Slots
	if slotMgr == nil {
		var err error
		slotMgr, err = InitSlots(cfg.BaseDir)
		if err != nil {
			return nil, fmt.Errorf("init slot manager: %w", err)
		}
	}

	ownsIPC := false
	ipc := cfg.IPCServer
	if ipc == nil {
		ipc = NewIPCServer()
		ownsIPC = true
	}

	var listener net.Listener
	if cfg.Listener != nil {
		listener = cfg.Listener
	} else if ownsIPC {
		var err error
		targetPath := cfg.PipeName
		if runtime.GOOS == "linux" {
			targetPath = cfg.SocketPath
		}
		listener, err = ListenIPC(targetPath, cfg.SDDL)
		if err != nil {
			return nil, fmt.Errorf("listen ipc: %w", err)
		}
	}

	sup := &Supervisor{
		cfg:       cfg,
		slots:     slotMgr,
		ipc:       ipc,
		listener:  listener,
		ownsIPC:   ownsIPC,
		logger:    logger,
		state:     StateStopped,
		restartCh: make(chan string, 8),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		readyCh:   make(chan struct{}),
	}

	sup.registerIPCHandlers()
	return sup, nil
}

// registerIPCHandlers registers handlers for heartbeat, health confirmation,
// restart requests, and inactive slot queries.
func (s *Supervisor) registerIPCHandlers() {
	s.ipc.RegisterHandler(MsgHeartbeat, func(msg *IPCMessage) (*IPCMessage, error) {
		s.mu.Lock()
		defer s.mu.Unlock()

		if s.workerPID != 0 && msg.PID != 0 && msg.PID != s.workerPID {
			s.logger.Warn("discarding heartbeat from mismatched PID",
				"expected_pid", s.workerPID,
				"received_pid", msg.PID,
			)
			return nil, nil
		}

		s.lastHeartbeat = time.Now()
		if msg.PID != 0 {
			s.workerPID = msg.PID
		}
		s.workerRSS = msg.RSSBytes
		s.heartbeatCounter++
		return nil, nil
	})

	s.ipc.RegisterHandler(MsgNotifyHealthy, func(msg *IPCMessage) (*IPCMessage, error) {
		s.mu.Lock()
		if s.workerPID != 0 && msg.PID != 0 && msg.PID != s.workerPID {
			expectedPID := s.workerPID
			s.mu.Unlock()
			s.logger.Warn("mismatched PID for notify_healthy",
				"expected_pid", expectedPID,
				"received_pid", msg.PID,
			)
			return nil, fmt.Errorf("mismatched PID %d (expected %d)", msg.PID, expectedPID)
		}
		s.mu.Unlock()

		s.logger.Info("worker reported healthy over IPC", "version", msg.Version, "pid", msg.PID)
		if err := s.slots.ConfirmHealthy(msg.Version); err != nil {
			s.logger.Error("failed to confirm healthy slot", "err", err)
			return nil, err
		}
		s.mu.Lock()
		s.consecutiveCrashes = 0
		s.mu.Unlock()
		return nil, nil
	})

	s.ipc.RegisterHandler(MsgRequestRestart, func(msg *IPCMessage) (*IPCMessage, error) {
		s.mu.Lock()
		if s.workerPID != 0 && msg.PID != 0 && msg.PID != s.workerPID {
			expectedPID := s.workerPID
			s.mu.Unlock()
			s.logger.Warn("mismatched PID for request_restart",
				"expected_pid", expectedPID,
				"received_pid", msg.PID,
			)
			return nil, fmt.Errorf("mismatched PID %d (expected %d)", msg.PID, expectedPID)
		}
		s.mu.Unlock()

		s.logger.Info("worker requested restart over IPC", "reason", msg.Reason, "version", msg.Version, "pid", msg.PID)
		if msg.Reason == "update_staged" {
			if err := s.slots.PromotePending(msg.Version); err != nil {
				s.logger.Error("failed to promote pending slot on restart request", "err", err)
				return nil, err
			}
			s.logger.Info("promoted staged update to pending slot", "version", msg.Version)
		}

		s.mu.Lock()
		s.expectedIntent = intentRestart
		s.consecutiveCrashes = 0
		cmd := s.workerCmd
		s.mu.Unlock()

		select {
		case s.restartCh <- msg.Reason:
		default:
		}

		// Safety timeout: ensure old worker process terminates
		go func() {
			time.Sleep(1 * time.Second)
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.workerCmd == cmd && cmd != nil && cmd.Process != nil {
				_ = terminateWorkerProcess(cmd.Process)
			}
		}()

		return nil, nil
	})

	s.ipc.RegisterHandler(MsgGetInactive, func(msg *IPCMessage) (*IPCMessage, error) {
		inactiveSlot := s.slots.GetInactiveSlot()
		inactiveDir := s.slots.GetInactiveSlotDir()
		activeSlot := s.slots.GetActiveSlot()

		return &IPCMessage{
			Type:         MsgInactiveResp,
			Slot:         inactiveSlot,
			Path:         inactiveDir,
			ActiveSlot:   activeSlot,
			InactiveSlot: inactiveSlot,
		}, nil
	})
}

// Start launches the supervisor event loop, starts the IPC server, spawns the worker process,
// and blocks until context cancellation or Stop() is invoked.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.state != StateStopped {
		s.mu.Unlock()
		return errors.New("supervisor already started")
	}
	s.state = StateStarting
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.state = StateStopped
		s.mu.Unlock()
		close(s.doneCh)
	}()

	// 1. Rollback Circuit Pre-Check on Boot
	// If the host crashed or rebooted during an update trial, roll back before spawning.
	rolledBack, err := s.slots.CheckRollbackCircuit(s.cfg.RollbackTimeout)
	if err != nil {
		s.logger.Error("error checking rollback circuit on startup", "err", err)
	} else if rolledBack {
		s.logger.Warn("stale pending update was automatically rolled back on supervisor boot")
	}

	// 2. Start IPC server
	if s.ownsIPC && s.listener != nil {
		if err := s.ipc.Start(s.listener); err != nil {
			return fmt.Errorf("start ipc server: %w", err)
		}
		defer func() {
			_ = s.ipc.Stop()
		}()
	}

	// 3. Initial Worker Spawn
	var restartTimer *time.Timer
	var restartTimerCh <-chan time.Time

	if err := s.spawnWorker(); err != nil {
		s.logger.Error("initial worker spawn failed, scheduling restart", "err", err)
		s.scheduleRestart(&restartTimer, &restartTimerCh)
	}

	s.readyOnce.Do(func() {
		close(s.readyCh)
	})

	watchdogTicker := time.NewTicker(s.cfg.HeartbeatCheckInterval)
	defer watchdogTicker.Stop()

	rollbackTicker := time.NewTicker(s.cfg.RollbackCheckInterval)
	defer rollbackTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("supervisor shutdown requested via context")
			s.shutdown()
			return nil

		case <-s.stopCh:
			s.logger.Info("supervisor shutdown requested via Stop()")
			s.shutdown()
			return nil

		case exitErr := <-s.workerExitCh:
			s.handleWorkerExit(exitErr, &restartTimer, &restartTimerCh)

		case <-restartTimerCh:
			restartTimerCh = nil
			if err := s.spawnWorker(); err != nil {
				s.logger.Error("failed to restart worker", "err", err)
				s.scheduleRestart(&restartTimer, &restartTimerCh)
			}

		case reason := <-s.restartCh:
			s.logger.Info("processing worker restart request", "reason", reason)
			s.mu.Lock()
			s.expectedIntent = intentRestart
			s.consecutiveCrashes = 0
			cmd := s.workerCmd
			s.mu.Unlock()
			if cmd != nil && cmd.Process != nil {
				_ = terminateWorkerProcess(cmd.Process)
			}

		case <-watchdogTicker.C:
			s.checkWatchdog()

		case <-rollbackTicker.C:
			s.checkRollbackCircuit()
		}
	}
}

// Run is an alias for Start(ctx), executing the supervisor run loop.
func (s *Supervisor) Run(ctx context.Context) error {
	return s.Start(ctx)
}

// spawnWorker starts the worker executable with platform window suppression and IPC environment variables.
func (s *Supervisor) spawnWorker() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StateStopping || s.state == StateStopped {
		return nil
	}

	binPath := s.cfg.WorkerCommand
	if binPath == "" {
		binPath = s.slots.GetCurrentBinaryPath()
	}

	cmd := exec.Command(binPath, s.cfg.WorkerArgs...)
	configureWorkerProc(cmd)

	// Propagate environment
	cmd.Env = append(os.Environ(), s.cfg.Env...)
	// Only the endpoint this platform listens on is handed to the worker.
	// Both names used to be exported everywhere, and a Linux worker took
	// the Windows pipe name first, could not dial it, ran standalone and
	// was killed by the watchdog every 30 seconds for never heartbeating.
	if runtime.GOOS == "windows" {
		if s.cfg.PipeName != "" {
			cmd.Env = append(cmd.Env, "HOMELAB_RMM_IPC_PIPE="+s.cfg.PipeName, "RMM_SUPERVISOR_PIPE="+s.cfg.PipeName)
		}
	} else if s.cfg.SocketPath != "" {
		cmd.Env = append(cmd.Env, "HOMELAB_RMM_IPC_SOCKET="+s.cfg.SocketPath, "RMM_SUPERVISOR_SOCKET="+s.cfg.SocketPath)
	}

	if s.cfg.Stdout != nil {
		cmd.Stdout = s.cfg.Stdout
	}
	if s.cfg.Stderr != nil {
		cmd.Stderr = s.cfg.Stderr
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start worker %s: %w", binPath, err)
	}

	s.workerCmd = cmd
	s.workerPID = cmd.Process.Pid
	s.workerRunning = true
	s.workerStartedAt = time.Now()
	s.lastHeartbeat = time.Now()
	s.watchdogTriggered = false
	s.state = StateRunning
	s.expectedIntent = intentUnexpected

	exitCh := make(chan error, 1)
	s.workerExitCh = exitCh

	go func(c *exec.Cmd, ch chan error) {
		ch <- c.Wait()
	}(cmd, exitCh)

	s.logger.Info("worker process spawned successfully", "pid", s.workerPID, "path", binPath)
	return nil
}

// handleWorkerExit evaluates process termination, triggers rollback if candidate crashed,
// and schedules process restart within 5 seconds.
func (s *Supervisor) handleWorkerExit(exitErr error, timer **time.Timer, timerCh *<-chan time.Time) {
	s.mu.Lock()
	intent := s.expectedIntent
	startedAt := s.workerStartedAt
	pid := s.workerPID
	s.workerCmd = nil
	s.workerPID = 0
	s.workerRunning = false
	s.state = StateRestarting
	s.restarts++
	s.expectedIntent = intentUnexpected
	s.mu.Unlock()

	s.logger.Warn("worker process exited", "pid", pid, "err", exitErr, "intent", intent, "restarts", s.restarts)

	if intent == intentShutdown {
		return
	}

	// 1. Candidate Crash during Verification Trial -> Immediate Rollback!
	state := s.slots.GetState()
	if state.PendingSlot != "" && (intent == intentUnexpected || intent == intentWatchdog) {
		s.logger.Warn("candidate worker crashed during verification trial; rolling back to active slot",
			"pending_slot", state.PendingSlot,
			"active_slot", state.ActiveSlot,
		)
		if err := s.slots.Rollback(); err != nil {
			s.logger.Error("failed to rollback slot after candidate crash", "err", err)
		}
		// Reset crashes so known-good active slot starts immediately
		s.mu.Lock()
		s.consecutiveCrashes = 0
		s.mu.Unlock()
		if err := s.spawnWorker(); err != nil {
			s.logger.Error("failed to spawn active worker after candidate rollback", "err", err)
			s.scheduleRestart(timer, timerCh)
		}
		return
	}

	// 2. Normal worker crash / external kill / intentional restart
	s.mu.Lock()
	if time.Since(startedAt) > s.cfg.ResetCrashAfter {
		s.consecutiveCrashes = 0
	}
	if intent != intentRestart && intent != intentRollback {
		s.consecutiveCrashes++
	} else {
		s.consecutiveCrashes = 0
	}
	s.mu.Unlock()

	// If intent was intentRestart or intentRollback, restart immediately
	if intent == intentRestart || intent == intentRollback {
		if err := s.spawnWorker(); err != nil {
			s.logger.Error("failed to spawn worker after restart/rollback", "err", err)
			s.scheduleRestart(timer, timerCh)
		}
		return
	}

	// External taskkill or crash: schedule throttled restart (strictly capped at 5s)
	s.scheduleRestart(timer, timerCh)
}

// scheduleRestart computes backoff delay bounded by MaxRestartDelayCap and arms the restart timer.
func (s *Supervisor) scheduleRestart(timer **time.Timer, timerCh *<-chan time.Time) {
	s.mu.RLock()
	crashes := s.consecutiveCrashes
	baseDelay := s.cfg.RestartDelay
	maxDelay := s.cfg.MaxRestartDelay
	s.mu.RUnlock()

	var delay time.Duration
	if crashes <= 1 {
		delay = baseDelay
	} else {
		delay = baseDelay * time.Duration(1<<(crashes-1))
	}
	if delay > maxDelay {
		delay = maxDelay
	}
	if delay > MaxRestartDelayCap {
		delay = MaxRestartDelayCap
	}

	s.logger.Info("scheduling worker restart", "delay", delay, "consecutive_crashes", crashes)
	if *timer != nil {
		(*timer).Stop()
	}
	t := time.NewTimer(delay)
	*timer = t
	*timerCh = t.C
}

// checkWatchdog inspects last heartbeat timestamp and kills hung worker processes.
func (s *Supervisor) checkWatchdog() {
	s.mu.Lock()
	if s.workerCmd == nil || s.workerPID == 0 || s.state != StateRunning || s.watchdogTriggered {
		s.mu.Unlock()
		return
	}
	elapsed := time.Since(s.lastHeartbeat)
	overdue := elapsed > s.cfg.HeartbeatTimeout
	cmd := s.workerCmd
	pid := s.workerPID
	if overdue {
		s.watchdogTriggered = true
		s.watchdogKills++
		s.expectedIntent = intentWatchdog
	}
	s.mu.Unlock()

	if overdue && cmd != nil && cmd.Process != nil {
		s.logger.Warn("watchdog heartbeat timeout: worker process unresponsive, terminating",
			"pid", pid,
			"elapsed", elapsed,
			"timeout", s.cfg.HeartbeatTimeout,
			"watchdog_kills", s.watchdogKills,
		)
		_ = terminateWorkerProcess(cmd.Process)
	}
}

// checkRollbackCircuit inspects update trial duration and triggers rollback if verification expired.
func (s *Supervisor) checkRollbackCircuit() {
	if s.slots == nil {
		return
	}

	rolledBack, err := s.slots.CheckRollbackCircuit(s.cfg.RollbackTimeout)
	if err != nil {
		s.logger.Error("rollback circuit check error", "err", err)
		return
	}
	if rolledBack {
		s.logger.Warn("candidate worker failed to signal healthy check-in within timeout; update rolled back to active slot",
			"timeout", s.cfg.RollbackTimeout,
		)
		s.mu.Lock()
		s.expectedIntent = intentRollback
		cmd := s.workerCmd
		s.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			_ = terminateWorkerProcess(cmd.Process)
		}
	}
}

// shutdown terminates the worker process tree and stops the IPC server.
func (s *Supervisor) shutdown() {
	s.mu.Lock()
	if s.state == StateStopping || s.state == StateStopped {
		s.mu.Unlock()
		return
	}
	s.state = StateStopping
	s.expectedIntent = intentShutdown
	cmd := s.workerCmd
	exitCh := s.workerExitCh
	s.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		_ = terminateWorkerProcess(cmd.Process)
		if exitCh != nil {
			select {
			case <-exitCh:
			case <-time.After(3 * time.Second):
				s.logger.Warn("timed out waiting for worker process exit on shutdown")
			}
		}
	}

	if s.ownsIPC && s.ipc != nil {
		_ = s.ipc.Stop()
	}
}

// Stop initiates graceful shutdown of the supervisor and unblocks Start().
func (s *Supervisor) Stop() error {
	if s.stopped.Swap(true) {
		return nil
	}
	close(s.stopCh)
	s.mu.Lock()
	isStarted := s.state != StateStopped
	s.mu.Unlock()
	if isStarted {
		<-s.doneCh
	}
	return nil
}

// State returns the current lifecycle status of the supervisor.
func (s *Supervisor) State() SupervisorState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// WorkerPID returns the process ID of the currently supervised worker, or 0 if not running.
func (s *Supervisor) WorkerPID() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.workerPID
}

// RestartCount returns the number of worker restarts performed by the supervisor.
func (s *Supervisor) RestartCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int(s.restarts)
}

// LastHeartbeat returns the timestamp of the most recent heartbeat received.
func (s *Supervisor) LastHeartbeat() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastHeartbeat
}

// HeartbeatCount returns the total number of heartbeats ingested.
func (s *Supervisor) HeartbeatCount() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.heartbeatCounter
}

// WatchdogKills returns the number of times the watchdog terminated an unresponsive worker.
func (s *Supervisor) WatchdogKills() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.watchdogKills
}

// Slots returns the underlying SlotManager.
func (s *Supervisor) Slots() *SlotManager {
	return s.slots
}

// IPC returns the IPCServer instance.
func (s *Supervisor) IPC() *IPCServer {
	return s.ipc
}

// IPCServer returns the IPCServer instance.
func (s *Supervisor) IPCServer() *IPCServer {
	return s.ipc
}

// Addr returns the network address of the supervisor IPC listener.
func (s *Supervisor) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	if s.ipc != nil {
		return s.ipc.Addr()
	}
	return nil
}

// Ready returns a channel that is closed once the supervisor has initialized IPC
// and launched its initial worker spawn attempt.
func (s *Supervisor) Ready() <-chan struct{} {
	return s.readyCh
}

// ConnectIPC creates and connects an IPCClient to the supervisor at targetPath.
// If targetPath is empty, DefaultPipeName (Windows) or DefaultLinuxSocketPath (Linux/other) is used.
func ConnectIPC(targetPath string) (*IPCClient, error) {
	dial := func() (net.Conn, error) {
		p := targetPath
		if runtime.GOOS == "windows" {
			if p == "" {
				p = DefaultPipeName
			}
			return DialPipe(p, 5*time.Second)
		}
		if p == "" {
			p = DefaultLinuxSocketPath
		}
		return DialUDS(p, 5*time.Second)
	}

	conn, err := dial()
	if err != nil {
		return nil, fmt.Errorf("connect ipc to %s: %w", targetPath, err)
	}
	client := NewIPCClient(dial, 5*time.Second)
	_ = client.Connect(conn)
	return client, nil
}
