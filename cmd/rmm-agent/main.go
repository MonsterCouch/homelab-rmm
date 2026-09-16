// rmm-agent is the device-side daemon of Homelab RMM.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"

	"github.com/MonsterCouch/homelab-rmm/internal/agent"
	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop"
	"github.com/MonsterCouch/homelab-rmm/internal/svc"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Homelab RMM agent %s

Usage:
  rmm-agent run [--config-dir DIR]       run in the foreground (what the service runs)
  rmm-agent install --server URL --token TOKEN [--fingerprint HEX] [--config-dir DIR]
                                         save config, register the service and start it
  rmm-agent uninstall | start | stop | restart | status   [--config-dir DIR]
  rmm-agent desktop-helper --server URL --token TOKEN [--fingerprint HEX] [--quality N]
  rmm-agent version

Config: %s
  --config-dir (or %s) moves it. install writes agent.json there AND records
  the directory in the service definition, because the service manager starts
  the agent with a clean environment. Note that sudo drops %s: pass
  --config-dir, or use "sudo -E" / "sudo %s=DIR ...".
`, agent.Version, agent.ConfigPath(), agent.EnvConfigDir, agent.EnvConfigDir, agent.EnvConfigDir)
}

func spec() svc.Spec {
	args := []string{"run"}
	// The service manager starts the agent with an environment of its own:
	// the RMM_AGENT_DIR the operator (or the install script) exported for
	// `install` is not there to be inherited, and sudo's env_reset drops it
	// before the documented one-liner runs at all. So the directory agent.json
	// was actually written to is pinned onto the command line that the service
	// definition stores - a systemd ExecStart= or the Windows ImagePath - and
	// the service is guaranteed to read the config the install just wrote
	// rather than whatever sits at the default path.
	if dir := configDir(); dir != agent.DefaultConfigDir() {
		args = append(args, "--config-dir", dir)
	}
	return svc.Spec{
		Name:        agent.ServiceName,
		DisplayName: "Homelab RMM Agent",
		Description: "Remote monitoring and management agent for Homelab RMM.",
		Args:        args,
	}
}

// configDir is agent.ConfigDir() as an absolute path. A relative directory is
// fine while a developer runs the agent from the repository, but it must not
// reach a service definition: the service starts from / (or C:\Windows\system32).
func configDir() string {
	dir := agent.ConfigDir()
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// configDirFlag registers --config-dir on fs. Every command that resolves a
// path takes it, so the operator can name the directory on the command line
// instead of through an environment variable that sudo throws away.
func configDirFlag(fs *flag.FlagSet) *string {
	return fs.String("config-dir", "", "directory holding agent.json (default $"+agent.EnvConfigDir+", else "+agent.DefaultConfigDir()+")")
}

// applyConfigDir pins the directory for this process before anything derives a
// path from it - the log file included.
func applyConfigDir(dir string) {
	if dir == "" {
		return
	}
	if _, err := agent.SetConfigDir(dir); err != nil {
		fmt.Fprintln(os.Stderr, "--config-dir:", err)
		os.Exit(2)
	}
}

// logDest says which file a command adds to stderr. The distinction matters
// because the two long-running commands do not have the same rights: the
// service owns ConfigDir and rotates its log there, while the desktop helper
// runs in the user's session, usually cannot write ConfigDir at all, and must
// never rename a file the service holds open.
type logDest int

const (
	logStderrOnly logDest = iota // one-shot commands: the console is the log
	logService                   // rmm-agent run, under the service manager
	logHelper                    // rmm-agent desktop-helper, in the user session
)

const (
	serviceLogRotateAt = 10 << 20 // rename agent.log to agent.log.1 past this
	helperLogMax       = 1 << 20  // restart the helper's own log past this
)

// setupLogging installs the process-wide slog handler and returns the file it
// also writes to, or "" when only stderr is open.
func setupLogging(dest logDest) string {
	f, path := openLog(dest)
	setupHandler(os.Stderr, f)
	return path
}

// setupHandler installs the handler over the sinks the caller opened, and is
// separate from setupLogging because the console is the sink that is not
// there: a process the Windows Service Control Manager started has no standard
// handles, so every write to os.Stderr fails for the whole life of the
// service. svc.LogWriter is what stops that taking the log file down with it -
// see its comment - and naming both sinks here is what lets a test stand a
// broken stderr up.
func setupHandler(stderr io.Writer, file *os.File) {
	sinks := []io.Writer{stderr}
	if file != nil {
		sinks = append(sinks, file)
	}
	level := slog.LevelInfo
	if os.Getenv("RMM_DEBUG") != "" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(svc.LogWriter(sinks...), &slog.HandlerOptions{Level: level})))
}

// openLog opens the log file for dest. It returns nil when dest has no file
// and when nothing writable could be found: a process that cannot open a log
// still runs, it just logs to stderr alone. The file is never closed - it
// lives as long as the process.
func openLog(dest logDest) (*os.File, string) {
	switch dest {
	case logStderrOnly:
		return nil, ""
	case logService:
		// EnsureConfigDir, not a bare MkdirAll: on Windows the directory
		// needs its protected DACL before agent.log is created inside it,
		// or the log (which quotes config paths, hostnames and errors)
		// inherits %ProgramData%'s "Users can read" ACL.
		if err := agent.EnsureConfigDir(); err != nil {
			return nil, ""
		}
		path := agent.LogPath()
		if st, err := os.Stat(path); err == nil && st.Size() > serviceLogRotateAt {
			os.Rename(path, path+".1")
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, ""
		}
		return f, path
	case logHelper:
		// The first candidate that opens wins; the helper creates no
		// directories and rotates nothing. Capping by starting the file
		// over is deliberate: a rename is what would steal a concurrent
		// helper's open file, and a helper session writes a handful of
		// lines, so there is nothing here worth keeping two copies of.
		for _, path := range agent.HelperLogPaths() {
			flags := os.O_CREATE | os.O_APPEND | os.O_WRONLY
			if st, err := os.Stat(path); err == nil && st.Size() > helperLogMax {
				flags = os.O_CREATE | os.O_TRUNC | os.O_WRONLY
			}
			if f, err := os.OpenFile(path, flags, 0o600); err == nil {
				return f, path
			}
		}
	}
	return nil, ""
}

// ---- did the service we just installed actually start? ----

// The two messages `run` writes before it gives up. The installer looks for
// them in the log the service it just started writes, so both sites name the
// same constant.
const (
	msgConfigLoadFailed = "cannot load config"
	msgAgentStopped     = "agent stopped"
)

const (
	startSettle = 3 * time.Second // watch this long before believing a "running"
	// Give up waiting for it to reach "running" - but only after the service
	// manager itself has made up its mind. The Windows SCM waits 30 s for a
	// service to connect to it and only then reports the failure (System event
	// 7009), so a shorter deadline here returned "it never said stopped
	// either" for a service the SCM was about to call dead.
	startTimeout = 45 * time.Second
	startPoll    = 300 * time.Millisecond
)

// statusOnly is the service.Interface service.New insists on for a handle that
// is only ever asked for its Status; neither method is reachable.
type statusOnly struct{}

func (statusOnly) Start(service.Service) error { return nil }
func (statusOnly) Stop(service.Service) error  { return nil }

// serviceStatus asks the service manager about the registered service.
// svc.Control prints the state rather than returning it, and Status reads
// nothing from the spec but the name, so the handle is built here.
func serviceStatus() (service.Status, error) {
	s, err := service.New(statusOnly{}, &service.Config{Name: spec().Name})
	if err != nil {
		return service.StatusUnknown, err
	}
	return s.Status()
}

// logSize is the current length of path, or 0 when there is no file yet.
func logSize(path string) int64 {
	if st, err := os.Stat(path); err == nil {
		return st.Size()
	}
	return 0
}

// startupFailure returns the first fatal line the agent wrote to its log after
// offset from, or "". Starting from an offset taken before the service was
// started is what keeps last month's failure out of this install's verdict; a
// file shorter than the offset was rotated or replaced under us, so it is read
// from the beginning instead. Only the two messages that precede os.Exit(1)
// count: a WARN (a server that is not up yet, say) is not an install failure.
func startupFailure(path string, from int64) string {
	f, err := os.Open(path)
	if err != nil {
		return "" // no log, or not ours to read: nothing to say
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() < from {
		from = 0
	}
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		for _, msg := range []string{msgConfigLoadFailed, msgAgentStopped} {
			if strings.Contains(line, `msg="`+msg+`"`) {
				return line
			}
		}
	}
	return ""
}

// confirmStarted waits for the service just installed to show that it is
// really running, and returns the reason it is not.
//
// Two signals, because neither is enough alone. The service manager can say
// "stopped" - a Windows service that exited before its first status report -
// but systemd maps a unit that is crash-looping under Restart=always to
// "activating", which reads as running, so a service that starts, cannot load
// its config and exits looks healthy from there. The agent's own log is what
// catches that one. Neither signal is fatal when it cannot be taken: a
// platform whose Status is unimplemented, and a log that was never created or
// cannot be read, must not fail an install that worked.
func confirmStarted(logPath string, from int64, status func() (service.Status, error), settle, timeout time.Duration) error {
	settled := time.Now().Add(settle)
	deadline := time.Now().Add(timeout)
	for {
		if line := startupFailure(logPath, from); line != "" {
			return errors.New("the agent logged: " + line)
		}
		st, err := status()
		switch {
		case err == nil && st == service.StatusStopped:
			return errors.New("the service manager reports it stopped")
		case err != nil && strings.Contains(err.Error(), "failed state"):
			// systemd has no Status value for a unit in "failed"; kardianos
			// hands it back as this error. It is a definite answer, unlike
			// the unreadable ones below.
			return errors.New("the service manager reports it failed")
		}
		now := time.Now()
		if !now.Before(settled) && (err != nil || st == service.StatusRunning) {
			return nil
		}
		if !now.Before(deadline) {
			return nil // it never said "running", but it never said "stopped" either
		}
		time.Sleep(startPoll)
	}
}

// startFailureHint names every place a failed start left a reason, because the
// operator reading it has nothing else to go on. The agent's own log comes
// first; the service manager's record is the fallback for a process that died
// before it could log anything at all, and on Windows the service is
// registered with SERVICE_ERROR_NORMAL precisely so that record exists.
func startFailureHint(logPath, goos string) string {
	hint := "the install did not succeed; check " + logPath
	if goos == "windows" {
		return hint + ", and the System event log for Service Control Manager entries about " + agent.ServiceName
	}
	return hint + ", and `journalctl -u " + agent.ServiceName + "` (or /var/log/" + agent.ServiceName + ".err without systemd)"
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "version", "-v", "--version":
		fmt.Println(agent.Version)
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		dir := configDirFlag(fs)
		fs.Parse(os.Args[2:])
		// Before setupLogging: agent.log lives in this directory too.
		applyConfigDir(*dir)
		setupLogging(logService)
		cfg, err := agent.LoadConfig()
		if err != nil {
			slog.Error(msgConfigLoadFailed, "path", agent.ConfigPath(), "err", err)
			os.Exit(1)
		}
		// Not only at install time: a config edited by hand, or copied from
		// another device, has to say so on every start of the service.
		if cfg.Plaintext() {
			slog.Warn("server URL is plaintext: the device key and everything this agent sends travel unencrypted",
				"server_url", cfg.ServerURL, "fingerprint_ignored", cfg.Fingerprint != "")
		}
		err = svc.Run(spec(), func(ctx context.Context) error { return agent.New(cfg).Run(ctx) })
		if err != nil {
			slog.Error(msgAgentStopped, "err", err)
			os.Exit(1)
		}
	case "install":
		fs := flag.NewFlagSet("install", flag.ExitOnError)
		server := fs.String("server", "", "server URL, e.g. https://rmm.lan:8443")
		token := fs.String("token", "", "enrolment token from the console")
		fp := fs.String("fingerprint", "", "server certificate SHA-256 fingerprint (omit when the certificate is publicly trusted)")
		noService := fs.Bool("no-service", false, "write the config only; do not register a service")
		dir := configDirFlag(fs)
		fs.Parse(os.Args[2:])
		applyConfigDir(*dir)
		if *server == "" || *token == "" {
			fmt.Fprintln(os.Stderr, "--server and --token are required")
			os.Exit(2)
		}
		cfg := &agent.Config{ServerURL: strings.TrimRight(*server, "/"), EnrollToken: *token, Fingerprint: strings.ToLower(strings.ReplaceAll(*fp, ":", ""))}
		if old, err := agent.LoadConfig(); err == nil && old.ServerURL == cfg.ServerURL && old.Key != "" {
			cfg.AgentID, cfg.Key = old.AgentID, old.Key // keep identity across reinstalls
		}
		if err := cfg.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "cannot write config:", err)
			os.Exit(1)
		}
		fmt.Println("config written to", agent.ConfigPath())
		// Warnings, not refusals: a loopback server without TLS and an agent
		// run out of its own build tree are both normal while developing, and
		// an install that could not be completed would only be worked around.
		if w := cfg.PlaintextWarning(); w != "" {
			fmt.Fprintln(os.Stderr, w)
		}
		if *noService {
			return
		}
		if exe, err := os.Executable(); err == nil {
			if w := svc.ImagePathWarning(exe); w != "" {
				fmt.Fprintln(os.Stderr, w)
			}
		}
		// Read the log's length before the service touches it, so the
		// check below only ever reads what this start wrote.
		logPath := agent.LogPath()
		from := logSize(logPath)
		if err := svc.Control(spec(), "install"); err != nil {
			fmt.Fprintln(os.Stderr, "service install failed:", err)
			os.Exit(1)
		}
		if err := confirmStarted(logPath, from, serviceStatus, startSettle, startTimeout); err != nil {
			fmt.Fprintln(os.Stderr, "the service was registered but is not running:", err)
			fmt.Fprintln(os.Stderr, startFailureHint(logPath, runtime.GOOS))
			os.Exit(1)
		}
		fmt.Println("service installed and started")
	case "uninstall", "start", "stop", "restart", "status":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		dir := configDirFlag(fs)
		fs.Parse(os.Args[2:])
		applyConfigDir(*dir)
		if err := svc.Control(spec(), cmd); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if cmd == "uninstall" {
			fmt.Println("service removed; config left at", agent.ConfigPath())
		}
	case "desktop-helper":
		// Its own log file: the service's belongs to the service (desk-04).
		logPath := setupLogging(logHelper)
		fs := flag.NewFlagSet("desktop-helper", flag.ExitOnError)
		server := fs.String("server", "", "")
		token := fs.String("token", "", "")
		fp := fs.String("fingerprint", "", "")
		quality := fs.Int("quality", 60, "")
		fs.Parse(os.Args[2:])
		// The launcher passes the one-time token in the environment so it
		// never shows up in /proc/<pid>/cmdline or Process Explorer;
		// --token stays as a developer override. Drop it from our own
		// environment once read: nothing this process starts needs it.
		if *token == "" {
			*token = os.Getenv(desktop.TokenEnv)
		}
		os.Unsetenv(desktop.TokenEnv)
		slog.Info("desktop helper starting", "server", *server, "quality", *quality, "log", logPath)
		if err := desktop.Serve(context.Background(), *server, *token, *fp, *quality); err != nil {
			slog.Error("desktop helper ended", "err", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}
