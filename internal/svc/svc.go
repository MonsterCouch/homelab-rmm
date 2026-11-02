// Package svc wraps kardianos/service so both binaries install the same way:
// a Windows service (automatic start, restart on failure) or a systemd unit.
package svc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"
)

// Spec describes the service to register.
type Spec struct {
	Name        string
	DisplayName string
	Description string
	Args        []string // arguments passed to the executable when the service starts
	WorkingDir  string
}

type program struct {
	run    func(ctx context.Context) error
	cancel context.CancelFunc
	done   chan struct{}
}

func (p *program) Start(s service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		if err := p.run(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "service exited:", err)
		}
	}()
	return nil
}

func (p *program) Stop(s service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.done != nil {
		<-p.done
	}
	return nil
}

func config(spec Spec) *service.Config {
	cfg := &service.Config{
		Name:             spec.Name,
		DisplayName:      spec.DisplayName,
		Description:      spec.Description,
		Arguments:        spec.Args,
		WorkingDirectory: spec.WorkingDir,
		Option:           service.KeyValue{},
	}
	if runtime.GOOS == "windows" {
		cfg.Option["OnFailure"] = "restart"
		cfg.Option["OnFailureDelayDuration"] = "5s"
		cfg.Option["OnFailureResetPeriod"] = 60
		cfg.Option["StartType"] = "automatic"
		cfg.Option["DelayedAutoStart"] = false
	} else {
		cfg.Option["Restart"] = "always"
		cfg.Option["SystemdScript"] = systemdUnit
	}
	return cfg
}

// Run executes fn under the service manager's control. When launched from a
// terminal it just runs fn directly, so `rmm-agent run` works either way.
func Run(spec Spec, fn func(ctx context.Context) error) error {
	p := &program{run: fn}
	s, err := service.New(p, config(spec))
	if err != nil {
		return err
	}
	if service.Interactive() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-interrupt()
			cancel()
		}()
		return fn(ctx)
	}
	return s.Run()
}

// Control runs install/uninstall/start/stop/restart/status.
func Control(spec Spec, action string) error {
	s, err := service.New(&program{run: func(context.Context) error { return nil }}, config(spec))
	if err != nil {
		return err
	}
	switch action {
	case "status":
		st, err := s.Status()
		if err != nil {
			// A SysV init script reports a stopped service by printing
			// "Stopped" and exiting 1. kardianos turns that non-zero exit into
			// an error and throws the output away, so `status` printed
			// "exit status 1" and exited 1 for a service that is merely
			// stopped. Ask the script itself.
			if st2, ok := initScriptStatus(spec.Name, s.Platform()); ok {
				st, err = st2, nil
			}
		}
		if err != nil {
			return err
		}
		switch st {
		case service.StatusRunning:
			fmt.Println("running")
		case service.StatusStopped:
			fmt.Println("stopped")
		default:
			fmt.Println("unknown")
		}
		return nil
	case "install":
		// Idempotent reinstall. DeleteService on a running service only marks
		// it for deletion and the following CreateService fails with
		// ERROR_SERVICE_MARKED_FOR_DELETE, so stop it and wait first.
		if st, err := s.Status(); err == nil && st != service.StatusStopped {
			_ = s.Stop()
			waitForStatus(s, service.StatusStopped, 60*time.Second)
		}
		_ = s.Uninstall()
		waitGone(s, 15*time.Second)
		if err := s.Install(); err != nil {
			return err
		}
		if err := setErrorControl(spec.Name); err != nil {
			// Not fatal: the service is registered and will run. It just
			// will not leave a Service Control Manager entry behind when it
			// fails to start, which is the diagnostic of last resort.
			fmt.Fprintln(os.Stderr, "warning: could not set the service's error control:", err)
		}
		return s.Start()
	case "uninstall":
		_ = s.Stop()
		return s.Uninstall()
	default:
		return service.Control(s, action)
	}
}

// initScriptStatus re-runs a SysV init script and reads its own verdict.
// Only meaningful on the SysV fallback; every other platform returns false.
func initScriptStatus(name, platform string) (service.Status, bool) {
	if !strings.Contains(platform, "systemv") {
		return service.StatusUnknown, false
	}
	script := "/etc/init.d/" + name
	if _, err := os.Stat(script); err != nil {
		return service.StatusUnknown, false
	}
	out, _ := exec.Command(script, "status").CombinedOutput() // exit code is the thing we are working around
	switch text := strings.TrimSpace(string(out)); {
	case strings.HasPrefix(text, "Running"):
		return service.StatusRunning, true
	case strings.HasPrefix(text, "Stopped"):
		return service.StatusStopped, true
	}
	return service.StatusUnknown, false
}

// Describe says, in one line, what `install` actually registered. On a host
// without systemd kardianos silently falls back to a SysV init script, which
// no document mentions and whose output goes somewhere else entirely - and
// the documented `systemctl status <name>` then fails.
func Describe(spec Spec) string {
	s, err := service.New(&program{run: func(context.Context) error { return nil }}, config(spec))
	if err != nil {
		return "service installed and started"
	}
	switch p := s.Platform(); {
	case strings.Contains(p, "systemd"):
		return "registered systemd unit " + spec.Name + " and started it (systemctl status " + spec.Name + ")"
	case strings.Contains(p, "systemv"):
		return "no systemd on this host: registered SysV init script /etc/init.d/" + spec.Name +
			" and started it (service " + spec.Name + " status; its output goes to /var/log/" + spec.Name + ".log and .err)"
	case strings.Contains(p, "windows"):
		return "registered Windows service " + spec.Name + " and started it (sc query " + spec.Name + ")"
	default:
		return "registered " + p + " service " + spec.Name + " and started it"
	}
}

func waitForStatus(s service.Service, want service.Status, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, err := s.Status(); err != nil || st == want {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// waitGone returns once Status reports the service no longer exists.
func waitGone(s service.Service, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := s.Status(); err != nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// systemdUnit is rendered by kardianos/service's own template engine (v1.3+),
// not text/template: keys are bare ({{Description}}, not {{.Description}}),
// "." is only the current {{range}} element, and the only pipeline functions
// are the ones the library's default systemdScript uses (cmd, cmdEscape). A
// dotted key fails at install time with "unknown template key".
const systemdUnit = `[Unit]
Description={{Description}}
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={{Path | cmdEscape}}{{range Arguments}} {{. | cmd}}{{end}}
{{if WorkingDirectory}}WorkingDirectory={{WorkingDirectory | cmdEscape}}
{{end}}Restart=always
RestartSec=5
KillMode=process
LimitNOFILE=65536
{{range EnvVars}}{{.}}
{{end}}
[Install]
WantedBy=multi-user.target
`
