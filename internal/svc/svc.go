// Package svc wraps kardianos/service so both binaries install the same way:
// a Windows service (automatic start, restart on failure) or a systemd unit.
package svc

import (
	"context"
	"fmt"
	"os"
	"runtime"

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
		_ = s.Uninstall() // idempotent reinstall
		if err := s.Install(); err != nil {
			return err
		}
		return s.Start()
	case "uninstall":
		_ = s.Stop()
		return s.Uninstall()
	default:
		return service.Control(s, action)
	}
}

const systemdUnit = `[Unit]
Description={{.Description}}
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={{.Path}}{{range .Arguments}} {{.|cmd}}{{end}}
{{if .WorkingDirectory}}WorkingDirectory={{.WorkingDirectory|cmdEscape}}{{end}}
Restart=always
RestartSec=5
KillMode=process
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`
