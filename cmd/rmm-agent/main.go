// rmm-agent is the device-side daemon of Homelab RMM.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/agent"
	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop"
	"github.com/MonsterCouch/homelab-rmm/internal/svc"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Homelab RMM agent %s

Usage:
  rmm-agent run                          run in the foreground (what the service runs)
  rmm-agent install --server URL --token TOKEN [--fingerprint HEX]
                                         save config, register the service and start it
  rmm-agent uninstall | start | stop | restart | status
  rmm-agent desktop-helper --server URL --token TOKEN [--fingerprint HEX] [--quality N]
  rmm-agent version

Config: %s
`, agent.Version, agent.ConfigPath())
}

func spec() svc.Spec {
	return svc.Spec{
		Name:        agent.ServiceName,
		DisplayName: "Homelab RMM Agent",
		Description: "Remote monitoring and management agent for Homelab RMM.",
		Args:        []string{"run"},
	}
}

func setupLogging(toFile bool) {
	var w io.Writer = os.Stderr
	if toFile {
		if err := os.MkdirAll(agent.ConfigDir(), 0o700); err == nil {
			path := filepath.Join(agent.ConfigDir(), "agent.log")
			if st, err := os.Stat(path); err == nil && st.Size() > 10<<20 {
				os.Rename(path, path+".1")
			}
			if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
				w = io.MultiWriter(os.Stderr, f)
			}
		}
	}
	level := slog.LevelInfo
	if os.Getenv("RMM_DEBUG") != "" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})))
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
		setupLogging(true)
		cfg, err := agent.LoadConfig()
		if err != nil {
			slog.Error("cannot load config", "path", agent.ConfigPath(), "err", err)
			os.Exit(1)
		}
		err = svc.Run(spec(), func(ctx context.Context) error { return agent.New(cfg).Run(ctx) })
		if err != nil {
			slog.Error("agent stopped", "err", err)
			os.Exit(1)
		}
	case "install":
		fs := flag.NewFlagSet("install", flag.ExitOnError)
		server := fs.String("server", "", "server URL, e.g. https://rmm.lan:8443")
		token := fs.String("token", "", "enrolment token from the console")
		fp := fs.String("fingerprint", "", "server certificate SHA-256 fingerprint (omit when the certificate is publicly trusted)")
		noService := fs.Bool("no-service", false, "write the config only; do not register a service")
		fs.Parse(os.Args[2:])
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
		if *noService {
			return
		}
		if err := svc.Control(spec(), "install"); err != nil {
			fmt.Fprintln(os.Stderr, "service install failed:", err)
			os.Exit(1)
		}
		fmt.Println("service installed and started")
	case "uninstall", "start", "stop", "restart", "status":
		if err := svc.Control(spec(), cmd); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if cmd == "uninstall" {
			fmt.Println("service removed; config left at", agent.ConfigPath())
		}
	case "desktop-helper":
		setupLogging(true)
		fs := flag.NewFlagSet("desktop-helper", flag.ExitOnError)
		server := fs.String("server", "", "")
		token := fs.String("token", "", "")
		fp := fs.String("fingerprint", "", "")
		quality := fs.Int("quality", 60, "")
		fs.Parse(os.Args[2:])
		if err := desktop.Serve(context.Background(), *server, *token, *fp, *quality); err != nil {
			slog.Error("desktop helper ended", "err", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}
