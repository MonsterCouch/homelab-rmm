// rmm-server is the Homelab RMM control plane: one executable with the web
// UI, API, agent endpoint and SQLite database inside.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/MonsterCouch/homelab-rmm/internal/server"
	"github.com/MonsterCouch/homelab-rmm/internal/svc"
)

const serviceName = "HomelabRMMServer"

func usage() {
	fmt.Fprintf(os.Stderr, `Homelab RMM server %s

Usage:
  rmm-server run [flags]            start the server in the foreground
  rmm-server install [flags]        register as a system service with these flags and start it
  rmm-server uninstall | start | stop | restart | status
  rmm-server user add --username U [--role admin|tech|viewer]   (prompts for password)
  rmm-server user passwd --username U
  rmm-server user list
  rmm-server version

Flags for run/install:
  --listen ADDR       address to listen on (default :8443)
  --data DIR          data directory (default %s)
  --public-url URL    URL agents use to reach this server (default https://<hostname>:<port>)
  --cert FILE --key FILE   use your own certificate instead of the generated one
  --insecure          plain HTTP (only behind a TLS-terminating reverse proxy)
  --dev-web DIR       serve the UI from a directory instead of the embedded build

Environment: RMM_DATA_DIR, RMM_LISTEN, RMM_PUBLIC_URL, RMM_CERT_FILE, RMM_KEY_FILE, RMM_INSECURE, RMM_DEBUG
`, server.Version, server.DefaultDataDir())
}

func parseFlags(args []string) server.Config {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfg := server.Config{}
	fs.StringVar(&cfg.Listen, "listen", ":8443", "")
	fs.StringVar(&cfg.DataDir, "data", server.DefaultDataDir(), "")
	fs.StringVar(&cfg.PublicURL, "public-url", "", "")
	fs.StringVar(&cfg.CertFile, "cert", "", "")
	fs.StringVar(&cfg.KeyFile, "key", "", "")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "")
	fs.StringVar(&cfg.DevWebDir, "dev-web", "", "")
	fs.Parse(args)
	return cfg.FromEnv()
}

func setupLogging(cfg server.Config) {
	var w io.Writer = os.Stderr
	if err := os.MkdirAll(cfg.DataDir, 0o750); err == nil {
		path := filepath.Join(cfg.DataDir, "server.log")
		if st, err := os.Stat(path); err == nil && st.Size() > 20<<20 {
			os.Rename(path, path+".1")
		}
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			w = io.MultiWriter(os.Stderr, f)
		}
	}
	level := slog.LevelInfo
	if os.Getenv("RMM_DEBUG") != "" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})))
}

func spec(args []string) svc.Spec {
	return svc.Spec{
		Name:        serviceName,
		DisplayName: "Homelab RMM Server",
		Description: "Homelab RMM control plane (web console, API and agent endpoint).",
		Args:        append([]string{"run"}, args...),
	}
}

func readPassword(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(syscall.Stdin)) {
		b, _ := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		return string(b)
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	return strings.TrimSpace(sc.Text())
}

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "version", "-v", "--version":
		fmt.Println(server.Version)
	case "run":
		cfg := parseFlags(args)
		setupLogging(cfg)
		s, err := server.New(cfg)
		if err != nil {
			slog.Error("startup failed", "err", err)
			os.Exit(1)
		}
		if err := svc.Run(spec(args), s.Run); err != nil {
			slog.Error("server stopped", "err", err)
			os.Exit(1)
		}
	case "install":
		cfg := parseFlags(args)
		// validate once so a bad flag fails here, not silently in the service
		if _, err := server.New(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "configuration check failed:", err)
			os.Exit(1)
		}
		if err := svc.Control(spec(args), "install"); err != nil {
			fmt.Fprintln(os.Stderr, "service install failed:", err)
			os.Exit(1)
		}
		fmt.Printf("service installed and started; data in %s\n", cfg.DataDir)
	case "uninstall", "start", "stop", "restart", "status":
		if err := svc.Control(spec(nil), cmd); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "user":
		if len(args) == 0 {
			usage()
			os.Exit(2)
		}
		sub := args[0]
		fs := flag.NewFlagSet("user", flag.ExitOnError)
		username := fs.String("username", "", "")
		role := fs.String("role", "admin", "")
		data := fs.String("data", server.DefaultDataDir(), "")
		fs.Parse(args[1:])
		cfg := server.Config{DataDir: *data, Listen: ":8443", Insecure: true}.FromEnv()
		s, err := server.New(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		db := s.DB()
		switch sub {
		case "add":
			if *username == "" {
				fmt.Fprintln(os.Stderr, "--username required")
				os.Exit(2)
			}
			pw := readPassword("Password: ")
			if _, err := db.CreateUser(*username, pw, *role, ""); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("user created")
		case "passwd":
			if *username == "" {
				fmt.Fprintln(os.Stderr, "--username required")
				os.Exit(2)
			}
			pw := readPassword("New password: ")
			if err := db.ResetPassword(*username, pw); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("password updated and sessions cleared")
		case "list":
			users, _ := db.ListUsers()
			for _, u := range users {
				fmt.Printf("%-20s %-7s totp=%v\n", u.Username, u.Role, u.TOTPEnabled)
			}
		default:
			usage()
			os.Exit(2)
		}
	default:
		usage()
		os.Exit(2)
	}
	_ = context.Background
}
