// rmm-server is the Homelab RMM control plane: one executable with the web
// UI, API, agent endpoint and SQLite database inside.
package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
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
  --public-url URL    URL agents use to reach this server (default https://<hostname>:<port>).
                      On first run it seeds the Public URL setting; after that the value
                      saved in Settings wins and this flag is only the fallback.
  --cert FILE --key FILE   use your own certificate instead of the generated one
  --insecure          plain HTTP (only behind a TLS-terminating reverse proxy)
  --trusted-proxies   comma-separated IPs/CIDRs whose X-Forwarded-For header is trusted (the reverse proxy)
  --dev-web DIR       serve the UI from a directory instead of the embedded build

install resolves --data, --cert, --key and --dev-web to absolute paths before storing them
in the service definition, because the service manager runs from a different directory.

Environment: RMM_DATA_DIR, RMM_LISTEN, RMM_PUBLIC_URL, RMM_CERT_FILE, RMM_KEY_FILE, RMM_INSECURE,
             RMM_TRUSTED_PROXIES, RMM_DEV_WEB_DIR, RMM_DEBUG

First run: with no users yet the server prints a one-time SETUP CODE to the console and to
server.log in the data directory. The setup form asks for it unless you open the console from
a browser on the server itself. Lost it? Restart the server before creating a user: a new code
is minted on every start that finds no users.
`, server.Version, server.DefaultDataDir())
}

func newFlagSet(name string) (*flag.FlagSet, *server.Config, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = usage
	cfg := &server.Config{}
	fs.StringVar(&cfg.Listen, "listen", ":8443", "address:port to listen on")
	fs.StringVar(&cfg.DataDir, "data", server.DefaultDataDir(), "data directory (database, certificate, agent binaries)")
	fs.StringVar(&cfg.PublicURL, "public-url", "", "URL agents use to reach this server, e.g. https://rmm.lan:8443")
	fs.StringVar(&cfg.CertFile, "cert", "", "your own TLS certificate (PEM) instead of the generated one")
	fs.StringVar(&cfg.KeyFile, "key", "", "private key for --cert (PEM)")
	fs.BoolVar(&cfg.TailscaleCert, "tailscale-cert", false,
		"get the certificate from `tailscale cert` and keep it renewed (needs HTTPS certificates enabled for the tailnet)")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "serve plain HTTP (only behind a TLS-terminating reverse proxy)")
	fs.StringVar(&cfg.DevWebDir, "dev-web", "", "serve the UI from this directory instead of the embedded build")
	proxies := fs.String("trusted-proxies", "", "comma-separated IPs/CIDRs whose X-Forwarded-For header is trusted")
	return fs, cfg, proxies
}

func parseFlags(args []string) server.Config {
	fs, cfg, proxies := newFlagSet("run")
	fs.Parse(args)
	if *proxies != "" {
		cfg.TrustedProxies = strings.Split(*proxies, ",")
	}
	return cfg.FromEnv()
}

// setupLogging installs the process-wide slog handler over stderr and
// server.log in the data directory. The file is never closed - it lives as
// long as the process.
func setupLogging(cfg server.Config) {
	var f *os.File
	if err := os.MkdirAll(cfg.DataDir, 0o750); err == nil {
		path := filepath.Join(cfg.DataDir, "server.log")
		if st, err := os.Stat(path); err == nil && st.Size() > 20<<20 {
			os.Rename(path, path+".1")
		}
		if opened, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			f = opened
		}
	}
	setupHandler(os.Stderr, f)
}

// setupHandler installs the handler over the sinks the caller opened. stderr
// is a parameter rather than os.Stderr for the same reason as in rmm-agent: a
// process the Windows Service Control Manager started has no standard handles
// at all, so every write to os.Stderr fails for the whole life of the service.
// io.MultiWriter stops at that first failure and never reaches server.log,
// which is the one place docs/OPERATIONS.md tells the operator to read the
// one-time first-run setup code "when it runs as a Windows service, where
// stderr goes nowhere". svc.LogWriter drops the dead sink instead - see its
// comment - and naming both sinks here is what lets a test stand a broken
// stderr up.
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

func spec(args []string) svc.Spec {
	return svc.Spec{
		Name:        serviceName,
		DisplayName: "Homelab RMM Server",
		Description: "Homelab RMM control plane (web console, API and agent endpoint).",
		Args:        append([]string{"run"}, args...),
	}
}

// absPaths rewrites every path in cfg to an absolute one. `install` validates
// the configuration in the operator's current directory and then registers a
// service the manager starts from somewhere else entirely (/ for systemd), so
// a relative --data silently became a second, empty database.
func absPaths(cfg *server.Config) {
	for _, p := range []*string{&cfg.DataDir, &cfg.CertFile, &cfg.KeyFile, &cfg.DevWebDir} {
		if *p == "" {
			continue
		}
		if abs, err := filepath.Abs(*p); err == nil {
			*p = abs
		}
	}
}

// installArgs renders the resolved configuration as the flags the service is
// started with, so what was checked here is what the service runs - including
// values that came from the environment, which the service does not inherit.
func installArgs(cfg server.Config) []string {
	args := []string{"--listen", cfg.Listen, "--data", cfg.DataDir}
	if cfg.PublicURL != "" {
		args = append(args, "--public-url", cfg.PublicURL)
	}
	if cfg.CertFile != "" {
		args = append(args, "--cert", cfg.CertFile, "--key", cfg.KeyFile)
	}
	if cfg.TailscaleCert {
		args = append(args, "--tailscale-cert")
	}
	if cfg.Insecure {
		args = append(args, "--insecure")
	}
	if cfg.DevWebDir != "" {
		args = append(args, "--dev-web", cfg.DevWebDir)
	}
	if len(cfg.TrustedProxies) > 0 {
		args = append(args, "--trusted-proxies", strings.Join(cfg.TrustedProxies, ","))
	}
	return args
}

// validateConfig checks what `install` can check without touching the
// database. It deliberately does NOT open rmm.db: the service being upgraded
// is usually running, and opening its database ran migrations, re-seeded and
// marked every device offline underneath it.
func validateConfig(cfg server.Config) error {
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		return fmt.Errorf("--listen %q: %w", cfg.Listen, err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("data dir %s: %w", cfg.DataDir, err)
	}
	probe := filepath.Join(cfg.DataDir, ".write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("data dir %s is not writable: %w", cfg.DataDir, err)
	}
	f.Close()
	os.Remove(probe)
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return errors.New("--cert and --key must be given together")
	}
	if cfg.CertFile != "" {
		if _, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
			return fmt.Errorf("certificate: %w", err)
		}
	}
	if cfg.DevWebDir != "" {
		if st, err := os.Stat(cfg.DevWebDir); err != nil || !st.IsDir() {
			return fmt.Errorf("--dev-web %s is not a directory", cfg.DevWebDir)
		}
	}
	return nil
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

// runUser is the `user` subcommand. It opens an EXISTING database read-write
// and never creates one: a mistyped --data used to migrate and seed a brand
// new database, print nothing and exit 0, which is indistinguishable from a
// fleet with no users - exactly the situation the lockout instructions send
// people into.
func runUser(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	fs.Usage = usage
	username := fs.String("username", "", "account name")
	role := fs.String("role", "admin", "admin, tech or viewer")
	data := fs.String("data", server.DefaultDataDir(), "data directory holding rmm.db")
	fs.Parse(args[1:])
	cfg := server.Config{DataDir: *data, Listen: ":8443", Insecure: true}.FromEnv()
	db, err := server.OpenDatabase(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer db.Close()
	switch sub {
	case "add":
		if *username == "" {
			fmt.Fprintln(os.Stderr, "--username required")
			return 2
		}
		pw := readPassword("Password: ")
		if _, err := db.CreateUser(*username, pw, *role, ""); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("user created")
	case "passwd":
		if *username == "" {
			fmt.Fprintln(os.Stderr, "--username required")
			return 2
		}
		pw := readPassword("New password: ")
		if err := db.ResetPassword(*username, pw); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("password updated and sessions cleared")
	case "list":
		users, err := db.ListUsers()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if len(users) == 0 {
			fmt.Println("no users; start the server to get a first-run setup code")
			return 0
		}
		for _, u := range users {
			fmt.Printf("%-20s %-7s totp=%v\n", u.Username, u.Role, u.TOTPEnabled)
		}
	default:
		usage()
		return 2
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// No arguments prints usage, the way rmm-agent does and the way
	// docs/OPERATIONS.md says both binaries behave. It used to default to
	// "run", so a bare `rmm-server` started a live server on :8443 against
	// the default data directory - creating it, generating a certificate and
	// minting a setup code.
	if len(args) == 0 {
		usage()
		return 2
	}
	cmd := args[0]
	if strings.HasPrefix(cmd, "-") {
		switch cmd {
		case "-h", "--help", "-help":
			// intercepted before parseFlags, which would otherwise treat it
			// as a run flag and dump the flagset instead of the usage block
			usage()
			return 0
		case "-v", "--version":
			fmt.Println(server.Version)
			return 0
		}
		// any other leading flag is a `run` flag, as before
		cmd = "run"
	} else {
		args = args[1:]
	}
	switch cmd {
	case "help":
		usage()
		return 0
	case "version":
		fmt.Println(server.Version)
	case "run":
		cfg := parseFlags(args)
		setupLogging(cfg)
		s, err := server.New(cfg)
		if err != nil {
			slog.Error("startup failed", "err", err)
			return 1
		}
		if err := svc.Run(spec(args), s.Run); err != nil {
			slog.Error("server stopped", "err", err)
			return 1
		}
	case "install":
		cfg := parseFlags(args)
		absPaths(&cfg)
		if err := validateConfig(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "configuration check failed:", err)
			return 1
		}
		sp := spec(installArgs(cfg))
		if err := svc.Control(sp, "install"); err != nil {
			fmt.Fprintln(os.Stderr, "service install failed:", err)
			return 1
		}
		fmt.Printf("%s; data in %s\n", svc.Describe(sp), cfg.DataDir)
	case "uninstall", "start", "stop", "restart", "status":
		if err := svc.Control(spec(nil), cmd); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	case "user":
		return runUser(args)
	default:
		usage()
		return 2
	}
	return 0
}
