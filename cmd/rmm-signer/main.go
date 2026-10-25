// rmm-signer signs pending approvals out of band. It fetches the manifest
// bytes from the server, decodes and prints them itself, and signs exactly
// those bytes with the native Windows WebAuthn API, so the operator's decision
// does not rest on a console page the server served (design:
// docs/plans/2026-10-24-phase3d-out-of-band-signer.md).
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/winwebauthn"
)

// Signer is the part of the WebAuthn API the tool needs; tests inject a fake.
type Signer interface {
	GetAssertion(ctx context.Context, o winwebauthn.Options) (*winwebauthn.Assertion, error)
}

// Version is stamped at build time with -X main.Version=..., by the Makefile,
// tools/build.sh and tools/build.ps1 alike. It lives here rather than in
// internal/server or internal/agent because the signer must not link either
// package just to print a string.
var Version = "dev"

// winSigner is the real signer: Windows Hello or a security key.
type winSigner struct{}

func (winSigner) GetAssertion(ctx context.Context, o winwebauthn.Options) (*winwebauthn.Assertion, error) {
	return winwebauthn.GetAssertion(ctx, o)
}

// app carries everything the subcommands touch, so tests run them in process
// against an httptest server with a fake signer and no terminal.
type app struct {
	out, errw    io.Writer
	in           *bufio.Reader
	getenv       func(string) string
	signer       Signer
	client       *http.Client
	sessionFile  string
	now          func() time.Time
	readPassword func(prompt string) (string, error)
	selftest     func() (string, error)
	// needWindows makes sign refuse before it prints anything: the tool still
	// builds elsewhere so list and show work, but nothing can be signed.
	needWindows bool
}

func newApp() *app {
	in := bufio.NewReader(os.Stdin)
	a := &app{
		out: os.Stdout, errw: os.Stderr, in: in,
		getenv: os.Getenv, signer: winSigner{},
		// Redirects are never followed: the session cookie must not travel to
		// a host the operator did not name.
		client: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:         time.Now,
		needWindows: runtime.GOOS != "windows",
		selftest:    realSelftest,
	}
	a.sessionFile, _ = defaultSessionFile()
	a.readPassword = func(prompt string) (string, error) { return readSecret(a.errw, in, prompt) }
	return a
}

const usageText = `rmm-signer signs pending approvals outside the browser.

  rmm-signer login   --server URL [--user NAME]   sign in; the session is kept in a private file
  rmm-signer logout  [--server URL]               end the session and delete that file
  rmm-signer list    [--server URL]               what is waiting for your signature
  rmm-signer show    [--server URL] ID            decode and print one manifest without signing
  rmm-signer sign    [--server URL] ID [--yes]    print it, ask for confirmation, sign, post the assertion
  rmm-signer sign    [--server URL] --all         the same for every entry, one at a time
  rmm-signer selftest                             report the WebAuthn API version; shows no prompt
  rmm-signer version                              print the build version

--server may also come from the RMM_SERVER environment variable; after login it
defaults to the server you signed in to.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := newApp().run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

// run dispatches one command line and returns the process exit code: 0 on
// success, 1 on failure, 2 on a usage mistake.
func (a *app) run(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(a.errw, usageText)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "login":
		err = a.cmdLogin(ctx, rest)
	case "logout":
		err = a.cmdLogout(ctx, rest)
	case "list":
		err = a.cmdList(ctx, rest)
	case "show":
		err = a.cmdShow(ctx, rest)
	case "sign":
		err = a.cmdSign(ctx, rest)
	case "selftest":
		err = a.cmdSelftest(rest)
	case "version", "--version":
		if len(rest) > 0 {
			err = usagef("version takes no arguments.")
		} else {
			fmt.Fprintf(a.out, "rmm-signer %s\n", Version)
		}
	default:
		fmt.Fprintf(a.errw, "rmm-signer: unknown command %q.\n\n%s", cmd, usageText)
		return 2
	}
	var ue *usageError
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &ue):
		fmt.Fprintf(a.errw, "rmm-signer: %s\n", ue.msg)
		return 2
	default:
		fmt.Fprintf(a.errw, "rmm-signer: %v\n", err)
		return 1
	}
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return &usageError{fmt.Sprintf(format, args...)} }

// parseFlags parses flags that may come before or after positional arguments
// (the standard library stops at the first positional) and returns the
// positionals.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usagef("%v", err)
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func (a *app) newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.errw)
	server := fs.String("server", "", "server URL, for example https://rmm.example.com (or set RMM_SERVER)")
	return fs, server
}

func (a *app) cmdSelftest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	fs.SetOutput(a.errw)
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("selftest takes no arguments.")
	}
	s, err := a.selftest()
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, s)
	return nil
}

func realSelftest() (string, error) {
	if runtime.GOOS != "windows" {
		return "", errors.New("selftest needs Windows: the WebAuthn API is part of Windows")
	}
	r, err := winwebauthn.Selftest()
	if err != nil {
		return "", fmt.Errorf("the Windows WebAuthn API did not answer: %w", err)
	}
	pa := "no (Windows Hello is not set up; a security key can still sign)"
	if r.PlatformAuthenticatorFound {
		pa = "yes"
	}
	return fmt.Sprintf("WebAuthn API version: %d\nPlatform authenticator (Windows Hello) available: %s", r.APIVersion, pa), nil
}
