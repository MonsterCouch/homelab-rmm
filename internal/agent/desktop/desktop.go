// Package desktop implements the remote-desktop helper: screen capture with
// dirty-tile JPEG streaming, keyboard/mouse injection, and the logic that
// launches the helper inside the interactive session (Windows session 0
// isolation, Linux X11 display ownership).
//
// Wire protocol: see docs/DESKTOP-PROTOCOL.md.
package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Config carries everything the helper needs for one session. It is built by
// the server's desktop.start RPC on the agent side and passed to Launch; the
// launcher forwards the non-secret fields to the helper on its command line
// (helperArgs) and the token in the environment (TokenEnv).
type Config struct {
	ServerURL   string
	Token       string
	Fingerprint string
	Quality     int
	// Mode is "console" (the interactive user's screen, the default) or
	// "backstage" (an isolated administrative desktop the user never sees).
	Mode string
	// WebRTC is set when the viewer offered a WebRTC transport: the helper
	// negotiates a peer connection for low-latency video and input while the
	// JPEG tile stream stays up as the fast-start and firewall fallback.
	WebRTC bool
}

// modeOrDefault maps an empty or unknown mode to console.
func modeOrDefault(mode string) string {
	if mode == string(modeBackstage) {
		return string(modeBackstage)
	}
	return string(modeConsole)
}

// Desktop modes, kept as a package-local type so this package need not import
// internal/protocol (the agent translates protocol.DesktopMode to these).
type desktopMode string

const (
	modeConsole   desktopMode = "console"
	modeBackstage desktopMode = "backstage"
)

// Serve runs inside the helper process (or in-process when the agent already
// runs in the user's session). It connects to cfg.ServerURL's
// /ws/desktop-agent?token=<token> endpoint, pinning the certificate by
// fingerprint, and streams until the socket closes or ctx ends.
func Serve(ctx context.Context, cfg Config) error {
	return serve(ctx, cfg, realServeDeps())
}

// serveDeps are the platform pieces serve uses, so a test can drive the
// ordering (dial, then capturer set-up, then the session) with fakes.
type serveDeps struct {
	platformInit func() error
	newInjector  func() (injector, error)
	newCapturer  func() capturer
	newBackstage func() (capturer, injector, error)
	dial         func(ctx context.Context, url, fingerprint string) (*websocket.Conn, error)
	// setupNotice returns the sentence for the viewer when newCapturer's
	// monitors() may block on the person at the machine (a Wayland screen
	// share prompt), or "" when set-up is not expected to wait.
	setupNotice func() string
	showBanner  func() func()
}

func realServeDeps() serveDeps {
	return serveDeps{
		platformInit: platformInit,
		newInjector:  newInjector,
		newCapturer:  newCapturer,
		newBackstage: newBackstage,
		dial:         dial,
		setupNotice:  capturerSetupNotice,
		showBanner:   showBanner,
	}
}

func serve(ctx context.Context, cfg Config, d serveDeps) error {
	serverURL, token, fingerprint, quality := cfg.ServerURL, cfg.Token, cfg.Fingerprint, cfg.Quality
	if serverURL == "" || token == "" {
		return errors.New("desktop helper needs --server and --token")
	}
	target := wsURL(serverURL, "/ws/desktop-agent?token="+url.QueryEscape(token))

	// Dial the bridge first, on every platform, then probe the platform.
	// The server waits only 30 s (45 s while the agent RPC is outstanding)
	// for the helper's socket and the one-time token is spent by the
	// attempt; capturer set-up can take far longer than that, because on
	// Wayland the first ScreenCast portal request waits for the person at
	// the machine to accept a "Share Screen" prompt (up to 30 s + 2 min).
	// Probing first made the server give up while the prompt was open and
	// the helper then failed with HTTP 401. The property probing first
	// had, that a machine without a usable display fails with one clear
	// message instead of a mystery timeout, is kept: a probe failure is
	// written to the socket as {"t":"error"} and the console shows it.
	// The X11 order inside the probe is unchanged: the injector comes
	// first on purpose, because it holds the one persistent X connection
	// and the capture backend's per-call connections must never be the
	// server's last client (an X server regenerates when that disconnects
	// and drops whoever connects meanwhile). Dialling earlier opens no X
	// connection, so that rule is not affected.
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ws, err := d.dial(dialCtx, target, fingerprint)
	cancel()
	if err != nil {
		return err
	}

	var (
		cap  capturer
		inj  injector
		perr error
	)
	backstage := modeOrDefault(cfg.Mode) == string(modeBackstage)
	if perr = d.platformInit(); perr == nil {
		if backstage {
			// An isolated administrative desktop the logged-in user never
			// sees. Its capturer composites the virtual desktop's windows
			// off-screen and its injector posts messages to them, so the
			// physical screen and cursor are never touched.
			cap, inj, perr = d.newBackstage()
		} else if inj, perr = d.newInjector(); perr == nil {
			cap = d.newCapturer()
			perr = probeCapturer(ctx, ws, cap, d.setupNotice)
			if perr != nil {
				closeCapturer(cap)
				inj.close()
				inj = nil
			}
		}
	}
	if perr != nil {
		slog.Error("desktop helper cannot start", "err", perr)
		msg, _ := json.Marshal(map[string]string{"t": "error", "message": perr.Error()})
		ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		ws.WriteMessage(websocket.TextMessage, msg)
		ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
		ws.Close()
		return perr
	}
	defer inj.close()
	defer closeCapturer(cap)
	hideBanner := d.showBanner()
	defer hideBanner()
	slog.Info("desktop helper connected", "server", serverURL, "quality", quality, "mode", modeOrDefault(cfg.Mode), "webrtc", cfg.WebRTC)
	s := newSession(ws, cap, inj, quality)
	s.webrtcOffered = cfg.WebRTC
	s.noFollow = backstage
	err = s.run(ctx)
	slog.Info("desktop helper finished", "err", err)
	return err
}

func closeCapturer(c capturer) {
	if cl, ok := c.(interface{ Close() error }); ok {
		cl.Close()
	}
}

// probeCapturer enumerates the monitors once, which is where a capturer does
// its set-up (and, on Wayland, waits for the screen-share prompt). When
// notice says set-up may wait for a person, the viewer is told first with a
// "note" that carries "pending":true; a console that knows the flag shows it
// only until the first frame, and one that does not shows it as an ordinary
// note. When set-up succeeds a pending note with an empty message withdraws
// it. Cancelling ctx closes the capturer, which ends a wait in progress.
func probeCapturer(ctx context.Context, ws *websocket.Conn, cap capturer, notice func() string) error {
	pending := ""
	if notice != nil {
		pending = notice()
	}
	if pending != "" {
		writePendingNote(ws, pending)
	}
	res := make(chan error, 1)
	go func() {
		_, err := cap.monitors()
		res <- err
	}()
	var err error
	select {
	case err = <-res:
	case <-ctx.Done():
		closeCapturer(cap)
		err = <-res
		if err == nil {
			err = ctx.Err()
		}
	}
	if err == nil && pending != "" {
		writePendingNote(ws, "")
	}
	return err
}

// writePendingNote sends {"t":"note","message":msg,"pending":true}. Nothing
// else writes to the socket until the session starts, so no lock is needed.
func writePendingNote(ws *websocket.Conn, msg string) {
	b, _ := json.Marshal(map[string]any{"t": "note", "message": msg, "pending": true})
	ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	ws.WriteMessage(websocket.TextMessage, b)
}

// Launch starts the helper for the interactive session from the agent
// service. exe is the agent binary (the helper is `<exe> desktop-helper ...`).
// It returns a note for the operator ("attached to console session of user
// X", "no user logged in, showing the logon screen") and an error when no
// interactive session can be reached.
func Launch(exe string, cfg Config) (note string, err error) {
	if exe == "" {
		return "", errors.New("agent executable path is empty")
	}
	if cfg.ServerURL == "" || cfg.Token == "" {
		return "", errors.New("desktop start needs a server URL and a token")
	}
	if cfg.Quality < minQuality || cfg.Quality > maxQuality {
		cfg.Quality = 60
	}
	cfg.Mode = modeOrDefault(cfg.Mode)
	return launch(exe, cfg)
}

// TokenEnv carries the one-time bridge token to the helper. It is never a
// command-line argument: /proc/<pid>/cmdline is world-readable on Linux and
// Process Explorer shows the command line of any process on Windows, so an
// argument would hand the token (good for one desktop session) to every
// local user. `--token` still works for a developer running the helper by
// hand; the launchers use this.
const TokenEnv = "RMM_DESKTOP_TOKEN"

// envWithToken returns entries with any inherited TokenEnv variable
// removed and ours appended, so the helper always reads the token this
// launch minted. Windows environment names are case-insensitive, hence the
// folded comparison; it lives here (rather than in the Windows launcher)
// because it is plain string work worth testing on any platform.
func envWithToken(entries []string, token string) []string {
	out := make([]string, 0, len(entries)+1)
	prefix := TokenEnv + "="
	for _, e := range entries {
		if len(e) >= len(prefix) && strings.EqualFold(e[:len(prefix)], prefix) {
			continue
		}
		out = append(out, e)
	}
	out = append(out, prefix+token)
	// Windows documents an environment block as sorted case-insensitively,
	// and CreateEnvironmentBlock hands one over that way; re-sort rather
	// than appending out of order behind its back.
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToUpper(out[i]) < strings.ToUpper(out[j])
	})
	return out
}

// helperArgs is the command line every launcher builds; keeping it in one
// place means main.go's flag set and the launchers cannot drift apart. The
// token is passed in the environment (TokenEnv), not here.
func helperArgs(cfg Config) []string {
	args := []string{"desktop-helper", "--server", cfg.ServerURL, "--fingerprint", cfg.Fingerprint, "--quality", fmt.Sprint(cfg.Quality)}
	if m := modeOrDefault(cfg.Mode); m != string(modeConsole) {
		args = append(args, "--mode", m)
	}
	if cfg.WebRTC {
		args = append(args, "--webrtc")
	}
	return args
}

// serveInProcess is the developer-mode path: the agent itself has a
// display, so the helper runs as a goroutine of this process.
func serveInProcess(cfg Config) {
	go func() {
		if err := Serve(context.Background(), cfg); err != nil {
			slog.Error("in-process desktop helper ended", "err", err)
		}
	}()
}
