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
	serverURL, token, fingerprint, quality := cfg.ServerURL, cfg.Token, cfg.Fingerprint, cfg.Quality
	if serverURL == "" || token == "" {
		return errors.New("desktop helper needs --server and --token")
	}
	target := wsURL(serverURL, "/ws/desktop-agent?token="+url.QueryEscape(token))

	// Probe the platform before dialling so a machine without a usable
	// display fails with one clear message, but still tell the viewer
	// about it: an error over the socket beats a 30 s "did not connect".
	// The injector comes first on purpose: on X11 it holds the one
	// persistent connection, and the capture backend's per-call
	// connections must never be the server's last client (an X server
	// regenerates when that disconnects and drops whoever connects
	// meanwhile).
	var (
		cap  capturer
		inj  injector
		perr error
	)
	backstage := modeOrDefault(cfg.Mode) == string(modeBackstage)
	if perr = platformInit(); perr == nil {
		if backstage {
			// An isolated administrative desktop the logged-in user never
			// sees. Its capturer composites the virtual desktop's windows
			// off-screen and its injector posts messages to them, so the
			// physical screen and cursor are never touched.
			cap, inj, perr = newBackstage()
		} else if inj, perr = newInjector(); perr == nil {
			cap = newCapturer()
			if _, perr = cap.monitors(); perr != nil {
				if c, ok := cap.(interface{ Close() error }); ok {
					c.Close()
				}
				inj.close()
				inj = nil
			}
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ws, err := dial(dialCtx, target, fingerprint)
	cancel()
	if err != nil {
		if inj != nil {
			inj.close()
		}
		return err
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
	if c, ok := cap.(interface{ Close() error }); ok {
		defer c.Close()
	}
	hideBanner := showBanner()
	defer hideBanner()
	slog.Info("desktop helper connected", "server", serverURL, "quality", quality, "mode", modeOrDefault(cfg.Mode), "webrtc", cfg.WebRTC)
	s := newSession(ws, cap, inj, quality)
	s.webrtcOffered = cfg.WebRTC
	s.noFollow = backstage
	err = s.run(ctx)
	slog.Info("desktop helper finished", "err", err)
	return err
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
