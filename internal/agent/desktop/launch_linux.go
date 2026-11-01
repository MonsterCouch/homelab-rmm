//go:build linux

package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// x11Session is the interactive session the helper should attach to.
type x11Session struct {
	id      string
	user    string
	uid     int
	gid     int
	groups  []uint32
	home    string
	display string
	xauth   string
	class   string // logind session class: "user", "greeter", "lock-screen", ...
	// configured marks a session that came from the operator's desktop_*
	// keys rather than from logind; those values win over whatever the
	// agent's own environment happens to say.
	configured bool

	// Wayland sessions only (see launch_wayland): the compositor socket and
	// the session bus the ScreenCast portal is reached through. display and
	// xauth then describe the optional Xwayland server, not the session.
	wayland string
	dbus    string
}

// greeterClass is logind's class for the display manager's own session (the
// login screen). A greeter session means nobody is logged in yet, which is
// worth telling the operator apart from "the machine has no session at all".
const greeterClass = "greeter"

var (
	// errWayland marks a session the X11 path cannot serve: Wayland is
	// captured through the ScreenCast portal and driven through /dev/uinput
	// (launchWayland, waylandCapturer), never through XGetImage or XTEST.
	errWayland = errors.New("Wayland is served only through the ScreenCast portal and /dev/uinput, not X11")
	// errWaylandGreeter wraps errWayland so callers that special-case
	// Wayland still do, but the operator is told the more useful half:
	// there is no user session to attach to at all.
	errWaylandGreeter = fmt.Errorf("no user is logged in and the display manager's greeter is a Wayland session: %w", errWayland)
)

// launch finds the active X11 session — from the operator's desktop_* keys
// in agent.json when they are set, otherwise with logind — and runs the
// helper as its owner. The agent normally runs as root (systemd), so the
// helper is a child with that user's credentials and the X authority it
// needs; in developer mode (same user, or no logind but a DISPLAY of our
// own) the helper runs inside this process.
func launch(exe string, cfg Config) (string, error) {
	token := cfg.Token
	sess, err := findSession()
	if err != nil {
		if errors.Is(err, errWayland) {
			// A user's Wayland session is served through uinput plus the
			// portal; the display manager's greeter has no user session to
			// attach to, so that case stays an error.
			if !errors.Is(err, errWaylandGreeter) {
				return launchWayland(exe, cfg, err)
			}
			return "", err
		}
		// No usable answer: fall back to our own display when the agent is
		// run from a terminal (development), else tell the operator which
		// two keys would settle it.
		if os.Getenv("XDG_SESSION_TYPE") == "wayland" && uinputSelectorWired {
			slog.Info("desktop: no logind session, serving our own Wayland session", "reason", err)
			serveInProcess(cfg)
			return "running in-process on the agent's own Wayland session", nil
		}
		if d := os.Getenv("DISPLAY"); d != "" && os.Getenv("XDG_SESSION_TYPE") != "wayland" {
			slog.Info("desktop: no logind X11 session, using our own DISPLAY", "display", d, "reason", err)
			serveInProcess(cfg)
			return fmt.Sprintf("running in-process on display %s", d), nil
		}
		slog.Warn("desktop: no graphical session found", "err", err, "config", agentConfigPath())
		return "", fmt.Errorf("cannot find the graphical session (%v); set desktop_display and desktop_user in agent.json (%s)", err, agentConfigPath())
	}

	self := os.Geteuid()
	switch {
	case self == sess.uid:
		os.Setenv("DISPLAY", sess.display)
		if sess.xauth != "" && (sess.configured || os.Getenv("XAUTHORITY") == "") {
			os.Setenv("XAUTHORITY", sess.xauth)
		}
		if sess.configured {
			// The operator named an X display explicitly; a stale
			// XDG_SESSION_TYPE=wayland in the service environment must not
			// veto it (platformInit refuses Wayland).
			os.Setenv("XDG_SESSION_TYPE", "x11")
		}
		serveInProcess(cfg)
		return fmt.Sprintf("running in-process as %s on display %s", sess.user, sess.display), nil
	case self != 0:
		return "", fmt.Errorf("agent runs as uid %d but the X11 session belongs to %s (uid %d); run the agent as root", self, sess.user, sess.uid)
	}

	cmd := exec.Command(exe, helperArgs(cfg)...)
	cmd.Env = helperEnv(sess, token)
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr // the journal keeps helper logs with ours
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Groups is never empty (fillUser seeds it with the primary gid),
		// so setgroups always runs and the helper cannot inherit root's
		// supplementary groups.
		Credential: &syscall.Credential{Uid: uint32(sess.uid), Gid: uint32(sess.gid), Groups: sess.groups},
		Setsid:     true, // its own session: a service restart must not take the helper's terminal semantics with it
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start helper as %s: %w", sess.user, err)
	}
	slog.Info("desktop helper started", "pid", cmd.Process.Pid, "user", sess.user, "display", sess.display, "xauthority", sess.xauth, "class", sess.class)
	go func() {
		// Reap the child; without this every finished helper is a zombie
		// for as long as the agent lives.
		err := cmd.Wait()
		slog.Info("desktop helper exited", "pid", cmd.Process.Pid, "err", err)
	}()
	if sess.class == greeterClass {
		return fmt.Sprintf("no user is logged in; showing the login screen (session %s of %s on display %s)", sess.id, sess.user, sess.display), nil
	}
	return fmt.Sprintf("attached to X11 session %s of %s on display %s", sess.id, sess.user, sess.display), nil
}

// helperEnv is the minimal environment an X client needs; nothing from the
// service's own environment leaks through. The one-time bridge token rides
// here rather than on the command line: /proc/<pid>/cmdline is readable by
// every local account, /proc/<pid>/environ only by the helper's own user
// (who owns the session anyway) and root.
func helperEnv(s *x11Session, token string) []string {
	env := []string{
		"DISPLAY=" + s.display,
		"HOME=" + s.home,
		"USER=" + s.user,
		"LOGNAME=" + s.user,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"XDG_RUNTIME_DIR=/run/user/" + strconv.Itoa(s.uid),
		"XDG_SESSION_TYPE=x11",
	}
	if s.xauth != "" {
		env = append(env, "XAUTHORITY="+s.xauth)
	}
	if token != "" {
		env = append(env, TokenEnv+"="+token)
	}
	for _, name := range []string{"RMM_AGENT_DIR", "RMM_DEBUG"} {
		if v := os.Getenv(name); v != "" {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// ---- operator overrides (agent.json) ----

// defaultAgentDir mirrors agent.ConfigDir() on Linux. This package cannot
// import internal/agent — that package imports this one — so the path and
// the handful of keys below are read here directly instead.
const defaultAgentDir = "/etc/homelab-rmm"

// desktopConfig is the optional part of agent.json that says where the
// graphical session is on a host logind cannot describe (no systemd, a
// hand-started X server, a kiosk box, Xvfb). Unknown keys in the file are
// ignored, so the agent's own config struct is unaffected.
type desktopConfig struct {
	Display    string `json:"desktop_display"`
	XAuthority string `json:"desktop_xauthority"`
	User       string `json:"desktop_user"`
}

func (c desktopConfig) set() bool {
	return c.Display != "" || c.XAuthority != "" || c.User != ""
}

func agentConfigPath() string {
	dir := os.Getenv("RMM_AGENT_DIR")
	if dir == "" {
		dir = defaultAgentDir
	}
	return filepath.Join(dir, "agent.json")
}

// readDesktopConfig returns the desktop_* keys, or the zero value when the
// file is missing or unreadable: the override is optional and logind is the
// normal path.
func readDesktopConfig() desktopConfig {
	path := agentConfigPath()
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Debug("desktop: cannot read the agent config", "path", path, "err", err)
		}
		return desktopConfig{}
	}
	var c desktopConfig
	if err := json.Unmarshal(b, &c); err != nil {
		slog.Warn("desktop: the agent config is not valid JSON; ignoring the desktop_* keys", "path", path, "err", err)
		return desktopConfig{}
	}
	return c
}

// findSession picks the session to attach to: the operator's keys first
// (they exist precisely for hosts where logind has no answer), logind
// second.
func findSession() (*x11Session, error) {
	if c := readDesktopConfig(); c.set() {
		s, err := sessionFromConfig(c)
		if err == nil {
			slog.Info("desktop: using the desktop_* keys from the agent config", "user", s.user, "display", s.display, "xauthority", s.xauth)
			return s, nil
		}
		slog.Warn("desktop: the desktop_* keys in the agent config are unusable; falling back to loginctl", "path", agentConfigPath(), "err", err)
	}
	return findX11Session()
}

// sessionFromConfig builds the target session from the operator's keys.
// desktop_user may be a name or a numeric uid; when it is absent the helper
// stays in the agent's own account, which is what a root-started X server
// (Xvfb, a kiosk session) needs.
func sessionFromConfig(c desktopConfig) (*x11Session, error) {
	uid := os.Geteuid()
	if c.User != "" {
		u, err := lookupUser(c.User)
		if err != nil {
			return nil, fmt.Errorf("desktop_user %q: %w", c.User, err)
		}
		n, err := strconv.Atoi(u.Uid)
		if err != nil {
			return nil, fmt.Errorf("desktop_user %q has a non-numeric uid %q", c.User, u.Uid)
		}
		uid = n
	}
	s := &x11Session{id: "config", display: c.Display, xauth: c.XAuthority, class: "user", configured: true}
	if err := fillUser(s, uid); err != nil {
		return nil, err
	}
	if s.display == "" {
		if d, x := scanProcEnviron(uid, ""); d != "" {
			s.display = d
			if s.xauth == "" {
				s.xauth = x
			}
		}
	}
	if s.display == "" {
		s.display = ":0"
	}
	if s.xauth == "" {
		s.xauth = findXauthority(s.home, uid)
	} else if st, err := os.Stat(s.xauth); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("desktop_xauthority %q is not a readable file", s.xauth)
	}
	return s, nil
}

// lookupUser accepts either an account name or a numeric uid.
func lookupUser(spec string) (*user.User, error) {
	if _, err := strconv.Atoi(spec); err == nil {
		if u, err := user.LookupId(spec); err == nil {
			return u, nil
		}
	}
	return user.Lookup(spec)
}

// ---- logind ----

const loginctlTimeout = 5 * time.Second

func runLoginctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), loginctlTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "loginctl", args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("loginctl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("loginctl %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// findX11Session asks logind for the active graphical session. It prefers
// an active X11 session owned by a user; the display manager's greeter is
// taken only when there is nothing else (it shows the login screen, which
// beats showing nothing). An active Wayland session with no X11
// alternative is reported as errWayland — errWaylandGreeter when it is the
// greeter, because then the honest answer is "no user is logged in".
func findX11Session() (*x11Session, error) {
	list, err := runLoginctl("list-sessions", "--no-legend")
	if err != nil {
		return nil, err
	}
	return selectSession(list, showSession)
}

// selectSession is findX11Session's decision made testable: it walks
// loginctl's session list and asks show for each session's properties.
func selectSession(list string, show func(id string) (map[string]string, error)) (*x11Session, error) {
	var (
		best              *x11Session
		sawWayland        bool
		sawWaylandGreeter bool
		sawInactive       bool
	)
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		props, err := show(id)
		if err != nil {
			slog.Debug("desktop: loginctl show-session", "id", id, "err", err)
			continue
		}
		active := props["Active"] == "yes" || props["State"] == "active"
		if !active {
			sawInactive = true
			continue
		}
		switch props["Type"] {
		case "x11":
		case "wayland":
			if props["Class"] == greeterClass {
				sawWaylandGreeter = true
			} else {
				sawWayland = true
			}
			continue
		default:
			continue // tty, unspecified, ...
		}
		s, err := sessionFromProps(id, props)
		if err != nil {
			slog.Debug("desktop: unusable X11 session", "id", id, "err", err)
			continue
		}
		if best == nil || (best.class == greeterClass && s.class != greeterClass) {
			best = s
		}
		if best.class != greeterClass {
			break // a real user session; nothing can beat it
		}
	}
	switch {
	case best != nil:
		return best, nil
	case sawWayland:
		return nil, errWayland
	case sawWaylandGreeter:
		return nil, errWaylandGreeter
	case sawInactive:
		return nil, errors.New("no active graphical session (all sessions are inactive or text-only)")
	default:
		return nil, errors.New("no graphical session found with loginctl")
	}
}

func showSession(id string) (map[string]string, error) {
	out, err := runLoginctl("show-session", id, "-p", "Type", "-p", "Display", "-p", "Name", "-p", "Active", "-p", "State", "-p", "Class", "-p", "User")
	if err != nil {
		return nil, err
	}
	return parseKeyValues(out), nil
}

// parseKeyValues reads loginctl's KEY=VALUE output.
func parseKeyValues(out string) map[string]string {
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	return props
}

func sessionFromProps(id string, props map[string]string) (*x11Session, error) {
	uid, err := strconv.Atoi(props["User"])
	if err != nil {
		return nil, fmt.Errorf("session %s has no numeric User (%q)", id, props["User"])
	}
	s := &x11Session{id: id, uid: uid, user: props["Name"], display: props["Display"], class: props["Class"]}
	if err := fillUser(s, uid); err != nil {
		return nil, fmt.Errorf("session %s: %w", id, err)
	}
	envDisplay, envXauth := scanProcEnviron(uid, s.display)
	if s.display == "" {
		s.display = envDisplay
	}
	if s.display == "" {
		s.display = ":0"
	}
	s.xauth = envXauth
	if s.xauth == "" {
		s.xauth = findXauthority(s.home, uid)
	}
	return s, nil
}

// fillUser resolves the account the helper will run as. The helper is
// spawned with these credentials, so an unresolvable account must be an
// error: the zero gid is root's.
func fillUser(s *x11Session, uid int) error {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return fmt.Errorf("resolve uid %d: %w", uid, err)
	}
	s.uid = uid
	if s.user == "" {
		s.user = u.Username
	}
	s.home = u.HomeDir
	if s.home == "" {
		s.home = "/"
	}
	if s.gid, err = strconv.Atoi(u.Gid); err != nil {
		return fmt.Errorf("user %s has a non-numeric gid %q", s.user, u.Gid)
	}
	s.groups = []uint32{uint32(s.gid)}
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.Atoi(g); err == nil && n != s.gid {
				s.groups = append(s.groups, uint32(n))
			}
		}
	}
	return nil
}

// findXauthority is the last resort when neither the operator nor a running
// client told us where the X cookie lives.
func findXauthority(home string, uid int) string {
	for _, candidate := range []string{
		filepath.Join(home, ".Xauthority"),
		fmt.Sprintf("/run/user/%d/gdm/Xauthority", uid),
	} {
		if candidate == "" {
			continue
		}
		if st, err := os.Stat(candidate); err == nil && st.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

// displayKey strips the screen number from a DISPLAY value so logind's ":0"
// matches a client's ":0.0"; both name the same server.
func displayKey(display string) string {
	if i := strings.LastIndex(display, "."); i > strings.LastIndex(display, ":") {
		return display[:i]
	}
	return display
}

// scanProcEnviron looks through the environment of processes owned by uid
// for the DISPLAY/XAUTHORITY pair the session actually uses. wantDisplay
// narrows the search when logind already told us the display; "" accepts
// any. It returns the display seen and the first XAUTHORITY found for it.
func scanProcEnviron(uid int, wantDisplay string) (display, xauth string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", ""
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != uid {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "environ"))
		if err != nil || len(data) == 0 {
			continue
		}
		var d, x string
		for _, kv := range bytes.Split(data, []byte{0}) {
			k, v, ok := strings.Cut(string(kv), "=")
			if !ok {
				continue
			}
			switch k {
			case "DISPLAY":
				d = v
			case "XAUTHORITY":
				x = v
			}
		}
		if d == "" || (wantDisplay != "" && displayKey(d) != displayKey(wantDisplay)) {
			continue
		}
		if display == "" {
			display = d
		}
		if x != "" {
			return d, x
		}
	}
	return display, ""
}

// ---- Wayland ----

// launchWayland serves an active user Wayland session. Input goes through
// /dev/uinput and capture through the ScreenCast portal (with fallbacks, see
// capture_pipewire_linux.go); both live in the helper, which is told about
// the session through its environment (XDG_SESSION_TYPE=wayland selects them
// in platformInit). cause is the errWayland that sent us here and is
// returned when the Wayland path cannot be used.
func launchWayland(exe string, cfg Config, cause error) (string, error) {
	if !uinputSelectorWired {
		// The injector selection that makes Wayland input work is not
		// connected (see uinputSelectorWired); starting a helper would only
		// give it an XTEST injector that cannot reach Wayland clients.
		return "", cause
	}
	list, err := runLoginctl("list-sessions", "--no-legend")
	if err != nil {
		return "", fmt.Errorf("%w (%v)", cause, err)
	}
	sess, err := selectWaylandSession(list, showSession)
	if err != nil {
		return "", fmt.Errorf("%w (%v)", cause, err)
	}

	self := os.Geteuid()
	switch {
	case self == sess.uid:
		os.Setenv("XDG_SESSION_TYPE", "wayland")
		os.Setenv("WAYLAND_DISPLAY", sess.wayland)
		os.Setenv("DBUS_SESSION_BUS_ADDRESS", sess.dbus)
		if sess.display != "" {
			os.Setenv("DISPLAY", sess.display)
			if sess.xauth != "" {
				os.Setenv("XAUTHORITY", sess.xauth)
			}
		}
		serveInProcess(cfg)
		return fmt.Sprintf("running in-process as %s on Wayland session %s", sess.user, sess.id), nil
	case self != 0:
		return "", fmt.Errorf("agent runs as uid %d but the Wayland session belongs to %s (uid %d); run the agent as root", self, sess.user, sess.uid)
	}

	cmd := exec.Command(exe, helperArgs(cfg)...)
	cmd.Env = helperEnvWayland(sess, cfg.Token)
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Runs as the session's user: the session bus and the portal only
		// answer their owner. /dev/uinput must therefore be reachable by that
		// user (logind's uaccess ACL, or a udev rule); the helper reports a
		// clear error to the viewer when it is not.
		Credential: &syscall.Credential{Uid: uint32(sess.uid), Gid: uint32(sess.gid), Groups: sess.groups},
		Setsid:     true,
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start helper as %s: %w", sess.user, err)
	}
	slog.Info("desktop helper started for Wayland", "pid", cmd.Process.Pid, "user", sess.user, "wayland", sess.wayland, "xwayland", sess.display)
	go func() {
		err := cmd.Wait()
		slog.Info("desktop helper exited", "pid", cmd.Process.Pid, "err", err)
	}()
	return fmt.Sprintf("attached to Wayland session %s of %s (input via uinput)", sess.id, sess.user), nil
}

// helperEnvWayland is helperEnv for a Wayland session: the session type
// switches to wayland, DISPLAY/XAUTHORITY are kept only when an Xwayland
// server exists (they serve as the capture fallback), and the compositor
// socket and session bus are added.
func helperEnvWayland(s *x11Session, token string) []string {
	var env []string
	for _, e := range helperEnv(s, token) {
		switch {
		case e == "XDG_SESSION_TYPE=x11":
			e = "XDG_SESSION_TYPE=wayland"
		case e == "DISPLAY=" || strings.HasPrefix(e, "XAUTHORITY=") && s.display == "":
			continue
		}
		env = append(env, e)
	}
	env = append(env, "WAYLAND_DISPLAY="+s.wayland, "DBUS_SESSION_BUS_ADDRESS="+s.dbus)
	return env
}

// selectWaylandSession picks the first active, non-greeter Wayland session;
// it is selectSession's counterpart for the sessions that one skips.
func selectWaylandSession(list string, show func(id string) (map[string]string, error)) (*x11Session, error) {
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		props, err := show(fields[0])
		if err != nil {
			slog.Debug("desktop: loginctl show-session", "id", fields[0], "err", err)
			continue
		}
		if props["Type"] != "wayland" || props["Class"] == greeterClass {
			continue
		}
		if props["Active"] != "yes" && props["State"] != "active" {
			continue
		}
		s, err := waylandSessionFromProps(fields[0], props)
		if err != nil {
			slog.Debug("desktop: unusable Wayland session", "id", fields[0], "err", err)
			continue
		}
		return s, nil
	}
	return nil, errors.New("no active Wayland user session found with loginctl")
}

func waylandSessionFromProps(id string, props map[string]string) (*x11Session, error) {
	uid, err := strconv.Atoi(props["User"])
	if err != nil {
		return nil, fmt.Errorf("session %s has no numeric User (%q)", id, props["User"])
	}
	s := &x11Session{id: id, uid: uid, user: props["Name"], class: props["Class"]}
	if err := fillUser(s, uid); err != nil {
		return nil, fmt.Errorf("session %s: %w", id, err)
	}
	env := scanSessionEnv(uid)
	applyWaylandEnv(s, env)
	return s, nil
}

// applyWaylandEnv fills the Wayland fields from what the session's own
// processes advertise, with the conventional values as defaults.
func applyWaylandEnv(s *x11Session, env map[string]string) {
	s.wayland = env["WAYLAND_DISPLAY"]
	if s.wayland == "" {
		s.wayland = "wayland-0"
	}
	s.dbus = env["DBUS_SESSION_BUS_ADDRESS"]
	if s.dbus == "" {
		s.dbus = "unix:path=/run/user/" + strconv.Itoa(s.uid) + "/bus"
	}
	s.display = env["DISPLAY"] // Xwayland, if the session has one; no default
	if s.display != "" {
		s.xauth = env["XAUTHORITY"]
		if s.xauth == "" {
			s.xauth = findXauthority(s.home, s.uid)
		}
	}
}

// sessionEnvKeys are the variables a Wayland helper needs from the session.
var sessionEnvKeys = []string{"WAYLAND_DISPLAY", "DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS"}

// parseEnviron extracts the wanted variables from a /proc/<pid>/environ blob.
func parseEnviron(data []byte, want []string) map[string]string {
	out := map[string]string{}
	for _, kv := range bytes.Split(data, []byte{0}) {
		k, v, ok := strings.Cut(string(kv), "=")
		if !ok {
			continue
		}
		for _, w := range want {
			if k == w && v != "" {
				out[k] = v
			}
		}
	}
	return out
}

// scanSessionEnv returns sessionEnvKeys as set in the first process of uid
// that has WAYLAND_DISPLAY (a process inside the graphical session).
func scanSessionEnv(uid int) map[string]string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != uid {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "environ"))
		if err != nil || len(data) == 0 {
			continue
		}
		if env := parseEnviron(data, sessionEnvKeys); env["WAYLAND_DISPLAY"] != "" {
			return env
		}
	}
	return nil
}
