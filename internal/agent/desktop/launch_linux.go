//go:build linux

package desktop

import (
	"bytes"
	"context"
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
}

var errWayland = errors.New("Wayland sessions are not supported yet")

// launch finds the active X11 session with logind and runs the helper as
// its owner. The agent normally runs as root (systemd), so the helper is a
// child with that user's credentials and the X authority it needs; in
// developer mode (same user, or no logind but a DISPLAY of our own) the
// helper runs inside this process.
func launch(exe, serverURL, token, fingerprint string, quality int) (string, error) {
	sess, err := findX11Session()
	if err != nil {
		if errors.Is(err, errWayland) {
			return "", err
		}
		// No usable logind answer: fall back to our own display when the
		// agent is run from a terminal (development), else report why.
		if d := os.Getenv("DISPLAY"); d != "" && os.Getenv("XDG_SESSION_TYPE") != "wayland" {
			slog.Info("desktop: no logind X11 session, using our own DISPLAY", "display", d, "reason", err)
			serveInProcess(serverURL, token, fingerprint, quality)
			return fmt.Sprintf("running in-process on display %s", d), nil
		}
		return "", err
	}

	self := os.Geteuid()
	switch {
	case self == sess.uid:
		if os.Getenv("DISPLAY") != sess.display {
			os.Setenv("DISPLAY", sess.display)
		}
		if sess.xauth != "" && os.Getenv("XAUTHORITY") == "" {
			os.Setenv("XAUTHORITY", sess.xauth)
		}
		serveInProcess(serverURL, token, fingerprint, quality)
		return fmt.Sprintf("running in-process as %s on display %s", sess.user, sess.display), nil
	case self != 0:
		return "", fmt.Errorf("agent runs as uid %d but the X11 session belongs to %s (uid %d); run the agent as root", self, sess.user, sess.uid)
	}

	cmd := exec.Command(exe, helperArgs(serverURL, token, fingerprint, quality)...)
	cmd.Env = helperEnv(sess)
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr // the journal keeps helper logs with ours
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Groups is never empty (sessionFromProps seeds it with the primary
		// gid), so setgroups always runs and the helper cannot inherit
		// root's supplementary groups.
		Credential: &syscall.Credential{Uid: uint32(sess.uid), Gid: uint32(sess.gid), Groups: sess.groups},
		Setsid:     true, // its own session: a service restart must not take the helper's terminal semantics with it
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start helper as %s: %w", sess.user, err)
	}
	slog.Info("desktop helper started", "pid", cmd.Process.Pid, "user", sess.user, "display", sess.display, "xauthority", sess.xauth)
	go func() {
		// Reap the child; without this every finished helper is a zombie
		// for as long as the agent lives.
		err := cmd.Wait()
		slog.Info("desktop helper exited", "pid", cmd.Process.Pid, "err", err)
	}()
	return fmt.Sprintf("attached to X11 session %s of %s on display %s", sess.id, sess.user, sess.display), nil
}

// helperEnv is the minimal environment an X client needs; nothing from the
// service's own environment leaks through.
func helperEnv(s *x11Session) []string {
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
	for _, name := range []string{"RMM_AGENT_DIR", "RMM_DEBUG"} {
		if v := os.Getenv(name); v != "" {
			env = append(env, name+"="+v)
		}
	}
	return env
}

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
// an active X11 session on any seat; an active Wayland session with no X11
// alternative is reported as errWayland so the operator sees why.
func findX11Session() (*x11Session, error) {
	list, err := runLoginctl("list-sessions", "--no-legend")
	if err != nil {
		return nil, err
	}
	var (
		best        *x11Session
		sawWayland  bool
		sawInactive bool
	)
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		props, err := showSession(id)
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
			sawWayland = true
			continue
		default:
			continue // tty, unspecified, ...
		}
		s, err := sessionFromProps(id, props)
		if err != nil {
			slog.Debug("desktop: unusable X11 session", "id", id, "err", err)
			continue
		}
		best = s
		break
	}
	switch {
	case best != nil:
		return best, nil
	case sawWayland:
		return nil, errWayland
	case sawInactive:
		return nil, errors.New("no active graphical session (all sessions are inactive or text-only)")
	default:
		return nil, errors.New("no graphical session found with loginctl")
	}
}

func showSession(id string) (map[string]string, error) {
	out, err := runLoginctl("show-session", id, "-p", "Type", "-p", "Display", "-p", "Name", "-p", "Active", "-p", "State", "-p", "User")
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
	s := &x11Session{id: id, uid: uid, user: props["Name"], display: props["Display"]}
	// The helper is spawned with this user's credentials; an unresolvable
	// account must be an error, because the zero gid is root's.
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, fmt.Errorf("session %s: resolve uid %d: %w", id, uid, err)
	}
	if s.user == "" {
		s.user = u.Username
	}
	s.home = u.HomeDir
	if s.gid, err = strconv.Atoi(u.Gid); err != nil {
		return nil, fmt.Errorf("session %s: user %s has a non-numeric gid %q", id, s.user, u.Gid)
	}
	s.groups = []uint32{uint32(s.gid)}
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.Atoi(g); err == nil && n != s.gid {
				s.groups = append(s.groups, uint32(n))
			}
		}
	}
	if s.home == "" {
		s.home = "/"
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
		for _, candidate := range []string{
			filepath.Join(s.home, ".Xauthority"),
			fmt.Sprintf("/run/user/%d/gdm/Xauthority", uid),
		} {
			if st, err := os.Stat(candidate); err == nil && st.Mode().IsRegular() {
				s.xauth = candidate
				break
			}
		}
	}
	return s, nil
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
