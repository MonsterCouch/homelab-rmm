//go:build linux

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// linuxPTY is a shell running under a pseudo-terminal. Reads come from the
// pty master; when the shell exits the kernel reports EIO on the master,
// which is turned into io.EOF so the shell manager ends the session.
type linuxPTY struct {
	f    *os.File
	cmd  *exec.Cmd
	done chan struct{} // closed once Wait returned
	once sync.Once
}

// startPTY resolves the shell binary, prepares a sane environment (service
// environments have no TERM, and often no HOME or PATH) and starts the
// shell as a login shell in a new session with the pty as its controlling
// terminal.
func startPTY(shell string, cols, rows int) (ptySession, error) {
	bin, args, err := resolveShell(shell)
	if err != nil {
		return nil, err
	}
	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 30
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = shellEnv()
	if home := envValue(cmd.Env, "HOME"); home != "" {
		if st, err := os.Stat(home); err == nil && st.IsDir() {
			cmd.Dir = home
		}
	}
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, fmt.Errorf("start %s: %w", bin, err)
	}
	s := &linuxPTY{f: f, cmd: cmd, done: make(chan struct{})}
	go func() {
		cmd.Wait()
		close(s.done)
	}()
	return s, nil
}

// resolveShell maps the protocol's shell names onto binaries. "" and "bash"
// prefer bash and fall back to sh; "powershell" needs pwsh.
func resolveShell(shell string) (bin string, args []string, err error) {
	name := strings.ToLower(strings.TrimSpace(shell))
	switch name {
	case "", "bash", "default":
		for _, c := range []string{"/bin/bash", "/usr/bin/bash", "bash"} {
			if p, err := exec.LookPath(c); err == nil {
				return p, []string{"--login"}, nil
			}
		}
		fallthrough
	case "sh":
		for _, c := range []string{"/bin/sh", "/usr/bin/sh", "sh"} {
			if p, err := exec.LookPath(c); err == nil {
				return p, []string{"-l"}, nil
			}
		}
		return "", nil, errors.New("no /bin/sh on this device")
	case "zsh", "fish":
		if p, err := exec.LookPath(name); err == nil {
			return p, []string{"-l"}, nil
		}
		return "", nil, fmt.Errorf("%s is not installed on this device", name)
	case "powershell", "pwsh":
		if p, err := exec.LookPath("pwsh"); err == nil {
			return p, []string{"-NoLogo"}, nil
		}
		return "", nil, errors.New("pwsh is not installed on this device")
	case "cmd":
		return "", nil, errors.New("cmd.exe is Windows only")
	}
	return "", nil, fmt.Errorf("unsupported shell %q", shell)
}

// shellEnv starts from the service's environment and pins the variables an
// interactive shell needs to behave: a colour terminal, UTF-8, and HOME/PATH
// when the service manager left them out.
func shellEnv() []string {
	env := os.Environ()
	set := func(k, v string) {
		prefix := k + "="
		for i, e := range env {
			if strings.HasPrefix(e, prefix) {
				env[i] = prefix + v
				return
			}
		}
		env = append(env, prefix+v)
	}
	set("TERM", "xterm-256color")
	set("LANG", "C.UTF-8")
	set("COLORTERM", "truecolor")
	if envValue(env, "HOME") == "" {
		home := "/root"
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			home = u.HomeDir
		} else if os.Getuid() != 0 {
			home = "/"
		}
		set("HOME", home)
	}
	if envValue(env, "USER") == "" {
		if u, err := user.Current(); err == nil {
			set("USER", u.Username)
			set("LOGNAME", u.Username)
		}
	}
	if envValue(env, "PATH") == "" {
		set("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	// The shell is a real terminal now; leave nothing that tells tools it
	// is not.
	filtered := env[:0]
	for _, e := range env {
		if strings.HasPrefix(e, "DEBIAN_FRONTEND=") || strings.HasPrefix(e, "LC_ALL=") {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

func envValue(env []string, key string) string {
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, key+"="); ok {
			return v
		}
	}
	return ""
}

func (s *linuxPTY) Read(p []byte) (int, error) {
	n, err := s.f.Read(p)
	if err != nil {
		if errors.Is(err, syscall.EIO) || errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
			return n, io.EOF
		}
		return n, err
	}
	return n, nil
}

func (s *linuxPTY) Write(p []byte) (int, error) {
	n, err := s.f.Write(p)
	if err != nil && (errors.Is(err, syscall.EIO) || errors.Is(err, os.ErrClosed)) {
		return n, io.EOF
	}
	return n, err
}

func (s *linuxPTY) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 || cols > 65535 || rows > 65535 {
		return fmt.Errorf("invalid terminal size %dx%d", cols, rows)
	}
	return pty.Setsize(s.f, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// Close hangs up the session the way a closed terminal would (SIGHUP to the
// shell's process group), escalates to SIGKILL if it lingers, reaps the
// shell and closes the master. It is safe to call more than once.
func (s *linuxPTY) Close() error {
	var err error
	s.once.Do(func() {
		select {
		case <-s.done:
			// Already exited and reaped: the pid may belong to someone else
			// by now, so do not signal it.
		default:
			pid := s.cmd.Process.Pid
			signalGroup(pid, syscall.SIGHUP)
			select {
			case <-s.done:
			case <-time.After(2 * time.Second):
				signalGroup(pid, syscall.SIGKILL)
				select {
				case <-s.done:
				case <-time.After(2 * time.Second):
				}
			}
		}
		err = s.f.Close()
	})
	return err
}

// signalGroup signals the process group led by pid (the shell is a session
// leader thanks to Setsid) and falls back to the process alone.
func signalGroup(pid int, sig syscall.Signal) {
	if err := syscall.Kill(-pid, sig); err != nil {
		syscall.Kill(pid, sig)
	}
}
