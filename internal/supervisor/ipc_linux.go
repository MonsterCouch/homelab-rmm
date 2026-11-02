//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// DefaultLinuxSocketPath is the standard production path for the supervisor UDS.
	DefaultLinuxSocketPath = "/run/homelab-rmm/supervisor.sock"

	// maxLinuxUDSPathLen is the maximum allowable path length for AF_UNIX on Linux (108 - 1 for null terminator).
	maxLinuxUDSPathLen = 107
)

var (
	// ErrUnauthorizedPeer is returned when an IPC client fails peer credential verification.
	ErrUnauthorizedPeer = errors.New("unauthorized IPC peer UID")
)

// udsListener wraps a net.Listener to ensure the socket file is cleaned up on close
// and enforces peer credential verification on accepted connections.
type udsListener struct {
	net.Listener
	path        string
	closed      atomic.Bool
	enforceUID  bool
	expectedUID uint32
}

// Accept waits for and returns the next connection to the listener.
// Unauthorized connections (UID != 0 and UID != expectedUID) are rejected and closed,
// allowing the accept loop to continue uninterrupted.
func (l *udsListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		if l.enforceUID {
			cred, credErr := GetPeerCredentials(conn)
			if credErr != nil {
				slog.Warn("rejecting UDS connection: could not get peer credentials",
					"path", l.path,
					"err", credErr,
				)
				_ = conn.Close()
				continue
			}

			// Root (UID 0) and the supervisor's process UID are permitted.
			if cred.Uid != 0 && cred.Uid != l.expectedUID {
				slog.Warn("rejecting unauthorized UDS peer",
					"path", l.path,
					"peer_uid", cred.Uid,
					"peer_pid", cred.Pid,
					"expected_uid", l.expectedUID,
				)
				_ = conn.Close()
				continue
			}
		}

		return conn, nil
	}
}

// Close closes the underlying listener and unlinks the socket file from disk.
func (l *udsListener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	err := l.Listener.Close()
	if remErr := os.Remove(l.path); remErr != nil && !os.IsNotExist(remErr) {
		slog.Debug("could not unlink UDS socket on close", "path", l.path, "err", remErr)
	}
	return err
}

// ListenUDS creates a hardened Unix Domain Socket listener at path.
// If path is empty, it uses ResolveSocketPath("").
// It ensures parent directories exist with 0700 permissions, clears stale sockets,
// binds the socket, and applies strict 0600 file mode.
func ListenUDS(path string) (net.Listener, error) {
	return listenUDSInternal(path, true)
}

// ListenUDSUnrestricted creates a UDS listener without peer UID filtering,
// useful for isolated unit testing with simulated unprivileged users.
func ListenUDSUnrestricted(path string) (net.Listener, error) {
	return listenUDSInternal(path, false)
}

func listenUDSInternal(path string, enforceUID bool) (net.Listener, error) {
	path = ResolveSocketPath(path)

	if len(path) > maxLinuxUDSPathLen {
		return nil, fmt.Errorf("UDS path length (%d) exceeds Linux maximum (%d): %q", len(path), maxLinuxUDSPathLen, path)
	}

	// 1. Ensure parent directory exists with 0700 permissions
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create socket directory %s: %w", dir, err)
	}
	cleanDir := filepath.Clean(dir)
	if cleanDir != "/" && cleanDir != "/run" && cleanDir != "/tmp" && cleanDir != "/var/run" {
		_ = os.Chmod(cleanDir, 0700)
	}

	// 2. Stale socket check & cleanup
	if fi, err := os.Lstat(path); err == nil {
		if fi.IsDir() {
			return nil, fmt.Errorf("socket path %s is an existing directory", path)
		}

		// Probe if another process is actively listening on this socket
		conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("cannot listen on %s: another supervisor process is already running and listening", path)
		}

		// If dial failed with ECONNREFUSED or socket is dead, remove the stale file
		if isConnectionRefused(dialErr) || errors.Is(dialErr, syscall.ENOENT) {
			if remErr := os.Remove(path); remErr != nil && !os.IsNotExist(remErr) {
				return nil, fmt.Errorf("failed to remove stale socket %s: %w", path, remErr)
			}
		} else {
			if remErr := os.Remove(path); remErr != nil {
				return nil, fmt.Errorf("socket %s already exists and could not be probed or removed: %w (probe err: %v)", path, remErr, dialErr)
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat socket path %s: %w", path, err)
	}

	// 3. Bind the Unix Domain Socket
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix %s: %w", path, err)
	}

	// 4. Enforce strict 0600 mode on the socket file
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("chmod 0600 on socket %s: %w", path, err)
	}

	return &udsListener{
		Listener:    listener,
		path:        path,
		enforceUID:  enforceUID,
		expectedUID: uint32(os.Geteuid()),
	}, nil
}

// DialUDS connects to a Unix Domain Socket at path with a timeout.
// If path is empty, it uses ResolveSocketPath("").
func DialUDS(path string, timeout time.Duration) (net.Conn, error) {
	path = ResolveSocketPath(path)

	if len(path) > maxLinuxUDSPathLen {
		return nil, fmt.Errorf("UDS path length (%d) exceeds Linux maximum (%d): %q", len(path), maxLinuxUDSPathLen, path)
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("dial unix %s: %w", path, err)
	}

	return conn, nil
}

// ResolveSocketPath resolves custom path, env var override, or default path.
func ResolveSocketPath(customPath string) string {
	if customPath != "" {
		return filepath.Clean(customPath)
	}
	if envPath := os.Getenv("RMM_SUPERVISOR_SOCKET"); envPath != "" {
		return filepath.Clean(envPath)
	}
	return DefaultLinuxSocketPath
}

// GetPeerCredentials extracts the kernel-verified PID, UID, and GID of the connected peer.
func GetPeerCredentials(conn net.Conn) (*unix.Ucred, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("connection does not support SyscallConn")
	}

	rawConn, err := sc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("syscall conn: %w", err)
	}

	var cred *unix.Ucred
	var sockErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return nil, fmt.Errorf("control: %w", ctrlErr)
	}
	if sockErr != nil {
		return nil, fmt.Errorf("getsockopt SO_PEERCRED: %w", sockErr)
	}
	return cred, nil
}

// DefaultIPCPath returns the default Linux socket path.
func DefaultIPCPath() string {
	return DefaultLinuxSocketPath
}

// DefaultListener returns the default IPC listener on Linux.
func DefaultListener() (net.Listener, error) {
	return ListenUDS(DefaultLinuxSocketPath)
}

// DefaultDialer connects to the default supervisor IPC endpoint on Linux.
func DefaultDialer(timeout time.Duration) (net.Conn, error) {
	return DialUDS(DefaultLinuxSocketPath, timeout)
}

// ListenIPC creates a listener on Linux using Unix Domain Sockets.
func ListenIPC(path, _ string) (net.Listener, error) {
	if path == "" {
		path = DefaultLinuxSocketPath
	}
	return ListenUDS(path)
}

// DialIPC connects on Linux using Unix Domain Sockets.
func DialIPC(path string, timeout time.Duration) (net.Conn, error) {
	if path == "" {
		path = DefaultLinuxSocketPath
	}
	return DialUDS(path, timeout)
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, unix.ECONNREFUSED) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) || errors.Is(opErr.Err, unix.ECONNREFUSED) {
			return true
		}
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			if errors.Is(sysErr.Err, syscall.ECONNREFUSED) || errors.Is(sysErr.Err, unix.ECONNREFUSED) {
				return true
			}
		}
	}
	return strings.Contains(err.Error(), "connection refused")
}
