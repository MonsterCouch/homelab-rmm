//go:build !windows

package supervisor

import (
	"context"
	"errors"
	"net"
	"time"
)

const (
	// DefaultPipeName is the stub Windows named pipe name for non-Windows platforms.
	DefaultPipeName = `\\.\pipe\homelab-rmm-supervisor`

	// DefaultSDDL is the stub SDDL string for non-Windows platforms.
	DefaultSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
)

var (
	// ErrPipeNotSupported is returned when attempting to use Windows Named Pipes on non-Windows systems.
	ErrPipeNotSupported = errors.New("named pipe IPC is only supported on Windows")
)

// CurrentUserSDDL is a stub on non-Windows platforms.
func CurrentUserSDDL() (string, error) {
	return "", ErrPipeNotSupported
}

// ListenPipe is a stub on non-Windows platforms.
func ListenPipe(name string, sddl string) (net.Listener, error) {
	return nil, ErrPipeNotSupported
}

// DialPipe is a stub on non-Windows platforms.
func DialPipe(name string, timeout time.Duration) (net.Conn, error) {
	return nil, ErrPipeNotSupported
}

// DialPipeContext is a stub on non-Windows platforms.
func DialPipeContext(ctx context.Context, name string) (net.Conn, error) {
	return nil, ErrPipeNotSupported
}

// ClientPID is a stub on non-Windows platforms.
func ClientPID(conn net.Conn) (uint32, error) {
	return 0, ErrPipeNotSupported
}

// ServerPID is a stub on non-Windows platforms.
func ServerPID(conn net.Conn) (uint32, error) {
	return 0, ErrPipeNotSupported
}

// GetNamedPipeClientProcessId is a stub on non-Windows platforms.
func GetNamedPipeClientProcessId(conn net.Conn) (uint32, error) {
	return 0, ErrPipeNotSupported
}
