//go:build !linux

package supervisor

import (
	"errors"
	"net"
	"time"
)

const (
	// DefaultLinuxSocketPath stub for non-linux builds.
	DefaultLinuxSocketPath = "/run/homelab-rmm/supervisor.sock"
)

var (
	// ErrUDSNotSupported is returned when attempting to use Unix Domain Sockets on non-Linux systems.
	ErrUDSNotSupported = errors.New("unix domain socket IPC is only supported on Linux")
)

// ListenUDS is a stub on non-Linux platforms.
func ListenUDS(path string) (net.Listener, error) {
	return nil, ErrUDSNotSupported
}

// ListenUDSUnrestricted is a stub on non-Linux platforms.
func ListenUDSUnrestricted(path string) (net.Listener, error) {
	return nil, ErrUDSNotSupported
}

// DialUDS is a stub on non-Linux platforms.
func DialUDS(path string, timeout time.Duration) (net.Conn, error) {
	return nil, ErrUDSNotSupported
}

// ResolveSocketPath is a stub on non-Linux platforms.
func ResolveSocketPath(customPath string) string {
	if customPath != "" {
		return customPath
	}
	return DefaultLinuxSocketPath
}
