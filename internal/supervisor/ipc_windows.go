//go:build windows

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// DefaultPipeName is the well-known Windows named pipe for supervisor-worker IPC.
	DefaultPipeName = `\\.\pipe\homelab-rmm-supervisor`

	// DefaultSDDL restricts pipe access strictly to SYSTEM (SY) and Builtin Administrators (BA).
	// D: Discretionary ACL
	// P: SE_DACL_PROTECTED (prevents inheritance from parent container)
	// (A;;GA;;;SY): Allow Generic All to Local SYSTEM
	// (A;;GA;;;BA): Allow Generic All to Builtin Administrators
	DefaultSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

	// pipeBufferSize is the default in/out buffer allocated for named pipe instances (64 KB).
	pipeBufferSize = 65536
)

// pipeAddr represents a Windows Named Pipe address, implementing net.Addr.
type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

// pipeConn represents an active named pipe connection, implementing net.Conn.
// Because the underlying Windows file handle is opened with FILE_FLAG_OVERLAPPED,
// *os.File integrates with Go's internal runtime poller (IOCP), providing native
// support for Read, Write, and deadline timers (SetDeadline, SetReadDeadline, SetWriteDeadline).
type pipeConn struct {
	*os.File
	localAddr  pipeAddr
	remoteAddr pipeAddr
}

var _ net.Conn = (*pipeConn)(nil)

func (c *pipeConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *pipeConn) RemoteAddr() net.Addr { return c.remoteAddr }

// ClientPID returns the process ID of the client connected to this pipe instance.
func (c *pipeConn) ClientPID() (uint32, error) {
	var pid uint32
	err := windows.GetNamedPipeClientProcessId(windows.Handle(c.File.Fd()), &pid)
	if err != nil {
		return 0, fmt.Errorf("get named pipe client pid: %w", err)
	}
	return pid, nil
}

// ServerPID returns the process ID of the server hosting this pipe instance.
func (c *pipeConn) ServerPID() (uint32, error) {
	var pid uint32
	err := windows.GetNamedPipeServerProcessId(windows.Handle(c.File.Fd()), &pid)
	if err != nil {
		return 0, fmt.Errorf("get named pipe server pid: %w", err)
	}
	return pid, nil
}

// pipeListener implements net.Listener for Windows Named Pipes.
type pipeListener struct {
	name       string
	sddl       string
	sa         *windows.SecurityAttributes
	closeEvent windows.Handle

	mu            sync.Mutex
	acceptMu      sync.Mutex
	closed        bool
	pendingHandle windows.Handle
}

var _ net.Listener = (*pipeListener)(nil)

// normalizePipePath ensures the pipe name has the required \\.\pipe\ prefix.
func normalizePipePath(name string) string {
	if strings.HasPrefix(name, `\\.\pipe\`) {
		return name
	}
	return `\\.\pipe\` + strings.TrimPrefix(name, `\`)
}

// CurrentUserSDDL returns an SDDL string granting full access to SYSTEM,
// Administrators, and the current process's user account.
// This is used for unit and integration testing under non-elevated user accounts.
func CurrentUserSDDL() (string, error) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("get current token user: %w", err)
	}
	userSID := tu.User.Sid.String()
	return fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%s)", userSID), nil
}

// ListenPipe creates a named pipe listener with the specified name and SDDL permissions.
// If sddl is empty, DefaultSDDL is enforced.
func ListenPipe(name string, sddl string) (net.Listener, error) {
	name = normalizePipePath(name)
	if sddl == "" {
		sddl = DefaultSDDL
	}

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("invalid SDDL %q: %w", sddl, err)
	}

	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}

	closeEv, err := windows.CreateEvent(nil, 1, 0, nil) // manual-reset event, initially false
	if err != nil {
		return nil, fmt.Errorf("create close event: %w", err)
	}

	l := &pipeListener{
		name:       name,
		sddl:       sddl,
		sa:         sa,
		closeEvent: closeEv,
	}

	// Create first pipe instance with FILE_FLAG_FIRST_PIPE_INSTANCE to guarantee exclusivity
	h, err := l.createInstance(true)
	if err != nil {
		windows.CloseHandle(closeEv)
		return nil, fmt.Errorf("create first pipe instance for %s: %w", name, err)
	}
	l.pendingHandle = h

	return l, nil
}

func (l *pipeListener) createInstance(first bool) (windows.Handle, error) {
	n, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	h, err := windows.CreateNamedPipe(
		n,
		flags,
		mode,
		windows.PIPE_UNLIMITED_INSTANCES,
		pipeBufferSize,
		pipeBufferSize,
		0,
		l.sa,
	)
	if err != nil {
		return 0, err
	}
	return h, nil
}

func (l *pipeListener) Accept() (net.Conn, error) {
	l.acceptMu.Lock()
	defer l.acceptMu.Unlock()

	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, net.ErrClosed
		}
		h := l.pendingHandle
		l.mu.Unlock()

		ev, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			return nil, fmt.Errorf("create connect event: %w", err)
		}

		ov := &windows.Overlapped{HEvent: ev}
		err = windows.ConnectNamedPipe(h, ov)

		var connected bool
		switch {
		case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
			connected = true
			windows.CloseHandle(ev)
		case errors.Is(err, windows.ERROR_IO_PENDING):
			waitHandles := []windows.Handle{ev, l.closeEvent}
			waitRes, waitErr := windows.WaitForMultipleObjects(waitHandles, false, windows.INFINITE)
			if waitErr != nil {
				windows.CloseHandle(ev)
				return nil, fmt.Errorf("wait for named pipe connect: %w", waitErr)
			}
			if waitRes == windows.WAIT_OBJECT_0+1 {
				// closeEvent signaled via listener.Close()
				windows.CancelIoEx(h, ov)
				windows.CloseHandle(ev)
				return nil, net.ErrClosed
			}
			// ev signaled (waitRes == windows.WAIT_OBJECT_0)
			var n uint32
			resErr := windows.GetOverlappedResult(h, ov, &n, true)
			windows.CloseHandle(ev)
			if resErr != nil {
				// Client aborted before connection was established: recycle handle and retry
				if errors.Is(resErr, windows.ERROR_BROKEN_PIPE) ||
					errors.Is(resErr, windows.ERROR_PIPE_NOT_CONNECTED) ||
					errors.Is(resErr, windows.ERROR_NO_DATA) {
					windows.CloseHandle(h)
					nextH, createErr := l.createInstance(false)
					if createErr != nil {
						return nil, createErr
					}
					l.mu.Lock()
					l.pendingHandle = nextH
					l.mu.Unlock()
					continue
				}
				return nil, fmt.Errorf("get overlapped result: %w", resErr)
			}
			connected = true
		case errors.Is(err, windows.ERROR_NO_DATA):
			windows.CloseHandle(ev)
			// Client connected and closed already: recycle handle and retry
			windows.CloseHandle(h)
			nextH, createErr := l.createInstance(false)
			if createErr != nil {
				return nil, createErr
			}
			l.mu.Lock()
			l.pendingHandle = nextH
			l.mu.Unlock()
			continue
		default:
			windows.CloseHandle(ev)
			return nil, fmt.Errorf("connect named pipe: %w", err)
		}

		if connected {
			// Connection established. Prepare next instance for subsequent Accept calls.
			nextH, createErr := l.createInstance(false)
			if createErr != nil {
				windows.CloseHandle(h)
				return nil, fmt.Errorf("create next pipe instance: %w", createErr)
			}
			l.mu.Lock()
			l.pendingHandle = nextH
			l.mu.Unlock()

			f := os.NewFile(uintptr(h), l.name)
			return &pipeConn{
				File:       f,
				localAddr:  pipeAddr(l.name),
				remoteAddr: pipeAddr(l.name),
			}, nil
		}
	}
}

func (l *pipeListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	windows.SetEvent(l.closeEvent)
	l.mu.Unlock()

	// Acquire acceptMu to ensure any pending Accept() exits
	l.acceptMu.Lock()
	defer l.acceptMu.Unlock()

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pendingHandle != 0 && l.pendingHandle != windows.InvalidHandle {
		windows.CloseHandle(l.pendingHandle)
		l.pendingHandle = windows.InvalidHandle
	}
	if l.closeEvent != 0 && l.closeEvent != windows.InvalidHandle {
		windows.CloseHandle(l.closeEvent)
		l.closeEvent = windows.InvalidHandle
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return pipeAddr(l.name)
}

// DialPipe dials the Windows named pipe with a timeout.
func DialPipe(name string, timeout time.Duration) (net.Conn, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return DialPipeContext(ctx, name)
}

// DialPipeContext dials the Windows named pipe respecting the provided Context.
func DialPipeContext(ctx context.Context, name string) (net.Conn, error) {
	name = normalizePipePath(name)
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("invalid pipe name %q: %w", name, err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("dial pipe %s: %w", name, ctx.Err())
		default:
		}

		h, err := windows.CreateFile(
			n,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION,
			0,
		)
		if err == nil {
			f := os.NewFile(uintptr(h), name)
			return &pipeConn{
				File:       f,
				localAddr:  pipeAddr(name),
				remoteAddr: pipeAddr(name),
			}, nil
		}

		// Kernel SDDL rejection: unprivileged caller or denied by DACL
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, fmt.Errorf("dial pipe %s: %w (%w)", name, os.ErrPermission, err)
		}

		// Pipe not created yet (ERROR_FILE_NOT_FOUND) or all instances busy (ERROR_PIPE_BUSY)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
			if _, hasDeadline := ctx.Deadline(); !hasDeadline {
				return nil, fmt.Errorf("dial pipe %s: %w", name, err)
			}
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("dial pipe %s: %w", name, ctx.Err())
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}

		// Any other unexpected Win32 error
		return nil, fmt.Errorf("dial pipe %s: %w", name, err)
	}
}

// ClientPID extracts the client process ID from a net.Conn if it wraps a Windows named pipe.
func ClientPID(conn net.Conn) (uint32, error) {
	type pidGetter interface {
		ClientPID() (uint32, error)
	}
	if getter, ok := conn.(pidGetter); ok {
		return getter.ClientPID()
	}
	return 0, errors.New("connection is not a Windows named pipe connection")
}

// ServerPID extracts the server process ID from a net.Conn if it wraps a Windows named pipe.
func ServerPID(conn net.Conn) (uint32, error) {
	type pidGetter interface {
		ServerPID() (uint32, error)
	}
	if getter, ok := conn.(pidGetter); ok {
		return getter.ServerPID()
	}
	return 0, errors.New("connection is not a Windows named pipe connection")
}

// GetNamedPipeClientProcessId aliases ClientPID for explicit API parity.
func GetNamedPipeClientProcessId(conn net.Conn) (uint32, error) {
	return ClientPID(conn)
}

// DefaultIPCPath returns the default Windows named pipe path.
func DefaultIPCPath() string {
	return DefaultPipeName
}

// DefaultListener returns a listener on the default Windows named pipe with default SDDL.
func DefaultListener() (net.Listener, error) {
	return ListenPipe(DefaultPipeName, DefaultSDDL)
}

// DefaultDialer connects to the default Windows named pipe with a timeout.
func DefaultDialer(timeout time.Duration) (net.Conn, error) {
	return DialPipe(DefaultPipeName, timeout)
}

// ListenIPC creates a listener on Windows using Named Pipes.
func ListenIPC(path, sddl string) (net.Listener, error) {
	if path == "" {
		path = DefaultPipeName
	}
	return ListenPipe(path, sddl)
}

// DialIPC connects on Windows using Named Pipes.
func DialIPC(path string, timeout time.Duration) (net.Conn, error) {
	if path == "" {
		path = DefaultPipeName
	}
	return DialPipe(path, timeout)
}
