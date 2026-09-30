//go:build windows

package portalpipe

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SYSTEM and Administrators own the pipe; signed-in (interactive) users may
// read and write it; network logons are denied outright, on top of
// PIPE_REJECT_REMOTE_CLIENTS, since a named pipe is otherwise reachable over
// file sharing.
const pipeSDDL = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

const (
	passTimeout = 15 * time.Second
	maxClients  = 8
)

// clientDeadline bounds one caller from connect to hang-up, so a process that
// connects and goes quiet cannot hold a slot for good. A variable for tests.
var clientDeadline = 30 * time.Second

// Serve answers pass requests on the named pipe until ctx ends. It returns at
// once; the work runs in the background.
func Serve(ctx context.Context, name string, get PassFunc) {
	go func() {
		first := true
		slots := make(chan struct{}, maxClients)
		for ctx.Err() == nil {
			h, err := createPipe(name, first)
			if err != nil {
				slog.Warn("portal pipe unavailable", "pipe", name, "err", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Minute):
				}
				continue
			}
			first = false
			if err := connect(ctx, h); err != nil {
				windows.CloseHandle(h)
				continue
			}
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				windows.CloseHandle(h)
				return
			}
			go func() {
				defer func() { <-slots }()
				serveClient(ctx, name, h, get)
			}()
		}
	}()
}

func createPipe(name string, first bool) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return 0, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		// Refuse to start while another process owns the name, rather than
		// sharing tray apps with a squatter. Later instances inherit the
		// first one's security, which lets nobody else add instances.
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	return windows.CreateNamedPipe(n, flags, mode, windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, sa)
}

// connect waits for a caller on h, or for ctx to end.
func connect(ctx context.Context, h windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	ov := &windows.Overlapped{HEvent: ev} // on the heap: the kernel holds it while pending
	err = windows.ConnectNamedPipe(h, ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case !errors.Is(err, windows.ERROR_IO_PENDING):
		return err
	}
	stop := context.AfterFunc(ctx, func() { windows.CancelIoEx(h, ov) })
	defer stop()
	var n uint32
	return windows.GetOverlappedResult(h, ov, &n, true)
}

func serveClient(ctx context.Context, name string, h windows.Handle, get PassFunc) {
	// The handle is overlapped, so os.File gives it deadlines.
	f := os.NewFile(uintptr(h), name)
	defer f.Close()
	f.SetDeadline(time.Now().Add(clientDeadline))
	send := func(r reply) {
		b, _ := json.Marshal(r)
		f.Write(append(b, '\n'))
		// Closing the pipe throws away anything the caller has not read yet,
		// so wait for them to hang up first (or for the deadline).
		io.Copy(io.Discard, io.LimitReader(f, 1024))
	}

	line, err := bufio.NewReader(io.LimitReader(f, 64)).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "pass" {
		send(reply{Error: "unknown request"})
		return
	}
	acct, err := clientAccount(h)
	if err != nil {
		slog.Warn("portal pipe: cannot identify caller", "err", err)
		send(reply{Error: "cannot identify the signed-in user"})
		return
	}
	pctx, cancel := context.WithTimeout(ctx, passTimeout)
	defer cancel()
	pass, err := get(pctx, acct)
	if err != nil {
		slog.Warn("portal pass request failed", "user", acct.User, "err", err)
		send(reply{Error: "the server could not be reached"})
		return
	}
	send(reply{Pass: pass})
}

// clientAccount is the Windows account running the process on the other end
// of the pipe.
func clientAccount(h windows.Handle) (Account, error) {
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		return Account{}, fmt.Errorf("client process: %w", err)
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Account{}, fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return Account{}, fmt.Errorf("process token: %w", err)
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return Account{}, fmt.Errorf("token user: %w", err)
	}
	account, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return Account{}, fmt.Errorf("lookup account: %w", err)
	}
	// Service accounts are not people and get no portal.
	if strings.EqualFold(domain, "NT AUTHORITY") || strings.EqualFold(domain, "NT SERVICE") {
		return Account{}, fmt.Errorf("service account %s\\%s", domain, account)
	}
	// A local account's "domain" is this computer's short (NetBIOS) name.
	if host, err := windows.ComputerName(); err == nil && strings.EqualFold(domain, host) {
		return Account{User: account, Local: true}, nil
	}
	return Account{User: domain + `\` + account}, nil
}

// Ask requests a portal pass from the agent listening on name.
func Ask(name string) (string, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var h windows.Handle
	for attempt := 0; ; attempt++ {
		// SECURITY_IDENTIFICATION: whoever owns the pipe may learn who we
		// are, but cannot act as us.
		h, err = windows.CreateFile(n, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			break
		}
		if errors.Is(err, windows.ERROR_PIPE_BUSY) && attempt < 10 {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return "", errors.New("the Homelab agent service is not running")
		}
		return "", err
	}
	f := os.NewFile(uintptr(h), name)
	defer f.Close()
	f.SetDeadline(time.Now().Add(clientDeadline))
	if _, err := f.Write([]byte("pass\n")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(io.LimitReader(f, 64<<10)).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("no answer from the agent: %w", err)
	}
	var r reply
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		return "", fmt.Errorf("bad answer from the agent: %w", err)
	}
	if r.Error != "" {
		return "", errors.New(r.Error)
	}
	return r.Pass, nil
}
