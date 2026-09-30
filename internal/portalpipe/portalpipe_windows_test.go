//go:build windows

package portalpipe

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func testPipe(t *testing.T) string {
	return fmt.Sprintf(`\\.\pipe\homelab-rmm-portal-test-%d`, time.Now().UnixNano())
}

// waitServing retries Ask until the background listener is up.
func waitServing(t *testing.T, name string) (string, error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		pass, err := Ask(name)
		if err == nil || time.Now().After(deadline) || !strings.Contains(err.Error(), "not running") {
			return pass, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The account handed to the pass function is the caller's own, read off the
// pipe, and the pass comes back to the caller.
func TestAskGetsPassForCallersOwnAccount(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	name := testPipe(t)
	var mu sync.Mutex
	var got []Account
	Serve(ctx, name, func(_ context.Context, a Account) (string, error) {
		mu.Lock()
		got = append(got, a)
		mu.Unlock()
		return "pass-for-" + a.User, nil
	})

	pass, err := waitServing(t, name)
	if err != nil {
		t.Fatal(err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("pass function called %d times", len(got))
	}
	// user.Current is DOMAIN\name; a local account is reported bare.
	want := me.Username
	if got[0].Local {
		want = want[strings.LastIndex(want, `\`)+1:]
	}
	if !strings.EqualFold(got[0].User, want) {
		t.Fatalf("account = %q (local %v), want %q", got[0].User, got[0].Local, me.Username)
	}
	if pass != "pass-for-"+got[0].User {
		t.Fatalf("pass = %q", pass)
	}
}

// A caller that connects and says nothing must not stop anyone else.
func TestSilentCallerDoesNotBlockOthers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	name := testPipe(t)
	Serve(ctx, name, func(context.Context, Account) (string, error) { return "ok", nil })
	if _, err := waitServing(t, name); err != nil {
		t.Fatal(err)
	}

	n, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CreateFile(n, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)

	done := make(chan error, 1)
	go func() {
		_, err := Ask(name)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a silent caller blocked the next one")
	}
}

// A failure getting the pass reaches the caller as an error, not a pass.
func TestPassFailureIsReported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	name := testPipe(t)
	Serve(ctx, name, func(context.Context, Account) (string, error) { return "", errors.New("down") })
	if _, err := waitServing(t, name); err == nil || !strings.Contains(err.Error(), "could not be reached") {
		t.Fatalf("err = %v", err)
	}
}

// A second listener on a name that is already served refuses to start
// (FILE_FLAG_FIRST_PIPE_INSTANCE), so it cannot share callers with the first.
func TestSecondOwnerIsRefused(t *testing.T) {
	name := testPipe(t)
	h, err := createPipe(name, true)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if h2, err := createPipe(name, true); err == nil {
		windows.CloseHandle(h2)
		t.Fatal("a second first-instance listener was allowed")
	}
}

// Ending the context stops the listener.
func TestServeStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	name := testPipe(t)
	Serve(ctx, name, func(context.Context, Account) (string, error) { return "ok", nil })
	if _, err := waitServing(t, name); err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := Ask(name)
		if err != nil && strings.Contains(err.Error(), "not running") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still serving after cancel: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A silent caller is cut off at the deadline, so maxClients of them cannot
// lock the portal for everyone else.
func TestSilentCallerIsCutOff(t *testing.T) {
	old := clientDeadline
	clientDeadline = 300 * time.Millisecond
	defer func() { clientDeadline = old }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	name := testPipe(t)
	Serve(ctx, name, func(context.Context, Account) (string, error) { return "ok", nil })
	if _, err := waitServing(t, name); err != nil {
		t.Fatal(err)
	}
	n, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CreateFile(n, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	// The agent answers "unknown request" once the deadline cuts the read
	// short, then hangs up; reading to the end must finish well before 5s.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 512)
		var n uint32
		for windows.ReadFile(h, buf, &n, nil) == nil && n > 0 {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("silent caller was never cut off")
	}
}
