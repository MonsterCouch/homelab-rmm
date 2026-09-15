package svc

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kardianos/service"
)

// fakeService is a service.Service whose Status is scripted, so the waits that
// make a reinstall over a running service safe can be exercised without a
// service manager. Only Status is used by the code under test.
type fakeService struct {
	mu     sync.Mutex
	steps  []step
	calls  int
	closed bool
}

type step struct {
	st  service.Status
	err error
}

func (f *fakeService) Status() (service.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if len(f.steps) == 0 {
		return service.StatusUnknown, errors.New("exhausted")
	}
	s := f.steps[0]
	if len(f.steps) > 1 {
		f.steps = f.steps[1:]
	}
	return s.st, s.err
}

func (f *fakeService) Run() error                                        { return nil }
func (f *fakeService) Start() error                                      { return nil }
func (f *fakeService) Stop() error                                       { return nil }
func (f *fakeService) Restart() error                                    { return nil }
func (f *fakeService) Install() error                                    { return nil }
func (f *fakeService) Uninstall() error                                  { return nil }
func (f *fakeService) Logger(chan<- error) (service.Logger, error)       { return nil, nil }
func (f *fakeService) SystemLogger(chan<- error) (service.Logger, error) { return nil, nil }
func (f *fakeService) String() string                                    { return "fake" }
func (f *fakeService) Platform() string                                  { return "fake" }

func TestWaitForStatusReturnsWhenTheServiceStops(t *testing.T) {
	f := &fakeService{steps: []step{
		{st: service.StatusRunning},
		{st: service.StatusRunning},
		{st: service.StatusStopped},
	}}
	start := time.Now()
	waitForStatus(f, service.StatusStopped, 10*time.Second)
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("waiting for Stopped took %s", took)
	}
	if f.calls < 3 {
		t.Fatalf("expected to poll until stopped, polled %d times", f.calls)
	}
}

func TestWaitForStatusGivesUpAtTheDeadline(t *testing.T) {
	f := &fakeService{steps: []step{{st: service.StatusRunning}}} // never stops
	start := time.Now()
	waitForStatus(f, service.StatusStopped, 1200*time.Millisecond)
	took := time.Since(start)
	if took < time.Second {
		t.Fatalf("returned after %s, before the deadline", took)
	}
	if took > 5*time.Second {
		t.Fatalf("overshot the deadline: %s", took)
	}
}

func TestWaitGoneReturnsOnceStatusFails(t *testing.T) {
	// Windows marks a running service for deletion and only removes it when the
	// last handle closes; Status reporting an error is how "it is really gone"
	// looks, and Install must not run before then.
	f := &fakeService{steps: []step{
		{st: service.StatusStopped},
		{st: service.StatusUnknown, err: service.ErrNotInstalled},
	}}
	start := time.Now()
	waitGone(f, 10*time.Second)
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("waitGone took %s", took)
	}
	if f.calls < 2 {
		t.Fatalf("waitGone stopped polling after %d calls", f.calls)
	}
}

// TestDescribeNamesTheInitSystem pins OP-10: `install` printed "service
// installed and started" whatever it actually registered, so on a host
// without systemd the operator was sent to `systemctl status <name>` for a
// SysV script that systemctl cannot see.
func TestDescribeNamesTheInitSystem(t *testing.T) {
	spec := Spec{Name: "HomelabRMMTest", DisplayName: "Test", Description: "test"}
	got := Describe(spec)
	if !strings.Contains(got, spec.Name) {
		t.Fatalf("Describe should name the service: %q", got)
	}
	switch {
	case strings.Contains(got, "systemd"), strings.Contains(got, "SysV"), strings.Contains(got, "Windows"):
	default:
		t.Fatalf("Describe should say which init system was used: %q", got)
	}
	if strings.Contains(got, "SysV") && !strings.Contains(got, "/var/log/") {
		t.Fatalf("the SysV wording must say where the output goes: %q", got)
	}
}

// TestInitScriptStatusIgnoresOtherPlatforms keeps the SysV workaround off
// every platform that does not need it.
func TestInitScriptStatusIgnoresOtherPlatforms(t *testing.T) {
	if _, ok := initScriptStatus("HomelabRMMTest", "linux-systemd"); ok {
		t.Fatal("the SysV fallback must not answer for systemd")
	}
	if _, ok := initScriptStatus("HomelabRMMNoSuchService", "unix-systemv"); ok {
		t.Fatal("a service with no init script must not report a status")
	}
}
