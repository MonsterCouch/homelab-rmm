package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/supervisor"
)

// Most of these tests call autoUpdateAllowed directly: the decision (install,
// refuse, report) is what is under test there, and whether an allowed build then
// downloads and applies is update.go's job. The poll that asks for the decision
// is driven for real at the end, against a loopback update-check, because the
// gate is one `if` in checkAutoUpdate and a decision nobody consults protects
// nothing.

// autoUpdateReq is the build an update-check response advertises. The URL never
// resolves because nothing here downloads it.
func autoUpdateReq(sha string) protocol.AgentUpdate {
	return protocol.AgentUpdate{URL: "https://example.invalid/agent", SHA256: sha, Version: "t"}
}

// autoUpdateEvent fails unless exactly one security event arrived, and returns
// it, so each test only states what differs between the modes.
func autoUpdateEvent(t *testing.T, evs []protocol.Event) protocol.Event {
	t.Helper()
	if len(evs) != 1 {
		t.Fatalf("expected exactly one security event, got %d: %+v", len(evs), evs)
	}
	if got := evs[0].Fields["op"]; got != protocol.ReqAgentUpdate {
		t.Fatalf("event op is %q, want %q: %+v", got, protocol.ReqAgentUpdate, evs[0])
	}
	if evs[0].Fields["reason"] == "" {
		t.Fatalf("the event carries no reason: %+v", evs[0])
	}
	return evs[0]
}

func TestAutoUpdateNoBundleIsAllowed(t *testing.T) {
	h := newTrustHarness(t, t.TempDir())

	if !h.a.autoUpdateAllowed(autoUpdateReq(strings.Repeat("ab", 32))) {
		t.Fatal("without a trust bundle the poll must install as before")
	}
	if evs := h.drainSecurity(); len(evs) != 0 {
		t.Fatalf("no bundle must stay silent, got %+v", evs)
	}
}

// A bundle whose policy is off pins the keys but enforces nothing, so the poll
// behaves exactly as it does with no bundle at all.
func TestAutoUpdateModeOffIsAllowedSilently(t *testing.T) {
	dir := t.TempDir()
	writeTrust(t, dir, newKit().bundle(actionauth.ModeOff))
	h := newTrustHarness(t, dir)

	if !h.a.autoUpdateAllowed(autoUpdateReq(strings.Repeat("ab", 32))) {
		t.Fatal("mode off must install as before")
	}
	if evs := h.drainSecurity(); len(evs) != 0 {
		t.Fatalf("mode off must stay silent, got %+v", evs)
	}
}

// An agent built without New has no trust state; there is nothing to enforce.
func TestAutoUpdateWithoutTrustStateIsAllowed(t *testing.T) {
	if !(&Agent{}).autoUpdateAllowed(autoUpdateReq(strings.Repeat("ab", 32))) {
		t.Fatal("an agent without trust state must install as before")
	}
}

func TestAutoUpdateAuditInstallsAndReportsOnce(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	writeTrust(t, dir, kit.bundle(actionauth.ModeAudit))
	h := newTrustHarness(t, dir)
	req := autoUpdateReq(strings.Repeat("ab", 32))

	if !h.a.autoUpdateAllowed(req) {
		t.Fatal("audit mode must still install the build")
	}
	ev := autoUpdateEvent(t, h.drainSecurity())
	if ev.Fields["mode"] != actionauth.ModeAudit || ev.Fields["executed"] != "true" {
		t.Fatalf("audit mode must report an unsigned install that went ahead, got %+v", ev)
	}
	if !strings.Contains(ev.Fields["reason"], actionauth.ErrUnsigned.Error()) {
		t.Fatalf("the reason must say the update was unsigned, got %q", ev.Fields["reason"])
	}
	if !strings.Contains(ev.Message, "executed unsigned") {
		t.Fatalf("the message must say the update ran unsigned, got %q", ev.Message)
	}

	// The poll repeats every few minutes: the same build is not re-reported.
	if !h.a.autoUpdateAllowed(req) {
		t.Fatal("audit mode must keep allowing the same build")
	}
	if evs := h.drainSecurity(); len(evs) != 0 {
		t.Fatalf("the same build was reported twice: %+v", evs)
	}

	// Another build is new information and is reported again.
	if !h.a.autoUpdateAllowed(autoUpdateReq(strings.Repeat("cd", 32))) {
		t.Fatal("audit mode must allow a different build too")
	}
	autoUpdateEvent(t, h.drainSecurity())
}

func TestAutoUpdateEnforceRefuses(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	writeTrust(t, dir, kit.bundle(actionauth.ModeEnforce))
	h := newTrustHarness(t, dir)
	req := autoUpdateReq(strings.Repeat("ab", 32))

	if h.a.autoUpdateAllowed(req) {
		t.Fatal("enforce must refuse an update nobody signed")
	}
	ev := autoUpdateEvent(t, h.drainSecurity())
	if ev.Fields["mode"] != actionauth.ModeEnforce || ev.Fields["executed"] != "false" {
		t.Fatalf("enforce must report the refusal, got %+v", ev)
	}
	if !strings.Contains(ev.Fields["reason"], actionauth.ErrUnsigned.Error()) {
		t.Fatalf("the reason must say the update was unsigned, got %q", ev.Fields["reason"])
	}
	if !strings.Contains(ev.Message, "refused") {
		t.Fatalf("the message must say the update was refused, got %q", ev.Message)
	}

	// Only the report is once per build: every poll is still refused.
	if h.a.autoUpdateAllowed(req) {
		t.Fatal("enforce must keep refusing the same build")
	}
	if evs := h.drainSecurity(); len(evs) != 0 {
		t.Fatalf("the same refusal was reported twice: %+v", evs)
	}
}

// A trust.json that cannot be used refuses like every other protected request,
// and says how to get out of it, instead of reading as "no bundle".
func TestAutoUpdateDamagedTrustRefuses(t *testing.T) {
	dir := t.TempDir()
	writeTrust(t, dir, []byte("{not json"))
	h := newTrustHarness(t, dir)

	if h.a.autoUpdateAllowed(autoUpdateReq(strings.Repeat("ab", 32))) {
		t.Fatal("a damaged trust.json must refuse the update")
	}
	ev := autoUpdateEvent(t, h.drainSecurity())
	if ev.Fields["mode"] != actionauth.ModeEnforce || ev.Fields["executed"] != "false" {
		t.Fatalf("a damaged pin must be reported as an enforced refusal, got %+v", ev)
	}
	if !strings.Contains(ev.Fields["reason"], "delete trust.json") {
		t.Fatalf("the reason must say how to re-pin, got %q", ev.Fields["reason"])
	}
}

// The report key is the binary's digest (without case) and the mode: the same
// build spelled differently is not a new event, but an organization moving
// from audit to enforce is, because that is exactly when an operator wants to
// see the refusal.
func TestAutoUpdateReportKeyIsBuildAndMode(t *testing.T) {
	dir := t.TempDir()
	kit := newKit()
	writeTrust(t, dir, kit.bundle(actionauth.ModeAudit))
	h := newTrustHarness(t, dir)

	if !h.a.autoUpdateAllowed(autoUpdateReq(strings.Repeat("ab", 32))) {
		t.Fatal("audit mode must install the build")
	}
	autoUpdateEvent(t, h.drainSecurity())
	if !h.a.autoUpdateAllowed(autoUpdateReq(strings.Repeat("AB", 32))) {
		t.Fatal("audit mode must install the build")
	}
	if evs := h.drainSecurity(); len(evs) != 0 {
		t.Fatalf("the same digest in upper case was reported again: %+v", evs)
	}

	// What a signed trust.update to an enforcing bundle leaves behind.
	nb, err := actionauth.ParseBundle(kit.bundle(actionauth.ModeEnforce))
	if err != nil {
		t.Fatal(err)
	}
	h.a.trust.mu.Lock()
	h.a.trust.bundle = nb
	h.a.trust.mu.Unlock()

	if h.a.autoUpdateAllowed(autoUpdateReq(strings.Repeat("ab", 32))) {
		t.Fatal("enforce must refuse the build audit mode let through")
	}
	ev := autoUpdateEvent(t, h.drainSecurity())
	if ev.Fields["mode"] != actionauth.ModeEnforce || ev.Fields["executed"] != "false" {
		t.Fatalf("the switch to enforce must be reported for a build already seen in audit, got %+v", ev)
	}
}

// ---- the poll itself ----

// logBuffer collects what the agent logs, safe to write from any goroutine.
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// pollResult is what some polls of checkAutoUpdate did.
type pollResult struct {
	// installs is how often a poll got as far as asking the supervisor for a
	// slot, which is the first thing a real install does once its argument
	// checks have passed. The slot answer has no path, so the install stops right
	// there: nothing is downloaded, staged or restarted.
	installs int
	events   []protocol.Event
	logs     string
}

// pollUpdateCheck runs checkAutoUpdate polls times against a loopback
// update-check endpoint that answers with reply(base URL), on an agent whose
// trust bundle has the given mode ("" is no bundle at all). The gate on the
// unattended install path is a single `if` in checkAutoUpdate, so the poll is
// driven as it runs rather than only the decision it asks for.
func pollUpdateCheck(t *testing.T, mode string, polls int, reply func(base string) map[string]any) pollResult {
	t.Helper()
	dir := t.TempDir()
	if mode != "" {
		writeTrust(t, dir, newKit().bundle(mode))
	}
	h := newTrustHarness(t, dir)

	check := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/update-check" || r.Header.Get("Authorization") != "Bearer test-key" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(reply("http://" + r.Host))
	}))
	t.Cleanup(check.Close)
	// The harness agent has no server of its own: without both of these the poll
	// returns before asking anything and every case would pass for nothing.
	h.a.cfg.ServerURL = check.URL
	h.a.cfg.Key = "test-key"

	pipe := supervisor.NewInMemoryPipe()
	t.Cleanup(func() { pipe.Close() })
	srv := supervisor.NewIPCServer()
	t.Cleanup(func() { srv.Stop() })
	var installs atomic.Int32
	srv.RegisterHandler(supervisor.MsgGetInactive, func(*supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		installs.Add(1)
		return &supervisor.IPCMessage{Type: supervisor.MsgInactiveResp}, nil
	})
	if err := srv.Start(pipe); err != nil {
		t.Fatal(err)
	}
	conn, err := pipe.Dial()
	if err != nil {
		t.Fatal(err)
	}
	client := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = client.Connect(conn)
	t.Cleanup(func() { client.Close() })
	h.a.SetIPCClient(client)

	var logs logBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for i := 0; i < polls; i++ {
		h.a.checkAutoUpdate(context.Background())
	}
	return pollResult{installs: int(installs.Load()), events: h.drainSecurity(), logs: logs.String()}
}

// advertisedBuild is an update-check answer that offers a build, as the server
// does to every device that is not in an enforcing organization.
func advertisedBuild(base string) map[string]any {
	return map[string]any{"update_available": true, "version": "9.9.9", "sha256": strings.Repeat("ab", 32), "url": base + "/api/agent-download/rmm-agent"}
}

// withheldBuild is what an enforcing server sends instead (handleAgentUpdateCheck):
// the digest and version, but no url, and update_available false.
func withheldBuild(string) map[string]any {
	return map[string]any{"update_available": false, "signed_update_required": true, "version": "9.9.9", "sha256": strings.Repeat("ab", 32)}
}

// The device decides for itself whether to take an advertised build, whatever
// the server says: the server only withholds it from an enforcing organization
// to spare the alerts, so a server that advertises anyway, or whose idea of the
// organization mode differs from the pin on the device, must still not get an
// unsigned install out of an enforcing device.
func TestAutoUpdatePollInstallsOnlyWhereThePinAllowsIt(t *testing.T) {
	for _, c := range []struct {
		name         string
		mode         string
		wantInstalls int
		wantEvents   int
	}{
		{"no bundle", "", 1, 0},
		{"mode off", actionauth.ModeOff, 1, 0},
		{"audit", actionauth.ModeAudit, 1, 1},
		{"enforce", actionauth.ModeEnforce, 0, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := pollUpdateCheck(t, c.mode, 1, advertisedBuild)
			if got.installs != c.wantInstalls {
				t.Errorf("the poll went on to install %d times, want %d\nlog: %s", got.installs, c.wantInstalls, got.logs)
			}
			if len(got.events) != c.wantEvents {
				t.Errorf("security events = %d, want %d: %+v", len(got.events), c.wantEvents, got.events)
			}
		})
	}
}

// What an enforcing server sends is not an advertisement: nothing is installed
// and no security event is raised, because the device was never asked to do
// anything unsigned. The device says once that a build is staged and must come
// from the console, not on every five-minute poll.
func TestAutoUpdatePollWithheldBuildIsNoticedOnce(t *testing.T) {
	got := pollUpdateCheck(t, actionauth.ModeEnforce, 3, withheldBuild)
	if got.installs != 0 {
		t.Errorf("a withheld build was installed %d times", got.installs)
	}
	if len(got.events) != 0 {
		t.Errorf("a withheld build raised security events: %+v", got.events)
	}
	if n := strings.Count(got.logs, "requires a signed update from the console"); n != 1 {
		t.Errorf("the staged build was noticed %d times over 3 polls, want exactly once\nlog: %s", n, got.logs)
	}
}
