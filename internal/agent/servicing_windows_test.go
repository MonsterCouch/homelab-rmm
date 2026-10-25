//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const servicingSum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type servicingCall struct {
	name     string
	args     []string
	deadline time.Duration // time left on the command's context when it started
}

// servicingFake replaces every seam of the repair with recorders. exits maps
// "<exe> <first arg>" to the exit code the fake command returns.
type servicingFake struct {
	mu       sync.Mutex
	calls    []servicingCall
	exits    map[string]int
	out      map[string]string
	root     string
	fetched  []protocol.ServicingPackage
	fetchErr error
	scan     *protocol.UpdatesScanResult
	scanErr  error
	pending  bool
	rebooted int
}

func newServicingFake(t *testing.T) *servicingFake {
	t.Helper()
	f := &servicingFake{exits: map[string]int{}, out: map[string]string{}, root: t.TempDir()}
	f.scan = &protocol.UpdatesScanResult{}
	t.Setenv("SystemRoot", f.root)
	oldExec, oldScan, oldPending, oldReboot, oldFetch := servicingExec, servicingScan, servicingPending, servicingReboot, servicingFetch
	servicingExec = func(ctx context.Context, name string, args ...string) (string, int, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		c := servicingCall{name: name, args: args}
		if d, ok := ctx.Deadline(); ok {
			c.deadline = time.Until(d)
		}
		f.calls = append(f.calls, c)
		key := strings.ToLower(filepath.Base(name))
		if len(args) > 0 {
			key += " " + strings.ToLower(args[0])
		}
		code := f.exits[key]
		out := f.out[key]
		if code != 0 {
			return out, code, fmt.Errorf("%s exited with %d", filepath.Base(name), code)
		}
		return out, 0, nil
	}
	servicingScan = func(context.Context) (*protocol.UpdatesScanResult, error) { return f.scan, f.scanErr }
	servicingPending = func() bool { return f.pending }
	servicingReboot = func() error { f.rebooted++; return nil }
	servicingFetch = func(_ context.Context, _ *Config, pkg protocol.ServicingPackage, dst string) (string, error) {
		f.fetched = append(f.fetched, pkg)
		if f.fetchErr != nil {
			return "", f.fetchErr
		}
		return "cache leader-1 over h3", os.WriteFile(dst, []byte("cab"), 0o600)
	}
	t.Cleanup(func() {
		servicingExec, servicingScan, servicingPending, servicingReboot, servicingFetch = oldExec, oldScan, oldPending, oldReboot, oldFetch
	})
	return f
}

func (f *servicingFake) names() []string {
	var out []string
	for _, c := range f.calls {
		out = append(out, strings.ToLower(filepath.Base(c.name))+" "+strings.Join(c.args, " "))
	}
	return out
}

func stepStatuses(res *protocol.ServicingRepairResult) string {
	var parts []string
	for _, s := range res.Steps {
		parts = append(parts, s.Name+"="+s.Status)
	}
	return strings.Join(parts, ",")
}

func TestServicingCommandLinesTimeoutsAndPaths(t *testing.T) {
	f := newServicingFake(t)
	res, err := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{
		Steps:   []string{"rescan", "add_package", "sfc", "dism_restore"}, // deliberately out of order
		Package: &protocol.ServicingPackage{URL: "https://rmm.example/pkg/fix.cab", SHA256: servicingSum},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := stepStatuses(res), "dism_restore=ok,sfc=ok,add_package=ok,rescan=ok"; got != want {
		t.Fatalf("steps = %s, want %s (canonical order, whatever the request order)", got, want)
	}
	if len(f.calls) != 3 {
		t.Fatalf("commands = %v", f.names())
	}
	sys32 := filepath.Join(f.root, "System32")
	for _, c := range f.calls {
		if filepath.Dir(c.name) != sys32 {
			t.Errorf("%s is not an absolute path under %s", c.name, sys32)
		}
	}
	if got := f.names()[0]; got != "dism.exe /Online /Cleanup-Image /RestoreHealth" {
		t.Errorf("dism_restore ran %q", got)
	}
	if got := f.names()[1]; got != "sfc.exe /scannow" {
		t.Errorf("sfc ran %q", got)
	}
	if got := f.names()[2]; !strings.HasPrefix(got, "dism.exe /Online /Add-Package /PackagePath:") || !strings.HasSuffix(got, "package.cab /NoRestart") {
		t.Errorf("add_package ran %q", got)
	}
	within := func(got, want time.Duration) bool { return got <= want && got > want-time.Minute }
	if !within(f.calls[0].deadline, 60*time.Minute) {
		t.Errorf("dism timeout = %v, want 60m", f.calls[0].deadline)
	}
	if !within(f.calls[1].deadline, 30*time.Minute) {
		t.Errorf("sfc timeout = %v, want 30m", f.calls[1].deadline)
	}
	if !within(f.calls[2].deadline, 60*time.Minute) {
		t.Errorf("add-package timeout = %v, want 60m", f.calls[2].deadline)
	}
	if len(f.fetched) != 1 || f.fetched[0].SHA256 != servicingSum {
		t.Errorf("fetched = %+v", f.fetched)
	}
	if !strings.Contains(res.Steps[2].Tail, "package fetched from cache leader-1 over h3") {
		t.Errorf("the add_package tail does not say where the package came from: %q", res.Steps[2].Tail)
	}
	if res.Scan == nil {
		t.Error("the rescan result is missing")
	}
}

func TestServicingDefaultStepsWhenNoneNamed(t *testing.T) {
	f := newServicingFake(t)
	res, err := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := stepStatuses(res), "dism_restore=ok,reset_components=ok,rescan=ok"; got != want {
		t.Fatalf("steps = %s, want %s", got, want)
	}
	_ = f
}

func TestServicingRejectsUnknownStepAndReboot(t *testing.T) {
	newServicingFake(t)
	if _, err := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"format_c"}}, nil); err == nil || !strings.Contains(err.Error(), "unknown servicing repair step") {
		t.Errorf("unknown step: err = %v", err)
	}
	if _, err := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Reboot: "always"}, nil); err == nil {
		t.Error("reboot=always must be refused")
	}
}

func TestServicingResetRenamesOnlyTheCatalogDirectories(t *testing.T) {
	f := newServicingFake(t)
	sd := filepath.Join(f.root, "SoftwareDistribution")
	cr := filepath.Join(f.root, "System32", "catroot2")
	for _, d := range []string{sd, cr, sd + ".bak.111", cr + ".bak.111", filepath.Join(f.root, "System32", "catroot")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(sd, "DataStore.edb"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(f.root, "System32", "keep.txt"), []byte("x"), 0o600)
	fixed := time.Unix(1_700_000_000, 0)
	old := servicingNow
	servicingNow = func() time.Time { return fixed }
	t.Cleanup(func() { servicingNow = old })

	res, err := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"reset_components"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Steps[0].Status != "ok" {
		t.Fatalf("reset_components = %+v", res.Steps[0])
	}
	for _, gone := range []string{sd, cr, sd + ".bak.111", cr + ".bak.111"} {
		if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s should be gone (renamed, or an older backup deleted): %v", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(sd+".bak.1700000000", "DataStore.edb")); err != nil {
		t.Errorf("the renamed directory lost its content: %v", err)
	}
	if _, err := os.Stat(cr + ".bak.1700000000"); err != nil {
		t.Errorf("catroot2 was not renamed: %v", err)
	}
	for _, kept := range []string{filepath.Join(f.root, "System32", "catroot"), filepath.Join(f.root, "System32", "keep.txt")} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s must not be touched: %v", kept, err)
		}
	}
	want := []string{
		"net.exe stop wuauserv /y", "net.exe stop bits /y", "net.exe stop cryptsvc /y", "net.exe stop msiserver /y",
		"net.exe start msiserver", "net.exe start cryptsvc", "net.exe start bits", "net.exe start wuauserv",
	}
	if got := f.names(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("service sequence = %v\nwant %v", got, want)
	}
}

func TestServicingResetWithMissingDirectoriesIsNotAnError(t *testing.T) {
	f := newServicingFake(t)
	res, err := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"reset_components"}}, nil)
	if err != nil || res.Steps[0].Status != "ok" {
		t.Fatalf("res = %+v err = %v", res, err)
	}
	_ = f
}

// A rename that fails (a file inside is held open without delete sharing)
// fails the step, and the services still come back.
func TestServicingResetFailureStillRestartsServices(t *testing.T) {
	f := newServicingFake(t)
	sd := filepath.Join(f.root, "SoftwareDistribution")
	os.MkdirAll(sd, 0o755)
	held, err := os.Create(filepath.Join(sd, "locked.edb"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	res, err := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"reset_components", "rescan"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := stepStatuses(res), "reset_components=failed,rescan=skipped"; got != want {
		t.Fatalf("steps = %s, want %s (tail %q)", got, want, res.Steps[0].Tail)
	}
	starts := 0
	for _, n := range f.names() {
		if strings.HasPrefix(n, "net.exe start") {
			starts++
		}
	}
	if starts != 4 {
		t.Errorf("services started = %d, want 4 even though the rename failed", starts)
	}
	if !strings.Contains(res.Steps[0].Tail, "could not rename") {
		t.Errorf("tail = %q", res.Steps[0].Tail)
	}
}

func TestServicingStopsAtFirstFailureButSFCIsAdvisory(t *testing.T) {
	f := newServicingFake(t)
	f.exits["dism.exe /online"] = 1726
	res, _ := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"dism_restore", "sfc", "reset_components", "rescan"}}, nil)
	if got, want := stepStatuses(res), "dism_restore=failed,sfc=skipped,reset_components=skipped,rescan=skipped"; got != want {
		t.Fatalf("steps = %s, want %s", got, want)
	}
	if res.Steps[0].ExitCode != 1726 {
		t.Errorf("exit code = %d", res.Steps[0].ExitCode)
	}
	if len(f.calls) != 1 {
		t.Errorf("commands after the failure ran: %v", f.names())
	}

	f2 := newServicingFake(t)
	f2.exits["sfc.exe /scannow"] = 1
	res, _ = servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"sfc", "reset_components", "rescan"}}, nil)
	if got, want := stepStatuses(res), "sfc=failed,reset_components=ok,rescan=ok"; got != want {
		t.Fatalf("steps = %s, want %s (sfc is advisory)", got, want)
	}
}

func TestServicingRebootExit3010AndPolicy(t *testing.T) {
	for _, tc := range []struct {
		reboot string
		want   int
	}{{"never", 0}, {"", 0}, {"if_required", 1}} {
		f := newServicingFake(t)
		f.exits["dism.exe /online"] = 3010
		res, err := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"dism_restore"}, Reboot: tc.reboot}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Steps[0].Status != "ok" || !res.RebootRequired {
			t.Errorf("reboot=%q: 3010 is success with a reboot needed: %+v required=%v", tc.reboot, res.Steps[0], res.RebootRequired)
		}
		if f.rebooted != tc.want {
			t.Errorf("reboot=%q: reboots scheduled = %d, want %d", tc.reboot, f.rebooted, tc.want)
		}
	}
	f := newServicingFake(t)
	f.pending = true
	res, _ := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"sfc"}, Reboot: "if_required"}, nil)
	if !res.RebootRequired || f.rebooted != 1 {
		t.Errorf("a pending-reboot marker counts: required=%v reboots=%d", res.RebootRequired, f.rebooted)
	}
}

func TestServicingAddPackageValidation(t *testing.T) {
	f := newServicingFake(t)
	run := func(pkg *protocol.ServicingPackage) protocol.ServicingStep {
		res, err := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"add_package"}, Package: pkg}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Steps[0]
	}
	if st := run(nil); st.Status != "skipped" {
		t.Errorf("no package: %+v", st)
	}
	if st := run(&protocol.ServicingPackage{URL: "https://rmm.example/x.exe", SHA256: servicingSum}); st.Status != "failed" || !strings.Contains(st.Tail, ".cab or .msu") {
		t.Errorf("exe package: %+v", st)
	}
	if st := run(&protocol.ServicingPackage{URL: "https://rmm.example/x.msu", SHA256: "abc"}); st.Status != "failed" || !strings.Contains(st.Tail, "SHA-256") {
		t.Errorf("bad hash: %+v", st)
	}
	f.fetchErr = errors.New("hash mismatch")
	if st := run(&protocol.ServicingPackage{URL: "https://rmm.example/x.msu", SHA256: servicingSum}); st.Status != "failed" || !strings.Contains(st.Tail, "hash mismatch") {
		t.Errorf("fetch failure: %+v", st)
	}
	if len(f.calls) != 0 {
		t.Errorf("DISM ran although no package was fetched: %v", f.names())
	}
}

func TestServicingRescanReportsOutcome(t *testing.T) {
	f := newServicingFake(t)
	f.scan = &protocol.UpdatesScanResult{Error: "WUA search failed: 0x80240020", RebootPending: true}
	res, _ := servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"rescan"}}, nil)
	if res.Steps[0].Status != "failed" || !strings.Contains(res.Steps[0].Tail, "0x80240020") || res.Scan == nil || !res.RebootRequired {
		t.Errorf("a scan that still errors means the repair did not work: %+v scan=%v", res.Steps[0], res.Scan)
	}
	f.scan, f.scanErr = nil, errors.New("scan crashed")
	res, _ = servicingRepair(context.Background(), &Config{}, protocol.ServicingRepair{Steps: []string{"rescan"}}, nil)
	if res.Steps[0].Status != "failed" || res.Scan != nil {
		t.Errorf("scan error: %+v", res.Steps[0])
	}
}

func TestServicingTailCleansOutputAndKeepsTheEnd(t *testing.T) {
	got := servicingTail("W\x00i\x00n\x00\r\n[==  10%  ]\r[=====100%=====]\r\n\r\nThe operation completed.\r\n")
	if got != "Win\n[==  10%  ]\n[=====100%=====]\nThe operation completed." {
		t.Errorf("tail = %q", got)
	}
	long := strings.Repeat("line of text that repeats\n", 400) + "THE END"
	got = servicingTail(long)
	if len(got) > servicingTailBytes+3 || !strings.HasSuffix(got, "THE END") || !strings.HasPrefix(got, "...") {
		t.Errorf("long tail: len=%d prefix=%q", len(got), got[:10])
	}
}

// The production executor is runHidden (hidden window, process tree killed on
// timeout, covered by proc_windows_test.go); this pins that it reports the
// exit code the fake executor stands in for.
func TestServicingRunHiddenReportsExitCode(t *testing.T) {
	cmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	out, code, err := servicingRunHidden(context.Background(), cmd, "/c", "echo hello & exit 3")
	if code != 3 || err == nil || !strings.Contains(out, "hello") {
		t.Errorf("out=%q code=%d err=%v", out, code, err)
	}
	_, code, err = servicingRunHidden(context.Background(), cmd, "/c", "exit 0")
	if code != 0 || err != nil {
		t.Errorf("code=%d err=%v", code, err)
	}
}

func TestServicingFetchPackageRefusesForeignHosts(t *testing.T) {
	cfg := &Config{ServerURL: "https://rmm.example:8443"}
	for _, u := range []string{"http://rmm.example:8443/a.cab", "https://evil.example/a.cab"} {
		if _, err := servicingFetchPackage(context.Background(), cfg, protocol.ServicingPackage{URL: u, SHA256: servicingSum}, filepath.Join(t.TempDir(), "p.cab")); err == nil {
			t.Errorf("%s must be refused", u)
		}
	}
}
