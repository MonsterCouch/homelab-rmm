//go:build linux

package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// These tests exercise the real platform functions on the host running the
// suite. Anything that would change the machine (service actions, package
// installs, power) is only driven through its validation paths.

func TestLinuxPlatformLabel(t *testing.T) {
	label := platformName()
	if strings.TrimSpace(label) == "" {
		t.Fatal("platformName returned empty")
	}
	if pn := osRelease()["PRETTY_NAME"]; pn != "" && label != pn {
		t.Fatalf("label %q, want PRETTY_NAME %q", label, pn)
	}
	t.Logf("platform label: %s", label)
}

func TestLinuxRunCmd(t *testing.T) {
	ctx := context.Background()
	out, _, code, err := runCmd(ctx, "sh", "-c", "echo out; echo err 1>&2; echo LC_ALL=$LC_ALL; exit 3")
	if err == nil || code != 3 {
		t.Fatalf("want exit 3 with error, got code=%d err=%v", code, err)
	}
	if !strings.Contains(out, "out\n") || !strings.Contains(out, "LC_ALL=C") {
		t.Fatalf("stdout %q", out)
	}
	if _, _, _, err := runCmd(ctx, "definitely-not-a-binary-xyz"); !errors.Is(err, errNotFound) {
		t.Fatalf("missing binary must be errNotFound, got %v", err)
	}
	// output cap: 12 MB of 'a' must come back truncated, not OOM us
	out, _, _, err = runCmd(ctx, "sh", "-c", "head -c 12000000 /dev/zero | tr '\\0' a")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > maxCmdOutput+64 || !strings.HasSuffix(out, "[output truncated]") {
		t.Fatalf("cap not applied: len=%d suffix=%q", len(out), out[max(0, len(out)-30):])
	}
	// ctx timeout kills the child promptly
	tctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, _, err = runCmd(tctx, "sleep", "30")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
}

func TestLinuxStreamCmd(t *testing.T) {
	var lines []string
	log, code, err := streamCmd(context.Background(), []string{"RMM_TEST_VAR=1"}, func(l string) { lines = append(lines, l) }, "sh", "-c", "echo one; echo two 1>&2; echo var=$RMM_TEST_VAR")
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if len(lines) != 3 || !strings.Contains(log, "one\n") || !strings.Contains(log, "two\n") || !strings.Contains(log, "var=1") {
		t.Fatalf("lines=%v log=%q", lines, log)
	}
}

// TestLinuxPrepareCommandKillsGroup starts a shell with a backgrounded
// grandchild and lets the context expire: both must be gone, not just the
// shell, or a timed-out script would leak its children.
func TestLinuxPrepareCommandKillsGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", "sleep 60 & sleep 60")
	prepareCommand(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatal("Setpgid not set")
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	start := time.Now()
	cmd.Wait()
	if time.Since(start) > 5*time.Second {
		t.Fatalf("Wait took %s", time.Since(start))
	}
	// give the kernel a moment to deliver the group SIGKILL
	deadline := time.Now().Add(3 * time.Second)
	for {
		if n := liveProcsInGroup(pgid); n == 0 {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("%d process(es) still alive in group %d", n, pgid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// liveProcsInGroup counts non-zombie processes whose pgrp is pgid, from /proc.
func liveProcsInGroup(pgid int) int {
	entries, _ := os.ReadDir("/proc")
	n := 0
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// "pid (comm) state ppid pgrp ..." — comm may contain spaces, so
		// split after the closing parenthesis.
		s := string(b)
		i := strings.LastIndex(s, ")")
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 3 || f[0] == "Z" {
			continue
		}
		if g, _ := strconv.Atoi(f[2]); g == pgid {
			n++
		}
	}
	return n
}

// ptyOutput pumps a session's output on a goroutine so tests can wait for
// a marker with a deadline instead of blocking in Read.
type ptyOutput struct {
	mu   sync.Mutex
	buf  strings.Builder
	err  error
	done chan struct{}
}

func pumpPTY(p ptySession) *ptyOutput {
	o := &ptyOutput{done: make(chan struct{})}
	go func() {
		defer close(o.done)
		b := make([]byte, 4096)
		for {
			n, err := p.Read(b)
			o.mu.Lock()
			o.buf.Write(b[:n])
			if err != nil {
				o.err = err
			}
			o.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return o
}

func (o *ptyOutput) text() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

// waitFor polls until pred(text) holds or the deadline passes.
func (o *ptyOutput) waitFor(t *testing.T, what string, max time.Duration, pred func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(max)
	for {
		s := o.text()
		if pred(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s, got %q", what, s)
		}
		select {
		case <-o.done:
			if s = o.text(); pred(s) {
				return s
			}
			t.Fatalf("session ended before %s: err=%v got %q", what, o.err, s)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// waitEOF returns whether the reader ended with io.EOF within max.
func (o *ptyOutput) waitEOF(max time.Duration) (bool, error) {
	select {
	case <-o.done:
		o.mu.Lock()
		defer o.mu.Unlock()
		return errors.Is(o.err, io.EOF), o.err
	case <-time.After(max):
		return false, errors.New("timeout")
	}
}

// TestLinuxPTYEcho must run wherever /bin/sh exists: creack/pty works in
// containers.
func TestLinuxPTYEcho(t *testing.T) {
	p, err := startPTY("", 80, 24)
	if err != nil {
		t.Fatalf("startPTY: %v", err)
	}
	defer p.Close()
	out := pumpPTY(p)
	if _, err := p.Write([]byte("echo hello-from-pty\n")); err != nil {
		t.Fatal(err)
	}
	// the terminal echoes the command line, then the shell prints the word
	// on its own line
	out.waitFor(t, "echoed output", 15*time.Second, func(s string) bool { return strings.Count(s, "hello-from-pty") >= 2 })
	if err := p.Resize(100, 40); err != nil {
		t.Fatalf("resize: %v", err)
	}
	if err := p.Resize(0, 0); err == nil {
		t.Fatal("resize to 0x0 must be rejected")
	}
	p.Write([]byte("exit\n"))
	if ok, err := out.waitEOF(10 * time.Second); !ok {
		t.Fatalf("Read did not return io.EOF after the shell exited: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close after exit: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}
}

func TestLinuxPTYCloseUnblocksRead(t *testing.T) {
	p, err := startPTY("sh", 80, 24)
	if err != nil {
		t.Fatalf("startPTY: %v", err)
	}
	out := pumpPTY(p)
	p.Write([]byte("echo ready-marker\n"))
	out.waitFor(t, "shell prompt", 15*time.Second, func(s string) bool { return strings.Count(s, "ready-marker") >= 2 })
	start := time.Now()
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if ok, err := out.waitEOF(10 * time.Second); !ok && (err == nil || !strings.Contains(err.Error(), "closed")) {
		t.Fatalf("want EOF after Close, got %v", err)
	}
	if time.Since(start) > 6*time.Second {
		t.Fatalf("Close took %s; SIGHUP should end a shell immediately", time.Since(start))
	}
}

func TestLinuxResolveShell(t *testing.T) {
	bin, args, err := resolveShell("")
	if err != nil || !strings.HasSuffix(bin, "sh") || len(args) == 0 {
		t.Fatalf("default shell: %q %v %v", bin, args, err)
	}
	if _, _, err := resolveShell("cmd"); err == nil {
		t.Fatal("cmd must be rejected on Linux")
	}
	if _, _, err := resolveShell("../../evil"); err == nil {
		t.Fatal("unknown shell must be rejected")
	}
	if !hasCmd("pwsh") {
		if _, _, err := resolveShell("powershell"); err == nil {
			t.Fatal("powershell without pwsh must error")
		}
	}
	// the name is normalised before the lookup: " ZSH " is zsh, whether or
	// not it is installed
	if _, _, err := resolveShell(" ZSH "); err != nil && !strings.Contains(err.Error(), "zsh is not installed") {
		t.Fatalf("zsh lookup must use the normalised name: %v", err)
	}
	env := shellEnv()
	if envValue(env, "TERM") != "xterm-256color" || envValue(env, "LANG") != "C.UTF-8" || envValue(env, "HOME") == "" || envValue(env, "PATH") == "" {
		t.Fatalf("shell env: %v", env)
	}
	for _, e := range env {
		if strings.HasPrefix(e, "LC_ALL=") {
			t.Fatal("LC_ALL must not leak into the interactive shell")
		}
	}
}

func TestLinuxRealServices(t *testing.T) {
	if !hasCmd("systemctl") {
		t.Skip("systemctl not installed")
	}
	svcs, err := listServices()
	if err != nil {
		if strings.Contains(err.Error(), "not been booted with systemd") || strings.Contains(err.Error(), "connect to bus") {
			t.Skipf("no running systemd here: %v", err)
		}
		t.Fatal(err)
	}
	if len(svcs) == 0 {
		t.Fatal("no services listed")
	}
	running, withPID := 0, 0
	for _, s := range svcs {
		if s.Name == "" || !strings.HasSuffix(s.Name, ".service") || s.State == "" || s.StartType == "" {
			t.Fatalf("malformed service %#v", s)
		}
		if s.State == "running" {
			running++
			if s.PID > 0 {
				withPID++
			}
		}
	}
	t.Logf("%d services, %d running, %d with a pid", len(svcs), running, withPID)
	if running > 0 && withPID == 0 {
		t.Fatal("running services but no MainPID resolved")
	}
	if st := serviceState(svcs[0].Name); st == "" {
		t.Fatal("serviceState empty")
	}
}

func TestLinuxServiceValidation(t *testing.T) {
	if serviceState("-rf") != "unknown" || serviceState("a b") != "unknown" {
		t.Fatal("hostile names must be unknown")
	}
	if _, err := serviceAction("../etc/passwd", "start"); err == nil {
		t.Fatal("bad name must error")
	}
	if _, err := serviceAction("ssh", "explode"); err == nil {
		t.Fatal("bad action must error")
	}
	if hasCmd("systemctl") {
		if st := serviceState("no-such-unit-rmm-test"); st != "unknown" && st != "stopped" {
			t.Fatalf("unknown unit state %q", st)
		}
	}
}

func TestLinuxRealEventLog(t *testing.T) {
	if !hasCmd("journalctl") && !fileExists("/var/log/syslog") && !fileExists("/var/log/messages") {
		t.Skip("neither journalctl nor a syslog file")
	}
	es, err := queryEventLog(protocol.EventLogQuery{Limit: 20})
	if err != nil {
		if strings.Contains(err.Error(), "No journal files") || strings.Contains(err.Error(), "Permission") {
			t.Skipf("journal not readable here: %v", err)
		}
		t.Fatal(err)
	}
	if len(es) > 20 {
		t.Fatalf("limit ignored: %d", len(es))
	}
	for _, e := range es {
		if e.Level != "error" && e.Level != "warning" && e.Level != "info" {
			t.Fatalf("bad level %q", e.Level)
		}
	}
	t.Logf("%d journal entries (0 is fine in a fresh container)", len(es))
	if _, err := queryEventLog(protocol.EventLogQuery{Log: "kernel", Level: "error", Search: "foo (bar)", Limit: 5, SinceTS: time.Now().Add(-time.Hour).Unix()}); err != nil && !strings.Contains(err.Error(), "No journal") {
		t.Fatalf("filtered query: %v", err)
	}
	if _, err := queryEventLog(protocol.EventLogQuery{Log: "--since=yesterday"}); err == nil {
		t.Fatal("hostile Log selector must be rejected")
	}
	// the "unit or identifier" selector must be accepted by the real
	// journalctl as explicit matches (a syntax error here is exit 1 with
	// "Failed to add match" on stderr, which surfaces as an error)
	if hasCmd("journalctl") {
		if _, err := queryEventLog(protocol.EventLogQuery{Log: "sshd", Limit: 5}); err != nil && !strings.Contains(err.Error(), "No journal") {
			t.Fatalf("identifier scope: %v", err)
		}
	}
}

func TestLinuxTailFileLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "syslog")
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("Sep 15 03:56:01 host prog[1]: line " + strconv.Itoa(i) + "\n")
	}
	os.WriteFile(path, []byte(sb.String()), 0o600)
	lines, err := tailFileLines(path, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 || len(lines) > 60 || !strings.HasSuffix(lines[len(lines)-1], "line 999") {
		t.Fatalf("tail: %d lines, last %q", len(lines), lines[len(lines)-1])
	}
	if !strings.HasPrefix(lines[0], "Sep 15") {
		t.Fatalf("partial first line kept: %q", lines[0])
	}
	all, _ := tailFileLines(path, 1<<20)
	if len(all) != 1000 {
		t.Fatalf("small file: %d lines", len(all))
	}
}

func TestLinuxRealInventory(t *testing.T) {
	inv, err := collectInventory()
	if err != nil {
		t.Fatal(err)
	}
	if inv.Hostname == "" {
		t.Fatal("no hostname")
	}
	if len(inv.Disks) == 0 {
		t.Fatal("no disks")
	}
	if inv.Platform == "" || inv.KernelVer == "" {
		t.Fatalf("platform %q kernel %q", inv.Platform, inv.KernelVer)
	}
	if hasCmd("dpkg-query") || hasCmd("rpm") || hasCmd("pacman") {
		if len(inv.Software) == 0 {
			t.Fatal("package manager present but no software listed")
		}
	}
	if len(inv.Software) > maxSoftware {
		t.Fatalf("software cap: %d", len(inv.Software))
	}
	t.Logf("host=%s platform=%q disks=%d software=%d gpus=%v domain=%q extra=%v users=%v reboot=%v",
		inv.Hostname, inv.Platform, len(inv.Disks), len(inv.Software), inv.GPUs, inv.Domain, inv.Extra, inv.LoggedInUsers, inv.PendingReboot)
}

func TestLinuxPendingRebootAndUsers(t *testing.T) {
	start := time.Now()
	pr := pendingReboot()
	if time.Since(start) > 90*time.Second {
		t.Fatalf("pendingReboot took %s", time.Since(start))
	}
	// second call is served from the cache
	start = time.Now()
	pendingReboot()
	if time.Since(start) > time.Second {
		t.Fatalf("cached pendingReboot took %s", time.Since(start))
	}
	t.Logf("pending reboot: %v, users: %v", pr, loggedInUsers())
}

func TestLinuxPowerValidation(t *testing.T) {
	if err := powerAction(protocol.Power{Action: "explode"}); err == nil {
		t.Fatal("unknown action must error")
	}
	// a hostile delay must not wrap into an immediate action
	if clampDelay(-5) != 0 || clampDelay(30) != 30 || clampDelay(1<<62) != maxPowerDelay {
		t.Fatal("clampDelay")
	}
	if d := time.Duration(clampDelay(1<<62)) * time.Second; d <= 0 {
		t.Fatalf("clamped delay overflowed: %v", d)
	}
}

func TestLinuxJournalScope(t *testing.T) {
	for _, l := range []string{"", "System", "application", " ALL "} {
		if args, err := journalScope(l); err != nil || len(args) != 0 {
			t.Fatalf("journalScope(%q) = %v, %v", l, args, err)
		}
	}
	if args, _ := journalScope("kernel"); len(args) != 1 || args[0] != "-k" {
		t.Fatalf("kernel: %v", args)
	}
	if args, err := journalScope("sshd"); err != nil || args[0] != "_SYSTEMD_UNIT=sshd.service" || args[len(args)-1] != "_COMM=sshd" {
		t.Fatalf("identifier: %v %v", args, err)
	}
	for _, bad := range []string{"--since=yesterday", "-k", "a b", "/dev/sda", "x;y"} {
		if _, err := journalScope(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestLinuxRealScanUpdatesApt(t *testing.T) {
	if packageManager() != "apt" {
		t.Skipf("package manager is %q, not apt", packageManager())
	}
	if testing.Short() {
		t.Skip("-short: skipping apt-get update")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := scanUpdates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.LastScan == 0 {
		t.Fatal("LastScan unset")
	}
	if res.Error != "" {
		t.Logf("apt-get update reported: %s", firstLine(res.Error))
	}
	// cross-check against a direct simulation
	direct, _, _, err := runCmd(ctx, "apt-get", "-s", "-q", "-o", "Debug::NoLocking=true", "dist-upgrade")
	if err == nil {
		want := len(parseAptSimulate(direct))
		if want != len(res.Updates) {
			t.Fatalf("scan returned %d updates, direct simulation %d", len(res.Updates), want)
		}
	}
	for _, u := range res.Updates {
		if u.ID == "" || u.Version == "" || u.Source != "apt" || !validPkgID(u.ID) {
			t.Fatalf("malformed update %#v", u)
		}
	}
	t.Logf("%d apt updates available, reboot pending %v", len(res.Updates), res.RebootPending)

	// install path: only the validation branches, nothing is installed
	ires, err := installUpdates(ctx, protocol.UpdatesInstall{IDs: []string{"-y", "no-such-package-rmm-test", "pkg-"}}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(ires.Installed) != 0 || ires.Failed["-y"] != "invalid package id" || ires.Failed["pkg-"] != "invalid package id" || ires.Failed["no-such-package-rmm-test"] != "not an available update" {
		t.Fatalf("validation result: %#v", ires)
	}
}
