//go:build linux

package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// prepareCommand puts the child in its own process group and makes context
// cancellation kill that whole group, so a timed-out script cannot leave
// grandchildren holding our stdout pipe (or running) behind it.
func prepareCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid addresses the group. The child is its leader thanks to
		// Setpgid, so this reaches everything it spawned that did not setsid.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return cmd.Process.Kill()
		}
		return nil
	}
	// A grandchild that escaped the group via setsid could still hold the
	// pipes open; give up on it rather than hang Wait forever.
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = 5 * time.Second
	}
}

const (
	defaultLinuxMaxMemoryMB     uint64 = 1024
	defaultLinuxCPULimitPercent uint32 = 80
)

// superviseCommand is called once a command has started. On Linux,
// prepareCommand's process group covers the descendant tree at cancellation time.
func superviseCommand(cmd *exec.Cmd) (release func()) {
	return superviseSandboxedCommand(cmd, 0, 0)
}

// superviseSandboxedCommand applies resource limits (virtual memory ceiling via
// RLIMIT_AS and optional cgroups v2 resource quotas) to a started command on Linux.
func superviseSandboxedCommand(cmd *exec.Cmd, maxMemMB uint64, cpuPercent uint32) (release func()) {
	if cmd == nil || cmd.Process == nil {
		return func() {}
	}
	if maxMemMB == 0 {
		maxMemMB = defaultLinuxMaxMemoryMB
	}
	if cpuPercent == 0 {
		cpuPercent = defaultLinuxCPULimitPercent
	}

	pid := cmd.Process.Pid
	memBytes := maxMemMB * 1024 * 1024

	// 1. Enforce hard memory limit via RLIMIT_AS (virtual address space) on the child process.
	rlim := unix.Rlimit{
		Cur: memBytes,
		Max: memBytes,
	}
	if err := unix.Prlimit(pid, unix.RLIMIT_AS, &rlim, nil); err != nil {
		slog.Debug("could not set RLIMIT_AS on process", "pid", pid, "limit_mb", maxMemMB, "err", err)
	}

	// 2. Optionally configure cgroup v2 if available on the host.
	cgDir := attachLinuxCgroup(pid, memBytes, cpuPercent)

	return func() {
		if cgDir != "" {
			_ = os.Remove(cgDir)
		}
	}
}

func attachLinuxCgroup(pid int, memBytes uint64, cpuPercent uint32) string {
	cgroupRoot := "/sys/fs/cgroup"
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return ""
	}
	cgDir := filepath.Join(cgroupRoot, "homelab-rmm", fmt.Sprintf("proc-%d", pid))
	if err := os.MkdirAll(cgDir, 0o755); err != nil {
		return ""
	}
	_ = os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
	_ = os.WriteFile(filepath.Join(cgDir, "memory.max"), []byte(strconv.FormatUint(memBytes, 10)), 0o644)
	if cpuPercent > 0 && cpuPercent <= 100 {
		quota := uint64(cpuPercent) * 1000
		_ = os.WriteFile(filepath.Join(cgDir, "cpu.max"), []byte(fmt.Sprintf("%d 100000", quota)), 0o644)
	}
	return cgDir
}
