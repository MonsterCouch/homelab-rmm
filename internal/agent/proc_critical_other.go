//go:build !windows

package agent

// isCriticalProcess is the non-Windows half of the hook implemented in
// proc_critical_windows.go. Unix has no per-process "the kernel panics
// without me" flag; pid 1 is the only such process and killProcess refuses it
// by pid.
func isCriticalProcess(pid int32) bool { return false }
