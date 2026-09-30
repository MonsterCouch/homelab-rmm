//go:build !windows

package desktop

import (
	"os/exec"
)

// showBanner provides a fallback notification on non-Windows desktop environments.
func showBanner() func() {
	if path, err := exec.LookPath("notify-send"); err == nil && path != "" {
		_ = exec.Command(path, "-a", "Homelab RMM", "IT Support Connected", "An administrator has started a remote desktop session.").Run()
		return func() {
			_ = exec.Command(path, "-a", "Homelab RMM", "IT Support Disconnected", "The remote desktop session has ended.").Run()
		}
	}
	return func() {}
}
