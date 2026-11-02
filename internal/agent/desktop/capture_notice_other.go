//go:build !linux

package desktop

// capturerSetupNotice: only the Linux Wayland portal can wait for a person
// during capturer set-up.
func capturerSetupNotice() string { return "" }
