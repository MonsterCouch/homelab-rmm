//go:build windows

package desktop

// newCapturer returns the Windows capture backend: DXGI Desktop Duplication
// with an automatic fall back to GDI BitBlt (kbinani/screenshot) for the
// cases duplication cannot serve - Session 0, headless VMs without a virtual
// GPU, rotated outputs and the secure desktop. See capture_dxgi_windows.go.
func newCapturer() capturer { return newDXGICapturer() }
