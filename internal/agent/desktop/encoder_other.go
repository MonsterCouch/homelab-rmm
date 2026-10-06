//go:build !windows

package desktop

import "errors"

// errNoVideoEncoder is returned when the platform has no H.264 encoder wired
// in; the session then stays on the JPEG tile transport (WebRTC still
// negotiates its data channels for input, but carries no video track).
var errNoVideoEncoder = errors.New("no hardware video encoder on this platform")

// newVideoEncoder has no implementation off Windows yet. Linux hardware
// encoding (VA-API / NVENC) is a later task; until then a Linux helper
// offered WebRTC falls back to tiles for video.
func newVideoEncoder(width, height, fps, bitrateKbps int) (videoEncoder, error) {
	return nil, errNoVideoEncoder
}
