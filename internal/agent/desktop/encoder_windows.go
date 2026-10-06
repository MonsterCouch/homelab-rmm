//go:build windows

package desktop

import "errors"

// errNoVideoEncoder is returned when no usable H.264 encoder MFT can be
// created; the session then stays on the JPEG tile transport.
var errNoVideoEncoder = errors.New("no H.264 encoder available")

// newVideoEncoder returns a Media Foundation H.264 encoder for width×height
// frames. This is the seam the MFT implementation (encoder_mft_windows.go)
// fills in; the stub keeps the package building until it lands.
//
// NOTE: placeholder — replaced by the Media Foundation implementation.
func newVideoEncoder(width, height, fps, bitrateKbps int) (videoEncoder, error) {
	return newMFTEncoder(width, height, fps, bitrateKbps)
}
