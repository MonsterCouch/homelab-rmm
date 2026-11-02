package desktop

import "image"

// videoFrame is one captured picture on its way to the video encoder. A
// capture backend that keeps frames in GPU memory (Windows Desktop
// Duplication) fills gpu and leaves rgba nil, so pixels never visit system
// RAM on the WebRTC path; every other backend fills rgba and the encoder
// uploads it.
type videoFrame struct {
	rgba  *image.RGBA
	gpu   any // platform handle (windows: *gpuSurface); nil when rgba is set
	w, h  int
	fresh bool // pixels changed since the previous frame handed out
}

// dirtyProvider is implemented by capture backends whose driver reports
// which regions changed. takeDirty returns the rectangles for the frame the
// last capture() produced; ok is false when the backend cannot say for that
// frame (it fell back to another engine), in which case the session diffs
// the pixels itself.
type dirtyProvider interface {
	takeDirty() (rects []image.Rectangle, ok bool)
}

// frameSource is implemented by capture backends that can hand the encoder a
// GPU-resident frame.
type frameSource interface {
	captureFrame(m monitor) (videoFrame, error)
}

// videoEncoder turns frames into an H.264 Annex B access unit. Encode is
// called from the capture goroutine only; ForceKeyframe may be called from
// any goroutine (it is driven by RTCP picture-loss feedback) and takes effect
// on the next Encode.
type videoEncoder interface {
	// Encode returns the encoded access unit (nil when the encoder is still
	// buffering) and whether it is an IDR frame.
	Encode(f videoFrame) (nal []byte, keyframe bool, err error)
	ForceKeyframe() error
	Close() error
}
