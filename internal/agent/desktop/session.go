package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"log/slog"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Timing and flow-control constants. They are the knobs a future tuning
// pass would touch, so they live together.
const (
	maxInflight      = 2  // frames sent but not yet acked (protocol)
	maxCaptureFails  = 25 // consecutive failures before giving up (~5 s)
	writeTimeout     = 15 * time.Second
	readLimit        = 1 << 20 // viewer messages are small; anything bigger is hostile
	inputQueue       = 512
	viewerMaxMonitor = maxMonitors
)

// Timings are variables so tests can shrink them; production never writes
// them.
var (
	ackTimeout       = 5 * time.Second        // a lost ack must not stall the stream forever
	minFrameInterval = 50 * time.Millisecond  // ~20 fps cap
	idlePoll         = 100 * time.Millisecond // ~10 Hz re-check when nothing changed
	monitorRecheck   = 1 * time.Second        // how often display geometry is re-read
	captureRetry     = 200 * time.Millisecond // pause after a failed capture

	// Liveness. The relay never pings the helper and a static screen sends
	// nothing, so without our own pings a link that died silently (the
	// operator's laptop went to sleep, a NAT entry expired) would leave the
	// helper alive in the user's session forever. The server's gorilla
	// reader answers pings automatically even though it never forwards
	// them, so a missing pong means the helper<->server hop is gone.
	pingInterval = 20 * time.Second
	readTimeout  = 60 * time.Second // three missed pongs
)

// session is one helper <-> viewer stream.
type session struct {
	ws  *websocket.Conn
	wmu sync.Mutex

	cap capturer
	inj injector

	quality atomic.Int32

	// reader -> capture loop
	ctl   chan viewerMsg // monitor / refresh
	acked atomic.Uint32  // highest frame id the viewer acknowledged
	ackCh chan struct{}  // signalled (coalesced) on every ack

	// reader + capture loop -> input loop
	inputs chan viewerMsg

	encoders int
	bufPool  sync.Pool
}

func newSession(ws *websocket.Conn, cap capturer, inj injector, quality int) *session {
	s := &session{
		ws:       ws,
		cap:      cap,
		inj:      inj,
		ctl:      make(chan viewerMsg, 16),
		ackCh:    make(chan struct{}, 1),
		inputs:   make(chan viewerMsg, inputQueue),
		encoders: max(1, runtime.NumCPU()),
	}
	s.bufPool.New = func() any { return new(bytes.Buffer) }
	s.setQuality(quality)
	return s
}

func (s *session) setQuality(q int) {
	if q < minQuality {
		q = 60 // the protocol default; 0 means "unset", not "worst"
	}
	if q > maxQuality {
		q = maxQuality
	}
	s.quality.Store(int32(q))
}

// run drives the three goroutines (reader, input, capture) until the socket
// closes, ctx ends, or capture fails for good. It returns nil for a normal
// end (peer closed / ctx cancelled) and the fatal error otherwise.
func (s *session) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		defer cancel()
		s.readLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		s.pingLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		// The input backend is thread-affine (X connection state, the
		// Windows thread desktop), so this goroutine owns one OS thread for
		// its whole life; never unlocking makes Go retire the thread.
		runtime.LockOSThread()
		s.inputLoop(ctx)
	}()

	capErr := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		capErr <- s.captureLoop(ctx)
	}()

	var err error
	select {
	case err = <-capErr:
	case <-ctx.Done():
		err = <-capErr
	}
	if err != nil && ctx.Err() == nil {
		slog.Error("desktop capture stopped", "err", err)
		s.sendJSON(map[string]string{"t": "error", "message": err.Error()})
	}
	cancel()
	// Unblock the reader: closing the socket makes ReadMessage return.
	s.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	s.ws.Close()
	wg.Wait()
	if ctx.Err() != nil && err == nil {
		return nil
	}
	return err
}

// ---- writing ----

func (s *session) send(mt int, data []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.ws.SetWriteDeadline(time.Now().Add(writeTimeout))
	return s.ws.WriteMessage(mt, data)
}

func (s *session) sendJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.send(websocket.TextMessage, b)
}

// ---- reader ----

// pingLoop keeps the link's liveness observable: a ping every pingInterval,
// whose pong (or any other inbound frame) extends the read deadline that
// readLoop otherwise lets expire. WriteControl is safe alongside the data
// writer, so no lock is needed.
func (s *session) pingLoop(ctx context.Context) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout)); err != nil {
				return // the socket is gone; readLoop ends the session
			}
		}
	}
}

// readLoop parses viewer messages and routes them: acks and quality are
// applied immediately, monitor/refresh go to the capture loop, everything
// else is input for the injector thread. It returns when the socket dies
// or stays silent (no pong, no input) for readTimeout.
func (s *session) readLoop(ctx context.Context) {
	s.ws.SetReadLimit(readLimit)
	// Both the pong handler and the loop body run on this goroutine
	// (gorilla invokes handlers from inside ReadMessage), so the deadline
	// is only ever touched from here.
	s.ws.SetReadDeadline(time.Now().Add(readTimeout))
	s.ws.SetPongHandler(func(string) error {
		return s.ws.SetReadDeadline(time.Now().Add(readTimeout))
	})
	for {
		mt, data, err := s.ws.ReadMessage()
		if err != nil {
			if ctx.Err() == nil && !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
				slog.Info("desktop viewer disconnected", "err", err)
			}
			return
		}
		s.ws.SetReadDeadline(time.Now().Add(readTimeout))
		if mt != websocket.TextMessage {
			continue // the viewer never sends binary; ignore rather than trust it
		}
		var msg viewerMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			slog.Debug("desktop: bad viewer message", "err", err)
			continue
		}
		switch msg.T {
		case msgAck:
			f := uint32(clampInt(msg.Frame, 0, math.MaxInt32))
			for {
				cur := s.acked.Load()
				if f <= cur || s.acked.CompareAndSwap(cur, f) {
					break
				}
			}
			select {
			case s.ackCh <- struct{}{}:
			default:
			}
		case msgQuality:
			s.setQuality(clampInt(msg.Q, 0, maxQuality))
		case msgMonitor, msgRefresh:
			select {
			case s.ctl <- msg:
			case <-ctx.Done():
				return
			}
		case msgMouseMove, msgMouseDown, msgMouseUp, msgWheel, msgKeyDown, msgKeyUp, msgPaste, msgCtrlAltDel:
			s.queueInput(ctx, msg)
		default:
			slog.Debug("desktop: unknown viewer message", "t", msg.T)
		}
	}
}

// queueInput hands a message to the injector thread. When the queue is full
// (the injector is stuck behind a desktop switch, say) pointer moves are
// dropped because a later one supersedes them, but clicks and keys are never
// lost: those block until there is room.
func (s *session) queueInput(ctx context.Context, msg viewerMsg) {
	select {
	case s.inputs <- msg:
		return
	default:
	}
	if msg.T == msgMouseMove {
		return
	}
	select {
	case s.inputs <- msg:
	case <-ctx.Done():
	}
}

// ---- input ----

func (s *session) inputLoop(ctx context.Context) {
	td := newThreadDesktop()
	defer td.close()
	var cur monitor // the monitor viewer coordinates refer to
	for {
		var msg viewerMsg
		select {
		case <-ctx.Done():
			return
		case msg = <-s.inputs:
		}
		if msg.mon != nil {
			cur = *msg.mon
			s.inj.setMonitor(cur)
			continue
		}
		if cur.Bounds.Empty() {
			continue // nothing on screen yet; there is nowhere to click
		}
		if err := s.inject(td, cur, msg); err != nil {
			slog.Debug("desktop: input rejected", "t", msg.T, "err", err)
		}
	}
}

func (s *session) inject(td *threadDesktop, cur monitor, msg viewerMsg) error {
	td.follow()
	x, y := clampPoint(msg.X, msg.Y, cur.Bounds)
	switch msg.T {
	case msgMouseMove:
		return s.inj.mouseMove(x, y)
	case msgMouseDown, msgMouseUp:
		b := clampInt(msg.Button, buttonLeft, buttonRight)
		return s.inj.mouseButton(b, msg.T == msgMouseDown, x, y)
	case msgWheel:
		return s.inj.wheel(msg.DX, msg.DY, x, y)
	case msgKeyDown, msgKeyUp:
		return s.inj.key(msg.Code, msg.Key, msg.T == msgKeyDown)
	case msgPaste:
		text := msg.Text
		if r := []rune(text); len(r) > maxPasteLen {
			text = string(r[:maxPasteLen])
		}
		return s.inj.paste(text)
	case msgCtrlAltDel:
		return s.inj.ctrlAltDel()
	}
	return nil
}

// ---- capture ----

// captureLoop is the producer: enumerate, capture, diff, encode, send, and
// respect the viewer's flow control. It never returns while the stream is
// healthy.
func (s *session) captureLoop(ctx context.Context) error {
	td := newThreadDesktop()
	defer td.close()

	var (
		mons       []monitor
		monsAt     time.Time
		want       = 0 // monitor index the viewer asked for
		cur        monitor
		haveCur    bool
		prev       *image.RGBA
		full       = true // next frame covers the whole monitor
		needScreen = true // next frame is preceded by a "screen" message
		frameID    uint32
		lastSent   uint32
		lastCap    time.Time
		fails      int
	)

	applyCtl := func(msg viewerMsg) {
		switch msg.T {
		case msgRefresh:
			full = true
		case msgMonitor:
			idx := clampInt(msg.Index, 0, viewerMaxMonitor-1)
			if idx != want {
				want = idx
				needScreen, full = true, true
				monsAt = time.Time{} // re-enumerate now
			}
		}
	}
	drainCtl := func() {
		for {
			select {
			case msg := <-s.ctl:
				applyCtl(msg)
			default:
				return
			}
		}
	}
	// wait sleeps for d, but returns early for control messages (which it
	// applies) or cancellation. It reports false when ctx ended.
	wait := func(d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return false
			case msg := <-s.ctl:
				applyCtl(msg)
				return true
			case <-t.C:
				return true
			}
		}
	}

	for {
		if ctx.Err() != nil {
			return nil
		}
		drainCtl()

		// Display geometry: cheap on Windows, a few X round trips on Linux,
		// so re-read on a timer rather than every frame.
		if mons == nil || time.Since(monsAt) > monitorRecheck {
			m, err := s.cap.monitors()
			if err != nil {
				fails++
				if fails > maxCaptureFails {
					return fmt.Errorf("enumerate displays: %w", err)
				}
				slog.Debug("desktop: enumerate displays", "err", err)
				if !wait(captureRetry) {
					return nil
				}
				continue
			}
			if len(m) != len(mons) && mons != nil {
				// A display was plugged or unplugged: the viewer's monitor
				// list is stale even if the current one is unchanged.
				needScreen, full = true, true
			}
			mons, monsAt = m, time.Now()
			idx := want
			if idx >= len(mons) {
				idx = 0
			}
			if !haveCur || mons[idx].Bounds != cur.Bounds || mons[idx].Index != cur.Index {
				if haveCur {
					slog.Info("desktop: display changed", "monitor", idx, "bounds", mons[idx].Bounds)
				}
				cur, haveCur = mons[idx], true
				needScreen, full = true, true
				m := cur
				s.queueInput(ctx, viewerMsg{mon: &m})
			}
		}

		// Flow control: at most maxInflight frames without an ack.
		for lastSent-s.ackedClamped(lastSent) >= maxInflight {
			t := time.NewTimer(ackTimeout)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case msg := <-s.ctl:
				applyCtl(msg)
			case <-s.ackCh:
			case <-t.C:
				slog.Warn("desktop: no ack from viewer, resuming", "unacked", lastSent-s.ackedClamped(lastSent))
				s.acked.Store(lastSent)
			}
			t.Stop()
		}

		// Frame-rate cap.
		if d := minFrameInterval - time.Since(lastCap); d > 0 {
			if !wait(d) {
				return nil
			}
		}

		if monsAt.IsZero() {
			// A monitor switch arrived while we were waiting (flow control
			// or the frame-rate cap): re-enumerate before capturing so the
			// next frame is the monitor the viewer asked for, not the old
			// one with a stale "screen" message.
			continue
		}

		td.follow()
		img, err := s.cap.capture(cur)
		lastCap = time.Now()
		if err != nil {
			fails++
			if fails > maxCaptureFails {
				return err
			}
			slog.Debug("desktop: capture failed", "err", err, "consecutive", fails)
			mons = nil // geometry may have changed under us
			if !wait(captureRetry) {
				return nil
			}
			continue
		}
		fails = 0
		if img.Rect.Dx() != cur.Bounds.Dx() || img.Rect.Dy() != cur.Bounds.Dy() {
			// The backend disagrees with what it enumerated a moment ago:
			// the mode changed mid-flight. Re-enumerate before trusting it.
			mons = nil
			continue
		}

		if needScreen {
			if err := s.sendJSON(newScreenMsg(mons, cur.Index)); err != nil {
				return fmt.Errorf("send screen: %w", err)
			}
			needScreen = false
			full = true
		}

		var rects []image.Rectangle
		if full {
			rects = fullRects(image.Rect(0, 0, img.Rect.Dx(), img.Rect.Dy()))
		} else {
			rects = diffRects(prev, img)
		}
		prev = img
		full = false
		if len(rects) == 0 {
			if !wait(idlePoll) {
				return nil
			}
			continue
		}

		frameID++
		if err := s.sendFrame(ctx, frameID, img, rects); err != nil {
			return err
		}
		lastSent = frameID
	}
}

// ackedClamped returns the acked frame id, never above what was sent, so a
// viewer that acks frames from the future cannot open the window wider.
func (s *session) ackedClamped(lastSent uint32) uint32 {
	a := s.acked.Load()
	if a > lastSent {
		return lastSent
	}
	return a
}

// sendFrame encodes every rectangle (in parallel, bounded by the CPU count)
// and writes the tiles as they complete, then the frame-end marker.
func (s *session) sendFrame(ctx context.Context, frameID uint32, img *image.RGBA, rects []image.Rectangle) error {
	quality := int(s.quality.Load())
	type result struct {
		buf *bytes.Buffer
		err error
	}
	results := make(chan result, len(rects))
	sem := make(chan struct{}, s.encoders)
	for _, r := range rects {
		sem <- struct{}{}
		go func(r image.Rectangle) {
			defer func() { <-sem }()
			buf, err := s.encodeTile(img, r, quality)
			results <- result{buf, err}
		}(r)
	}
	var firstErr error
	for range rects {
		res := <-results
		if res.err != nil {
			// One bad tile (a rectangle the encoder rejected) must not
			// kill the session; the area is simply re-sent next diff.
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		err := s.send(websocket.BinaryMessage, res.buf.Bytes())
		res.buf.Reset()
		s.bufPool.Put(res.buf)
		if err != nil {
			return fmt.Errorf("send tile: %w", err)
		}
	}
	if firstErr != nil {
		slog.Warn("desktop: tile encode failed", "err", firstErr)
	}
	if err := s.send(websocket.BinaryMessage, encodeFrameEnd(frameID)); err != nil {
		return fmt.Errorf("send frame end: %w", err)
	}
	return ctx.Err()
}

// encodeTile produces a complete tile message (header + JPEG) in a pooled
// buffer. The sub-image shares img's pixels, so no copy is made.
func (s *session) encodeTile(img *image.RGBA, r image.Rectangle, quality int) (*bytes.Buffer, error) {
	if r.Min.X < 0 || r.Min.Y < 0 || r.Dx() <= 0 || r.Dy() <= 0 || r.Max.X > maxTileCoordinate || r.Max.Y > maxTileCoordinate {
		return nil, fmt.Errorf("tile rectangle %v does not fit the wire format", r)
	}
	sub, ok := img.SubImage(r.Add(img.Rect.Min)).(*image.RGBA)
	if !ok || sub.Rect.Empty() {
		return nil, errors.New("tile outside the captured image")
	}
	buf := s.bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(tileHeaderLen + r.Dx()*r.Dy()/4)
	var hdr [tileHeaderLen]byte
	putTileHeader(hdr[:], r, codecJPEG)
	buf.Write(hdr[:])
	if err := jpeg.Encode(buf, sub, &jpeg.Options{Quality: quality}); err != nil {
		buf.Reset()
		s.bufPool.Put(buf)
		return nil, fmt.Errorf("jpeg: %w", err)
	}
	return buf, nil
}
