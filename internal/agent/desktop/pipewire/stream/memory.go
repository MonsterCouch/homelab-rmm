package stream

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemFiles is an in-memory Mem. A "file descriptor" is any integer the test
// registered with Add. Map returns a slice that aliases the registered bytes,
// so a fake server and the stream see each other's writes, the way two
// processes see a shared mapping. Like mmap, Map rejects an offset that is
// not a multiple of the page size.
type MemFiles struct {
	mu    sync.Mutex
	page  int
	files map[int][]byte
	live  map[*byte]int
}

// NewMemFiles returns an empty MemFiles with a 4096-byte page.
func NewMemFiles() *MemFiles {
	return &MemFiles{page: 4096, files: map[int][]byte{}, live: map[*byte]int{}}
}

// Add registers the contents behind fd. The slice is not copied.
func (m *MemFiles) Add(fd int, data []byte) {
	m.mu.Lock()
	m.files[fd] = data
	m.mu.Unlock()
}

// Mapped returns how many mappings have not been unmapped yet.
func (m *MemFiles) Mapped() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.live {
		n += c
	}
	return n
}

// PageSize implements Mem.
func (m *MemFiles) PageSize() int { return m.page }

// Size implements Mem.
func (m *MemFiles) Size(fd int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.files[fd]
	if !ok {
		return 0, fmt.Errorf("file descriptor %d is not a known memory file", fd)
	}
	return int64(len(d)), nil
}

// Map implements Mem.
func (m *MemFiles) Map(fd int, offset, length int64, write bool) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.files[fd]
	if !ok {
		return nil, fmt.Errorf("file descriptor %d is not a known memory file", fd)
	}
	if offset < 0 || offset%int64(m.page) != 0 {
		return nil, fmt.Errorf("mapping offset %d is not a multiple of the page size %d", offset, m.page)
	}
	if length <= 0 || offset+length > int64(len(d)) {
		return nil, fmt.Errorf("mapping %d bytes at offset %d runs past the %d byte file", length, offset, len(d))
	}
	b := d[offset : offset+length : offset+length]
	m.live[&b[0]]++
	return b, nil
}

// Unmap implements Mem.
func (m *MemFiles) Unmap(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("unmapping an empty slice")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live[&b[0]] == 0 {
		return fmt.Errorf("unmapping a slice that is not mapped")
	}
	m.live[&b[0]]--
	if m.live[&b[0]] == 0 {
		delete(m.live, &b[0])
	}
	return nil
}

// memEvent is one in-memory eventfd.
type memEvent struct {
	count uint64
	wake  chan struct{}
}

// MemSignals is an in-memory Signal. Eventfds are plain integers created on
// first use; the counter semantics match a non-blocking eventfd. It records
// the descriptors passed to Close.
type MemSignals struct {
	mu     sync.Mutex
	events map[int]*memEvent
	closed []int
	start  time.Time
}

// NewMemSignals returns an empty MemSignals.
func NewMemSignals() *MemSignals {
	return &MemSignals{events: map[int]*memEvent{}, start: time.Now()}
}

func (m *MemSignals) event(fd int) *memEvent {
	e := m.events[fd]
	if e == nil {
		e = &memEvent{wake: make(chan struct{}, 1)}
		m.events[fd] = e
	}
	return e
}

// Notify implements Signal.
func (m *MemSignals) Notify(fd int) error {
	m.mu.Lock()
	e := m.event(fd)
	e.count++
	m.mu.Unlock()
	select {
	case e.wake <- struct{}{}:
	default:
	}
	return nil
}

// Close implements Signal and records fd.
func (m *MemSignals) Close(fd int) error {
	m.mu.Lock()
	m.closed = append(m.closed, fd)
	m.mu.Unlock()
	return nil
}

// Closed returns the descriptors closed so far, in order.
func (m *MemSignals) Closed() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]int(nil), m.closed...)
}

// Now implements Signal. It counts up from 1 so a timestamp is never 0.
func (m *MemSignals) Now() int64 { return int64(time.Since(m.start)) + 1 }

// Wait blocks until fd has been signalled and resets it. A test uses it to
// wait for the stream to wake a peer.
func (m *MemSignals) Wait(ctx context.Context, fd int) error {
	w, _ := m.Watch(fd)
	return w.Wait(ctx)
}

// Watch implements Signal.
func (m *MemSignals) Watch(fd int) (Waiter, error) {
	m.mu.Lock()
	e := m.event(fd)
	m.mu.Unlock()
	return &memWaiter{m: m, e: e}, nil
}

type memWaiter struct {
	m *MemSignals
	e *memEvent
}

func (w *memWaiter) take() bool {
	w.m.mu.Lock()
	defer w.m.mu.Unlock()
	if w.e.count == 0 {
		return false
	}
	w.e.count = 0
	return true
}

func (w *memWaiter) Wait(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if w.take() {
			return nil
		}
		select {
		case <-w.e.wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (w *memWaiter) Drain() error {
	w.take()
	return nil
}

func (w *memWaiter) Close() error { return nil }
