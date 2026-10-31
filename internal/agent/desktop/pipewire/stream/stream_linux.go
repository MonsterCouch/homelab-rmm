//go:build linux

package stream

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func platformMem() Mem       { return linuxMem{} }
func platformSignal() Signal { return linuxSignal{} }

// linuxMem maps memfds with mmap.
type linuxMem struct{}

func (linuxMem) PageSize() int { return os.Getpagesize() }

func (linuxMem) Size(fd int) (int64, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return 0, err
	}
	return st.Size, nil
}

func (linuxMem) Map(fd int, offset, length int64, write bool) ([]byte, error) {
	prot := syscall.PROT_READ
	if write {
		prot |= syscall.PROT_WRITE
	}
	return syscall.Mmap(fd, offset, int(length), prot, syscall.MAP_SHARED)
}

func (linuxMem) Unmap(b []byte) error { return syscall.Munmap(b) }

// linuxSignal uses eventfds and epoll.
type linuxSignal struct{}

func newEventfd() (int, error) {
	fd, _, errno := syscall.RawSyscall(syscall.SYS_EVENTFD2, 0, uintptr(syscall.O_CLOEXEC|syscall.O_NONBLOCK), 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func (linuxSignal) Notify(fd int) error {
	var buf [8]byte
	binary.NativeEndian.PutUint64(buf[:], 1)
	for {
		_, err := syscall.Write(fd, buf[:])
		if err == syscall.EINTR {
			continue
		}
		return err
	}
}

func (linuxSignal) Close(fd int) error { return syscall.Close(fd) }

// Now reads CLOCK_MONOTONIC, the clock the activation timestamps use.
func (linuxSignal) Now() int64 {
	var ts syscall.Timespec
	const clockMonotonic = 1
	if _, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonic, uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		return 0
	}
	return ts.Nano()
}

func (linuxSignal) Watch(fd int) (Waiter, error) {
	ep, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("epoll_create1 failed: %w", err)
	}
	wake, err := newEventfd()
	if err != nil {
		syscall.Close(ep)
		return nil, fmt.Errorf("eventfd failed: %w", err)
	}
	for _, f := range []int{fd, wake} {
		ev := syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(f)}
		if err := syscall.EpollCtl(ep, syscall.EPOLL_CTL_ADD, f, &ev); err != nil {
			syscall.Close(ep)
			syscall.Close(wake)
			return nil, fmt.Errorf("epoll_ctl failed: %w", err)
		}
	}
	return &linuxWaiter{fd: fd, ep: ep, wake: wake}, nil
}

// linuxWaiter waits for fd or for its own wake eventfd, which a cancelled
// context writes to. One watcher goroutine serves the context of the current
// Wait calls (the stream uses the same context for every cycle), and Close
// joins it before the descriptors are closed, so a late write can never hit a
// closed or reused descriptor number.
type linuxWaiter struct {
	fd, ep, wake int

	// events is reused by every Wait; a Waiter is used from one goroutine.
	events [2]syscall.EpollEvent

	watchCtx context.Context
	quit     chan struct{}
	joined   chan struct{}
}

// watch makes sure the watcher goroutine belongs to ctx.
func (w *linuxWaiter) watch(ctx context.Context) {
	if w.watchCtx == ctx {
		return
	}
	w.unwatch()
	// A cancelled context may have written to the wake eventfd while the old
	// watcher was running; it is joined now, so this read cannot race it.
	_, _ = readCounter(w.wake)
	if ctx.Done() == nil {
		w.watchCtx = ctx
		return
	}
	w.watchCtx = ctx
	w.quit = make(chan struct{})
	w.joined = make(chan struct{})
	go func(quit, joined chan struct{}) {
		defer close(joined)
		select {
		case <-ctx.Done():
			_ = linuxSignal{}.Notify(w.wake)
		case <-quit:
		}
	}(w.quit, w.joined)
}

// unwatch stops the watcher goroutine and waits for it.
func (w *linuxWaiter) unwatch() {
	if w.quit != nil {
		close(w.quit)
		<-w.joined
		w.quit, w.joined = nil, nil
	}
	w.watchCtx = nil
}

// readCounter reads the 8-byte eventfd counter. ok is false when nothing was
// pending.
func readCounter(fd int) (ok bool, err error) {
	var buf [8]byte
	for {
		n, err := syscall.Read(fd, buf[:])
		switch {
		case err == syscall.EINTR:
			continue
		case err == syscall.EAGAIN:
			return false, nil
		case err != nil:
			return false, err
		case n != 8:
			return false, errors.New("short read from an eventfd")
		}
		return true, nil
	}
}

func (w *linuxWaiter) Drain() error {
	_, err := readCounter(w.fd)
	return err
}

func (w *linuxWaiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.watch(ctx)
	for {
		n, err := syscall.EpollWait(w.ep, w.events[:], -1)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("epoll_wait failed: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, ev := range w.events[:n] {
			if int(ev.Fd) != w.fd {
				continue
			}
			ok, err := readCounter(w.fd)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
	}
}

func (w *linuxWaiter) Close() error {
	w.unwatch()
	e1 := syscall.Close(w.ep)
	e2 := syscall.Close(w.wake)
	if e1 != nil {
		return e1
	}
	return e2
}
