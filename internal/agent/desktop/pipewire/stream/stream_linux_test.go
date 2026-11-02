//go:build linux

package stream

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// These tests exercise the real mmap and eventfd code. They only run on Linux.

func TestLinuxSignalNotifyWaitAndCancel(t *testing.T) {
	sig := platformSignal()
	fd, err := newEventfd()
	if err != nil {
		t.Fatal(err)
	}
	defer sig.Close(fd)
	w, err := sig.Watch(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if err := sig.Notify(fd); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.Wait(ctx); err != nil {
		t.Fatalf("Wait after Notify: %v", err)
	}

	// The counter was reset, so Drain finds nothing and Wait blocks until the
	// context ends.
	if err := w.Drain(); err != nil {
		t.Fatal(err)
	}
	short, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	if err := w.Wait(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait with nothing pending = %v, want the context's deadline", err)
	}

	// A signal sent after a cancelled wait is still delivered.
	if err := sig.Notify(fd); err != nil {
		t.Fatal(err)
	}
	if err := w.Wait(ctx); err != nil {
		t.Fatalf("Wait after a cancelled wait: %v", err)
	}
	if n := sig.Now(); n <= 0 {
		t.Fatalf("Now = %d", n)
	}
}

func TestLinuxMemMapsSharedFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "mem")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m := platformMem()
	page := m.PageSize()
	if err := f.Truncate(int64(2 * page)); err != nil {
		t.Fatal(err)
	}
	size, err := m.Size(int(f.Fd()))
	if err != nil || size != int64(2*page) {
		t.Fatalf("Size = %d, %v", size, err)
	}
	b, err := m.Map(int(f.Fd()), int64(page), 100, true)
	if err != nil {
		t.Fatal(err)
	}
	b[0] = 42
	if err := m.Unmap(b); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := f.ReadAt(one[:], int64(page)); err != nil || one[0] != 42 {
		t.Fatalf("the write through the mapping is not in the file: %v %v", one, err)
	}
	if _, err := m.Map(int(f.Fd()), 1, 10, false); err == nil {
		t.Fatal("an unaligned offset was accepted")
	}
}

// Many waits on one context share a watcher; cancelling ends the current wait,
// and Close afterwards does not race the watcher's write to the wake eventfd.
func TestLinuxWaiterReusesWatcherAndClosesCleanly(t *testing.T) {
	sig := platformSignal()
	fd, err := newEventfd()
	if err != nil {
		t.Fatal(err)
	}
	defer sig.Close(fd)
	w, err := sig.Watch(fd)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < 50; i++ {
		if err := sig.Notify(fd); err != nil {
			t.Fatal(err)
		}
		if err := w.Wait(ctx); err != nil {
			t.Fatalf("Wait %d: %v", i, err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- w.Wait(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait after cancel = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after the context was cancelled")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
