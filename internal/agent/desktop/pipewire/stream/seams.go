package stream

import "context"

// Mem maps the memory blocks the PipeWire server shares as file descriptors.
// The Linux implementation uses mmap; MemFiles is the in-memory one used by
// tests.
type Mem interface {
	// PageSize is the alignment Map needs for its offset argument.
	PageSize() int
	// Size returns the size in bytes of the file behind fd (fstat).
	Size(fd int) (int64, error)
	// Map maps length bytes of fd starting at offset, which is a multiple of
	// PageSize. The mapping is shared with the server and writable when
	// write is true.
	Map(fd int, offset, length int64, write bool) ([]byte, error)
	// Unmap releases a slice returned by Map.
	Unmap(b []byte) error
}

// Waiter waits on one eventfd. The stream creates one for the node's wake-up
// descriptor and uses it from a single goroutine.
type Waiter interface {
	// Wait blocks until the eventfd has been signalled, reads its 8-byte
	// counter (which resets it) and returns. It returns ctx.Err() when the
	// context ends first.
	Wait(ctx context.Context) error
	// Drain discards a pending signal without blocking.
	Drain() error
	// Close releases what Watch allocated. It does not close the eventfd and
	// must not be called while Wait is running.
	Close() error
}

// Signal is the eventfd side of the node: waiting for the driver, waking a
// peer, closing descriptors the server handed over and reading the clock the
// activation timestamps use.
type Signal interface {
	// Watch returns a Waiter for the eventfd fd.
	Watch(fd int) (Waiter, error)
	// Notify adds 1 to the eventfd's counter (an 8-byte write).
	Notify(fd int) error
	// Close closes a descriptor the stream owns.
	Close(fd int) error
	// Now returns the monotonic clock in nanoseconds (CLOCK_MONOTONIC on
	// Linux). It only feeds the timestamps in the activation block.
	Now() int64
}
