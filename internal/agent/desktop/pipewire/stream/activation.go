package stream

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"unsafe"
)

// Layout of struct pw_node_activation (PipeWire 1.2.7, x86-64), from the
// protocol notes, section 4.5. Offsets are in bytes from the start of the
// activation block.
const (
	actSize          = 2312
	actStatus        = 0   // u32, accessed atomically
	actState0Status  = 8   // i32, state[0].status
	actState0Pending = 16  // i32, state[0].pending
	actSignalTime    = 32  // u64 ns
	actAwakeTime     = 40  // u64 ns
	actFinishTime    = 48  // u64 ns
	actClientVersion = 540 // u32
)

// Activation status values (private.h).
const (
	actNotTriggered uint32 = 0
	actTriggered    uint32 = 1
	actAwake        uint32 = 2
	actFinished     uint32 = 3
	actInactive     uint32 = 4
)

// Status values of struct spa_io_buffers and of a node's process result
// (spa/node/io.h).
const (
	statusNeedData int32 = 1 << 0
	statusHaveData int32 = 1 << 1
)

// struct spa_io_buffers is {int32 status, uint32 buffer_id}.
const (
	ioBuffersSize     = 8
	ioBuffersStatus   = 0
	ioBuffersBufferID = 4
)

// atomicWord returns a pointer to the 4 bytes at b[off:] for use with
// sync/atomic. The caller has checked alignment with aligned4.
func atomicWord(b []byte, off int) *uint32 {
	return (*uint32)(unsafe.Pointer(&b[off]))
}

func atomicInt(b []byte, off int) *int32 {
	return (*int32)(unsafe.Pointer(&b[off]))
}

// aligned4 reports whether &b[off] can be used with sync/atomic on 32-bit
// words.
func aligned4(b []byte, off int) bool {
	if off < 0 || off+4 > len(b) {
		return false
	}
	return uintptr(unsafe.Pointer(&b[off]))%4 == 0
}

// checkAtomic returns an error when the offsets the process loop touches in
// a block are not usable with atomic operations.
func checkAtomic(what string, b []byte, offs ...int) error {
	for _, off := range offs {
		if !aligned4(b, off) {
			return fmt.Errorf("the %s memory is not 4-byte aligned at offset %d, so it cannot be shared safely with the server", what, off)
		}
	}
	return nil
}

func putU64(b []byte, off int, v uint64) {
	binary.LittleEndian.PutUint64(b[off:], v)
}

func casStatus(b []byte, from, to uint32) bool {
	return atomic.CompareAndSwapUint32(atomicWord(b, actStatus), from, to)
}
