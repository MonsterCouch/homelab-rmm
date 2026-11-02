package stream

import (
	"fmt"
	"sync/atomic"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/proto"
)

// maxMapSize bounds one mapping. A 8K frame with 4 bytes per pixel is about
// 127 MB; a server asking for more than 1 GiB is not sending a video buffer.
const maxMapSize = 1 << 30

// memFlagWritable is PW_MEMBLOCK_FLAG_WRITABLE (mem.h).
const memFlagWritable uint32 = 2

// writeMode says how a mapping may be opened.
type writeMode int

const (
	mapRead     writeMode = iota // read only
	mapReadMust                  // read and write; fail when the block is read-only
	mapReadTry                   // read and write when the block allows it
)

// mapping is a region of a memory block. data is the exact range the server
// asked for; raw is what Map returned, which starts on a page boundary.
type mapping struct {
	raw      []byte
	data     []byte
	writable bool
}

// mapRegion maps size bytes at offset inside the block the server announced
// with AddMem under memID. It checks the block is known, is shared memory and
// is large enough, because the numbers come from the server.
func (s *Stream) mapRegion(memID, offset, size uint32, mode writeMode) (*mapping, error) {
	blk, ok := s.conn.Mem(memID)
	if !ok {
		return nil, fmt.Errorf("the server referred to memory block %d, which it never announced or already removed", memID)
	}
	switch blk.Type {
	case pod.DataMemFd:
	case pod.DataDmaBuf:
		return nil, fmt.Errorf("memory block %d is a DMA-BUF, which this client does not support", memID)
	default:
		return nil, fmt.Errorf("memory block %d has data type %d, not shared memory", memID, blk.Type)
	}
	if blk.Fd < 0 {
		return nil, fmt.Errorf("memory block %d came without a file descriptor", memID)
	}
	if size == 0 || size > maxMapSize {
		return nil, fmt.Errorf("the server asked to map %d bytes of memory block %d", size, memID)
	}
	fsize, err := s.mem.Size(blk.Fd)
	if err != nil {
		return nil, fmt.Errorf("reading the size of memory block %d failed: %w", memID, err)
	}
	if end := int64(offset) + int64(size); end > fsize {
		return nil, fmt.Errorf("the server asked for bytes %d to %d of memory block %d, which holds %d", offset, end, memID, fsize)
	}
	writable := blk.Flags&memFlagWritable != 0
	if mode == mapReadMust && !writable {
		return nil, fmt.Errorf("memory block %d is read-only but the server expects this client to write to it", memID)
	}
	write := writable && mode != mapRead
	page := int64(s.mem.PageSize())
	aligned := int64(offset) / page * page
	delta := int64(offset) - aligned
	raw, err := s.mem.Map(blk.Fd, aligned, delta+int64(size), write)
	if err != nil {
		return nil, fmt.Errorf("mapping memory block %d failed: %w", memID, err)
	}
	return &mapping{raw: raw, data: raw[delta : delta+int64(size)], writable: write}, nil
}

func (s *Stream) unmap(m *mapping) {
	if m != nil && m.raw != nil {
		_ = s.mem.Unmap(m.raw)
		m.raw = nil
	}
}

// metaRef is one meta of a buffer, a slice of the buffer's block.
type metaRef struct {
	typ  uint32
	data []byte
}

// buffer is one buffer the server announced with PortUseBuffers, with every
// range already checked against the mapped memory.
type buffer struct {
	maps  []*mapping
	metas []metaRef
	chunk []byte // struct spa_chunk of the first data block
	pix   []byte // the first data block
	busy  []byte // struct spa_meta_busy, nil when absent or not writable
}

func (b *buffer) crop() *region {
	for _, m := range b.metas {
		if m.typ == pod.MetaVideoCrop && len(m.data) >= regionSize {
			r := readRegion(m.data)
			return &r
		}
	}
	return nil
}

func roundUp8(n uint32) uint64 { return (uint64(n) + 7) &^ 7 }

// buildBuffer resolves buffer i of a PortUseBuffers event as the notes
// describe in section 4.4: metas at the start of the block, then one chunk per
// data block, and each data block either inside the block (MemPtr) or in
// another memory block (MemId). Only the first data block carries the picture.
func (s *Stream) buildBuffer(i int, ub proto.UseBuffer) (*buffer, error) {
	if len(ub.Datas) == 0 {
		return nil, fmt.Errorf("buffer %d has no data block", i)
	}
	blk, err := s.mapRegion(ub.MemID, ub.Offset, ub.Size, mapReadTry)
	if err != nil {
		return nil, fmt.Errorf("buffer %d: %w", i, err)
	}
	b := &buffer{maps: []*mapping{blk}}
	fail := func(err error) (*buffer, error) {
		s.releaseBuffer(b)
		return nil, fmt.Errorf("buffer %d: %w", i, err)
	}
	block := blk.data
	var off uint64
	for _, m := range ub.Metas {
		if off+uint64(m.Size) > uint64(len(block)) {
			return fail(fmt.Errorf("meta of type %d (%d bytes) runs past the %d byte buffer block", m.Type, m.Size, len(block)))
		}
		b.metas = append(b.metas, metaRef{typ: m.Type, data: block[off : off+uint64(m.Size)]})
		off += roundUp8(m.Size)
	}
	if off+chunkSize*uint64(len(ub.Datas)) > uint64(len(block)) {
		return fail(fmt.Errorf("the %d chunks after the metas run past the %d byte buffer block", len(ub.Datas), len(block)))
	}
	b.chunk = block[off : off+chunkSize]

	d := ub.Datas[0]
	if d.MaxSize == 0 {
		return fail(fmt.Errorf("the first data block has size 0"))
	}
	switch d.Type {
	case pod.DataMemPtr:
		if uint64(d.DataID)+uint64(d.MaxSize) > uint64(len(block)) {
			return fail(fmt.Errorf("the pixel data (%d bytes at offset %d) runs past the %d byte buffer block", d.MaxSize, d.DataID, len(block)))
		}
		b.pix = block[d.DataID : uint64(d.DataID)+uint64(d.MaxSize)]
	case pod.DataMemId:
		m, err := s.mapRegion(d.DataID, d.MapOffset, d.MaxSize, mapRead)
		if err != nil {
			return fail(err)
		}
		b.maps = append(b.maps, m)
		b.pix = m.data
	default:
		return fail(fmt.Errorf("the first data block has type %d, which this client did not offer (it offers MemFd and MemPtr only)", d.Type))
	}

	if blk.writable {
		for _, m := range b.metas {
			if m.typ == pod.MetaBusy && len(m.data) >= 8 && aligned4(m.data, 4) {
				b.busy = m.data
				break
			}
		}
	}
	return b, nil
}

func (s *Stream) releaseBuffer(b *buffer) {
	for _, m := range b.maps {
		s.unmap(m)
	}
	b.maps = nil
}

// releaseMixBuffers unmaps the buffer set of one mix.
func (s *Stream) releaseMixBuffers(m *mix) {
	for _, b := range m.buffers {
		s.releaseBuffer(b)
	}
	m.buffers = nil
}

// releaseBuffers unmaps the buffer sets of every mix. A new format makes all
// of them stale.
func (s *Stream) releaseBuffers() {
	for _, m := range s.mixes {
		s.releaseMixBuffers(m)
	}
}

// busyAdd changes the count of the buffer's Busy meta, as pw_stream does
// around the time the application holds a buffer.
func (b *buffer) busyAdd(delta int32) {
	if b.busy != nil {
		atomic.AddUint32(atomicWord(b.busy, 4), uint32(delta))
	}
}
