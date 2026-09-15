package desktop

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
)

// Binary frame kinds (first byte of every helper -> viewer binary message).
// See docs/DESKTOP-PROTOCOL.md; all integers are little-endian.
const (
	kindTile     byte = 0x01 // u8 kind, u16 x, u16 y, u16 w, u16 h, u8 codec, bytes...
	kindFrameEnd byte = 0x02 // u8 kind, u32 frameId
)

// Tile codecs.
const (
	codecJPEG byte = 0
	codecPNG  byte = 1
)

const (
	tileHeaderLen     = 1 + 2*4 + 1 // kind + x,y,w,h + codec
	frameEndLen       = 1 + 4
	maxTileCoordinate = 0xFFFF
)

// tileFrame is one decoded rectangle message.
type tileFrame struct {
	Rect  image.Rectangle
	Codec byte
	Data  []byte // encoded pixels; aliases the input buffer on decode
}

// encodeTile builds a kindTile message. The rectangle must fit the u16 wire
// fields; the caller guarantees w and h are positive.
func encodeTile(r image.Rectangle, codec byte, data []byte) ([]byte, error) {
	if r.Min.X < 0 || r.Min.Y < 0 || r.Dx() <= 0 || r.Dy() <= 0 ||
		r.Min.X > maxTileCoordinate || r.Min.Y > maxTileCoordinate ||
		r.Dx() > maxTileCoordinate || r.Dy() > maxTileCoordinate {
		return nil, fmt.Errorf("tile rectangle %v does not fit the wire format", r)
	}
	buf := make([]byte, tileHeaderLen+len(data))
	buf[0] = kindTile
	binary.LittleEndian.PutUint16(buf[1:], uint16(r.Min.X))
	binary.LittleEndian.PutUint16(buf[3:], uint16(r.Min.Y))
	binary.LittleEndian.PutUint16(buf[5:], uint16(r.Dx()))
	binary.LittleEndian.PutUint16(buf[7:], uint16(r.Dy()))
	buf[9] = codec
	copy(buf[tileHeaderLen:], data)
	return buf, nil
}

// putTileHeader writes the tile header into the first tileHeaderLen bytes
// of dst (which must have room) so an encoder can write the payload straight
// after it without a second copy.
func putTileHeader(dst []byte, r image.Rectangle, codec byte) {
	dst[0] = kindTile
	binary.LittleEndian.PutUint16(dst[1:], uint16(r.Min.X))
	binary.LittleEndian.PutUint16(dst[3:], uint16(r.Min.Y))
	binary.LittleEndian.PutUint16(dst[5:], uint16(r.Dx()))
	binary.LittleEndian.PutUint16(dst[7:], uint16(r.Dy()))
	dst[9] = codec
}

// decodeTile parses a kindTile message. Data aliases buf.
func decodeTile(buf []byte) (tileFrame, error) {
	if len(buf) < tileHeaderLen {
		return tileFrame{}, errors.New("tile message too short")
	}
	if buf[0] != kindTile {
		return tileFrame{}, fmt.Errorf("not a tile message (kind 0x%02x)", buf[0])
	}
	x := int(binary.LittleEndian.Uint16(buf[1:]))
	y := int(binary.LittleEndian.Uint16(buf[3:]))
	w := int(binary.LittleEndian.Uint16(buf[5:]))
	h := int(binary.LittleEndian.Uint16(buf[7:]))
	if w == 0 || h == 0 {
		return tileFrame{}, errors.New("tile with empty size")
	}
	return tileFrame{Rect: image.Rect(x, y, x+w, y+h), Codec: buf[9], Data: buf[tileHeaderLen:]}, nil
}

// encodeFrameEnd builds a kindFrameEnd message.
func encodeFrameEnd(frameID uint32) []byte {
	buf := make([]byte, frameEndLen)
	buf[0] = kindFrameEnd
	binary.LittleEndian.PutUint32(buf[1:], frameID)
	return buf
}

// decodeFrameEnd parses a kindFrameEnd message.
func decodeFrameEnd(buf []byte) (uint32, error) {
	if len(buf) < frameEndLen {
		return 0, errors.New("frame-end message too short")
	}
	if buf[0] != kindFrameEnd {
		return 0, fmt.Errorf("not a frame-end message (kind 0x%02x)", buf[0])
	}
	return binary.LittleEndian.Uint32(buf[1:]), nil
}
