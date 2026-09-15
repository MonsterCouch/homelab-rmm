package desktop

import (
	"bytes"
	"encoding/binary"
	"image"
	"testing"
)

func TestTileRoundTrip(t *testing.T) {
	payload := []byte{0xff, 0xd8, 0xff, 0xd9}
	r := image.Rect(64, 128, 64+256, 128+64)
	buf, err := encodeTile(r, codecJPEG, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != tileHeaderLen+len(payload) {
		t.Fatalf("len=%d want %d", len(buf), tileHeaderLen+len(payload))
	}
	// Header bytes exactly as the protocol documents them (little-endian).
	want := []byte{0x01, 64, 0, 128, 0, 0, 1, 64, 0, 0}
	if !bytes.Equal(buf[:tileHeaderLen], want) {
		t.Fatalf("header %v want %v", buf[:tileHeaderLen], want)
	}
	tf, err := decodeTile(buf)
	if err != nil {
		t.Fatal(err)
	}
	if tf.Rect != r || tf.Codec != codecJPEG || !bytes.Equal(tf.Data, payload) {
		t.Fatalf("decoded %+v", tf)
	}

	// putTileHeader must produce the same bytes as encodeTile.
	var hdr [tileHeaderLen]byte
	putTileHeader(hdr[:], r, codecJPEG)
	if !bytes.Equal(hdr[:], want) {
		t.Fatalf("putTileHeader %v want %v", hdr, want)
	}
}

func TestTileRejectsUnencodable(t *testing.T) {
	for _, r := range []image.Rectangle{
		image.Rect(0, 0, 0, 10),          // empty
		image.Rect(-1, 0, 10, 10),        // negative origin
		image.Rect(0, 0, 70000, 10),      // too wide for u16
		image.Rect(65535, 0, 65535+1, 1), // origin at the edge is fine...
	} {
		_, err := encodeTile(r, codecJPEG, nil)
		if r.Min.X == 65535 {
			if err != nil {
				t.Errorf("%v: unexpected error %v", r, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%v: expected error", r)
		}
	}
	if _, err := decodeTile([]byte{0x01, 0, 0}); err == nil {
		t.Error("short tile decoded")
	}
	if _, err := decodeTile([]byte{0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Error("frame-end decoded as tile")
	}
	zero := make([]byte, tileHeaderLen)
	zero[0] = kindTile
	if _, err := decodeTile(zero); err == nil {
		t.Error("zero-size tile decoded")
	}
}

func TestFrameEndRoundTrip(t *testing.T) {
	for _, id := range []uint32{0, 1, 123, 0xFFFFFFFF} {
		buf := encodeFrameEnd(id)
		if len(buf) != frameEndLen || buf[0] != kindFrameEnd || binary.LittleEndian.Uint32(buf[1:]) != id {
			t.Fatalf("encodeFrameEnd(%d) = %v", id, buf)
		}
		got, err := decodeFrameEnd(buf)
		if err != nil || got != id {
			t.Fatalf("decodeFrameEnd(%v) = %d, %v", buf, got, err)
		}
	}
	if _, err := decodeFrameEnd([]byte{0x02, 1}); err == nil {
		t.Error("short frame-end decoded")
	}
	if _, err := decodeFrameEnd([]byte{0x01, 1, 0, 0, 0}); err == nil {
		t.Error("tile decoded as frame-end")
	}
}
