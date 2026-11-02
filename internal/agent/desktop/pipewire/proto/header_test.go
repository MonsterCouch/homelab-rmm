package proto

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

// unhex decodes a hex string with spaces and newlines, the form the protocol
// notes use.
func unhex(t testing.TB, s string) []byte {
	t.Helper()
	s = strings.Join(strings.Fields(s), "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test: %v", err)
	}
	return b
}

// Hello and Sync are the two full messages of notes section 2.8.
const (
	helloHeaderHex = "00 00 00 00 18 00 00 01 00 00 00 00 00 00 00 00"
	helloBodyHex   = "10 00 00 00 0e 00 00 00 04 00 00 00 04 00 00 00 04 00 00 00 00 00 00 00"
	syncHeaderHex  = "00 00 00 00 28 00 00 02 01 00 00 00 00 00 00 00"
	syncBodyHex    = `20 00 00 00 0e 00 00 00 04 00 00 00 04 00 00 00
		00 00 00 00 00 00 00 00 04 00 00 00 04 00 00 00
		01 00 00 40 00 00 00 00`
	footerHex = `28 00 00 00 0e 00 00 00 04 00 00 00 03 00 00 00
		00 00 00 00 00 00 00 00 10 00 00 00 0e 00 00 00
		08 00 00 00 05 00 00 00 05 00 00 00 00 00 00 00`
	transportBodyHex = `50 00 00 00 0e 00 00 00 08 00 00 00 12 00 00 00
		00 00 00 00 00 00 00 00 08 00 00 00 12 00 00 00
		01 00 00 00 00 00 00 00 04 00 00 00 04 00 00 00
		03 00 00 00 00 00 00 00 04 00 00 00 04 00 00 00
		00 00 00 00 00 00 00 00 04 00 00 00 04 00 00 00
		08 09 00 00 00 00 00 00`
	updatePropsBodyHex = `40 00 00 00 0e 00 00 00 38 00 00 00 0e 00 00 00
		04 00 00 00 04 00 00 00 01 00 00 00 00 00 00 00
		0b 00 00 00 08 00 00 00 6d 65 64 69 61 2e 74 79
		70 65 00 00 00 00 00 00 06 00 00 00 08 00 00 00
		56 69 64 65 6f 00 00 00`
)

func TestHeaderPackHello(t *testing.T) {
	h := Header{ID: 0, Opcode: CoreMethodHello, Size: 24, Seq: 0, NFds: 0}
	got := h.Pack()
	if !bytes.Equal(got[:], unhex(t, helloHeaderHex)) {
		t.Fatalf("hello header = % x, want % x", got, unhex(t, helloHeaderHex))
	}
	// The second word is opcode<<24 | size.
	if w := uint32(got[4]) | uint32(got[5])<<8 | uint32(got[6])<<16 | uint32(got[7])<<24; w != 0x01000018 {
		t.Fatalf("second header word = %#x, want 0x01000018", w)
	}
}

func TestHeaderPackSync(t *testing.T) {
	h := Header{ID: 0, Opcode: CoreMethodSync, Size: 40, Seq: 1}
	got := h.Pack()
	if !bytes.Equal(got[:], unhex(t, syncHeaderHex)) {
		t.Fatalf("sync header = % x, want % x", got, unhex(t, syncHeaderHex))
	}
}

func TestHeaderRoundTripAndMasks(t *testing.T) {
	h := Header{ID: 0x01020304, Opcode: 0xff, Size: MaxPayload, Seq: 0x3fffffff, NFds: 1024}
	b := h.Pack()
	got, err := UnpackHeader(b[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("round trip = %+v, want %+v", got, h)
	}
	// Seq is masked to 30 bits and Size to 24 bits when packing.
	over := Header{Seq: 0xffffffff, Size: 0x1ffffff}.Pack()
	back, _ := UnpackHeader(over[:])
	if back.Seq != SeqMask || back.Size != MaxPayload || back.Opcode != 0 {
		t.Fatalf("masking gave %+v", back)
	}
	if _, err := UnpackHeader(b[:15]); err == nil {
		t.Fatal("a 15-byte header was accepted")
	}
}

func TestBuildMessageHelloAndSync(t *testing.T) {
	h, payload, fds, err := BuildMessage(IDCore, 0, CoreHello{Version: VersionCore})
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, helloBodyHex); !bytes.Equal(payload, want) {
		t.Fatalf("hello payload = % x, want % x", payload, want)
	}
	if h.Size != 24 || h.Opcode != 1 || len(fds) != 0 {
		t.Fatalf("hello header = %+v fds=%v", h, fds)
	}
	_, payload, _, err = BuildMessage(IDCore, 1, CoreSync{ID: 0, Seq: int32(AsyncBit | 1)})
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, syncBodyHex); !bytes.Equal(payload, want) {
		t.Fatalf("sync payload = % x, want % x", payload, want)
	}
}

func TestUpdatePropertiesVector(t *testing.T) {
	_, payload, _, err := BuildMessage(IDClient, 1, ClientUpdateProperties{Props: Dict{{"media.type", "Video"}}})
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, updatePropsBodyHex); !bytes.Equal(payload, want) {
		t.Fatalf("UpdateProperties payload = % x, want % x", payload, want)
	}
	st, _, err := SplitPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	v, err := DecodeClientMethod(ClientMethodUpdateProperties, st, NewFdList(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v, ClientUpdateProperties{Props: Dict{{"media.type", "Video"}}}) {
		t.Fatalf("decoded %+v", v)
	}
}

func TestTransportVector(t *testing.T) {
	body := unhex(t, transportBodyHex)
	st, _, err := SplitPayload(body)
	if err != nil {
		t.Fatal(err)
	}
	fl := NewFdList([]int{40, 41})
	v, err := DecodeClientNodeEvent(ClientNodeEventTransport, st, fl)
	if err != nil {
		t.Fatal(err)
	}
	want := ClientNodeTransport{ReadFd: 40, WriteFd: 41, MemID: 3, Offset: 0, Size: 2312}
	if v != want {
		t.Fatalf("decoded %+v, want %+v", v, want)
	}
	if len(fl.Unused()) != 0 {
		t.Fatalf("unused fds %v", fl.Unused())
	}
	_, payload, fds, err := BuildMessage(2, 0, want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, body) || !reflect.DeepEqual(fds, []int{40, 41}) {
		t.Fatalf("marshal = % x fds %v", payload, fds)
	}
}

func TestFooterIsSkippedAndRead(t *testing.T) {
	payload := append(unhex(t, helloBodyHex), unhex(t, footerHex)...)
	st, f, err := SplitPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Fields) != 1 || st.Fields[0] != pod.Pod(pod.Int(4)) {
		t.Fatalf("struct = %+v", st)
	}
	if !f.HasGeneration || f.Generation != 5 {
		t.Fatalf("footer = %+v, want generation 5", f)
	}
	// The helper writes the same bytes as the notes.
	if got := AppendFooterGeneration(unhex(t, helloBodyHex), 5); !bytes.Equal(got, payload) {
		t.Fatalf("AppendFooterGeneration = % x", got)
	}
	// A truncated or odd footer is ignored, never an error.
	for _, junk := range [][]byte{{1}, {1, 2, 3, 4, 5, 6, 7, 8}, unhex(t, footerHex)[:20], bytes.Repeat([]byte{0xff}, 16)} {
		st, f, err := SplitPayload(append(unhex(t, helloBodyHex), junk...))
		if err != nil || len(st.Fields) != 1 || f.HasGeneration {
			t.Fatalf("junk footer % x: st=%+v f=%+v err=%v", junk, st, f, err)
		}
	}
}

func TestSplitPayloadRejectsNonStruct(t *testing.T) {
	if _, _, err := SplitPayload(pod.Encode(pod.Int(1))); err == nil {
		t.Fatal("an Int payload was accepted")
	}
	if _, _, err := SplitPayload(nil); err == nil {
		t.Fatal("an empty payload was accepted")
	}
}

func TestFdSetDeduplicates(t *testing.T) {
	var s FdSet
	if s.Index(7) != 0 || s.Index(9) != 1 || s.Index(7) != 0 {
		t.Fatal("same fd did not reuse its index")
	}
	if s.Index(-1) != pod.NoFd {
		t.Fatal("a negative fd is not NoFd")
	}
	if !reflect.DeepEqual(s.List(), []int{7, 9}) {
		t.Fatalf("list = %v", s.List())
	}
}

func TestFdListBounds(t *testing.T) {
	l := NewFdList([]int{3})
	if fd, err := l.Get(0); err != nil || fd != 3 {
		t.Fatalf("Get(0) = %d, %v", fd, err)
	}
	if fd, err := l.Get(int64(pod.NoFd)); err != nil || fd != -1 {
		t.Fatalf("Get(NoFd) = %d, %v", fd, err)
	}
	if _, err := l.Get(1); err == nil {
		t.Fatal("an index past the fd list was accepted")
	}
}
