package pod

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func hx(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// vectors are the byte examples of docs/plans/2026-10-25-pipewire-protocol-notes.md
// sections 1.6 and 2.8. They were derived by hand from builder.h, not
// captured from a daemon.
func vectors() []struct {
	name string
	hex  string
	pod  Pod
} {
	return []struct {
		name string
		hex  string
		pod  Pod
	}{
		{"None", "00000000 01000000", None{}},
		{"Bool true", "04000000 02000000 01000000 00000000", Bool(true)},
		{"Int 42", "04000000 04000000 2a000000 00000000", Int(42)},
		{"Long 1", "08000000 05000000 01000000 00000000", Long(1)},
		{"Id 8", "04000000 03000000 08000000 00000000", Id(VideoFormatBGRx)},
		{"String hi", "03000000 08000000 68690000 00000000", String("hi")},
		{"Rectangle 1920x1080", "08000000 0a000000 80070000 38040000", Rect(1920, 1080)},
		{"Fraction 30/1", "08000000 0b000000 1e000000 01000000", Frac(30, 1)},
		{"Fd 0", "08000000 12000000 00000000 00000000", Fd(0)},
		{"Struct Int 1, String a",
			"20000000 0e000000 04000000 04000000 01000000 00000000 02000000 08000000 61000000 00000000",
			NewStruct(Int(1), String("a"))},
		{"Array Int 1 2 3",
			"14000000 0d000000 04000000 04000000 01000000 02000000 03000000 00000000",
			ArrayInts(1, 2, 3)},
		{"Choice Enum Id",
			"20000000 13000000 03000000 00000000 04000000 03000000 08000000 08000000 07000000 0c000000",
			ChoiceEnum(Id(8), Id(8), Id(7), Id(12))},
		{"Choice Range Int",
			"1c000000 13000000 01000000 00000000 04000000 04000000 08000000 02000000 40000000 00000000",
			ChoiceRange(Int(8), Int(2), Int(64))},
		{"Choice Range Rectangle",
			"28000000 13000000 01000000 00000000 08000000 0a000000 40010000 f0000000 01000000 01000000 00100000 00100000",
			ChoiceRange(Rect(320, 240), Rect(1, 1), Rect(4096, 4096))},
		{"Object Format EnumFormat",
			"38000000 0f000000 03000400 03000000 01000000 00000000 04000000 03000000 02000000 00000000 " +
				"02000000 00000000 04000000 03000000 01000000 00000000",
			NewObject(ObjectFormat, ParamEnumFormat,
				P(FormatMediaType, Id(MediaTypeVideo)),
				P(FormatMediaSubtype, Id(MediaSubtypeRaw)))},
		{"Command Start", "08000000 0f000000 02000300 02000000",
			NewObject(TypeCommandNode, NodeCommandStart)},
		{"Hello body", "10000000 0e000000 04000000 04000000 04000000 00000000", NewStruct(Int(4))},
		{"Sync body",
			"20000000 0e000000 04000000 04000000 00000000 00000000 04000000 04000000 01000040 00000000",
			NewStruct(Int(0), Int(0x40000001))},
		{"Footer generation 5",
			"28000000 0e000000 04000000 03000000 00000000 00000000 10000000 0e000000 08000000 05000000 05000000 00000000",
			NewStruct(Id(0), NewStruct(Long(5)))},
		{"Transport body",
			"50000000 0e000000 08000000 12000000 00000000 00000000 08000000 12000000 01000000 00000000 " +
				"04000000 04000000 03000000 00000000 04000000 04000000 00000000 00000000 04000000 04000000 08090000 00000000",
			NewStruct(Fd(0), Fd(1), Int(3), Int(0), Int(2312))},
		{"UpdateProperties body",
			"40000000 0e000000 38000000 0e000000 04000000 04000000 01000000 00000000 " +
				"0b000000 08000000 6d656469 612e7479 70650000 00000000 06000000 08000000 56696465 6f000000",
			NewStruct(NewStruct(Int(1), String("media.type"), String("Video")))},
	}
}

func TestVectorsDecodeAndEncode(t *testing.T) {
	for _, v := range vectors() {
		t.Run(v.name, func(t *testing.T) {
			raw := hx(t, v.hex)
			if len(raw)%8 != 0 {
				t.Fatalf("vector length %d is not a multiple of 8", len(raw))
			}
			got, rest, err := Decode(raw)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if len(rest) != 0 {
				t.Fatalf("Decode left %d bytes", len(rest))
			}
			if !reflect.DeepEqual(got, v.pod) {
				t.Fatalf("Decode = %#v, want %#v", got, v.pod)
			}
			enc, err := EncodeErr(v.pod)
			if err != nil {
				t.Fatalf("EncodeErr: %v", err)
			}
			if !bytes.Equal(enc, raw) {
				t.Fatalf("Encode =\n%x\nwant\n%x", enc, raw)
			}
		})
	}
}

func TestRoundTripEveryType(t *testing.T) {
	var cases []Pod
	cases = append(cases,
		None{}, Bool(false), Bool(true), Id(0), Id(math.MaxUint32),
		Int(math.MinInt32), Int(math.MaxInt32), Long(math.MinInt64), Long(math.MaxInt64),
		Float(1.5), Float(float32(math.Inf(-1))), Double(-2.25e300), Double(0),
		String(""), Bytes(nil), Bitmap(nil),
		Rect(0, 0), Rect(math.MaxUint32, 1), Frac(0, 1), Frac(60000, 1001),
		Fd(0), Fd(7), NoFd,
		Pointer{PtrType: TypeBuffer, Ptr: 0xdeadbeefcafe},
		NewStruct(), NewObject(ObjectProps, ParamProps),
		Sequence{Unit: 1},
		Array{ChildType: TypeInt},
		Choice{Kind: ChoiceKindNone, ChildType: TypeInt},
	)
	for n := 0; n <= 17; n++ {
		cases = append(cases,
			String(strings.Repeat("x", n)),
			Bytes(bytes.Repeat([]byte{0xa5}, n)),
			Bitmap(bytes.Repeat([]byte{0x5a}, n)))
	}
	cases = append(cases,
		ArrayIds(1, 2, 3, 4, 5),
		ArrayInts(-1, 0, 1),
		ArrayLongs(1<<40, -1),
		NewArray(TypeRectangle, Rect(1, 2), Rect(3, 4)),
		NewArray(TypeFraction, Frac(1, 2)),
		NewArray(TypeBool, Bool(true), Bool(false), Bool(true)),
		NewArray(TypeFloat, Float(1), Float(2), Float(3)),
		NewArray(TypeDouble, Double(1), Double(2)),
		NewArray(TypeFd, Fd(0), Fd(1), Fd(2)),
		ChoiceNone(Int(5)),
		ChoiceRange(Long(1), Long(0), Long(10)),
		ChoiceStep(Int(4), Int(0), Int(100), Int(4)),
		ChoiceEnum(Id(VideoFormatBGRx), Id(VideoFormatBGRx), Id(VideoFormatRGBx), Id(VideoFormatBGRA), Id(VideoFormatRGBA)),
		ChoiceFlags(Int(6), Int(2), Int(4)),
		ChoiceRange(Frac(30, 1), Frac(0, 1), Frac(1000, 1)),
		Choice{Kind: ChoiceKindEnum, Flags: 3, ChildType: TypeFloat, Values: []Pod{Float(1), Float(2)}},
		Sequence{Unit: 2, Controls: []Control{
			{Offset: 0, Type: 1, Value: Int(5)},
			{Offset: 10, Type: 2, Value: String("ctl")},
		}},
		NewObject(ObjectParamBuffers, ParamBuffers,
			P(ParamBuffersBuffers, ChoiceRange(Int(8), Int(2), Int(64))),
			PF(ParamBuffersDataType, PropFlagMandatory|PropFlagReadOnly, ChoiceFlags(Int(6), Int(6)))),
	)
	for i, c := range cases {
		raw, err := EncodeErr(c)
		if err != nil {
			t.Fatalf("case %d %#v: EncodeErr: %v", i, c, err)
		}
		if len(raw)%8 != 0 {
			t.Fatalf("case %d: encoded length %d is not a multiple of 8", i, len(raw))
		}
		got, rest, err := Decode(raw)
		if err != nil || len(rest) != 0 {
			t.Fatalf("case %d %#v: Decode err=%v rest=%d", i, c, err, len(rest))
		}
		if !reflect.DeepEqual(got, c) {
			// Bytes(nil) and Bitmap(nil) decode as empty non-nil slices.
			if b, ok := c.(Bytes); ok && len(b) == 0 {
				if gb, ok := got.(Bytes); ok && len(gb) == 0 {
					continue
				}
			}
			if b, ok := c.(Bitmap); ok && len(b) == 0 {
				if gb, ok := got.(Bitmap); ok && len(gb) == 0 {
					continue
				}
			}
			t.Fatalf("case %d: got %#v, want %#v", i, got, c)
		}
	}
}

func TestNaNRoundTripsByBytes(t *testing.T) {
	raw := Encode(NewStruct(Float(float32(math.NaN())), Double(math.NaN())))
	p, _, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Encode(p), raw) {
		t.Fatal("NaN did not round-trip bit for bit")
	}
}

func TestNilEncodesAsNone(t *testing.T) {
	if got := Encode(nil); !bytes.Equal(got, hx(t, "00000000 01000000")) {
		t.Fatalf("Encode(nil) = %x", got)
	}
	if got := Encode(NewStruct(nil)); !bytes.Equal(got, Encode(NewStruct(None{}))) {
		t.Fatalf("nil field = %x", got)
	}
}

func TestEncodeRejectsBadValues(t *testing.T) {
	bad := []Pod{
		Array{ChildType: TypeString, Values: []Pod{String("a")}},
		Array{ChildType: TypeInt, Values: []Pod{Id(1)}},
		Array{ChildType: TypeInt, Values: []Pod{nil}},
		Array{},
		Choice{Kind: ChoiceKindEnum, ChildType: TypeInt, Values: []Pod{Int(1), Long(2)}},
		NewStruct(Array{ChildType: TypeInt, Values: []Pod{Long(1)}}),
		NewObject(1, 1, P(1, Choice{ChildType: TypeBytes})),
	}
	for i, p := range bad {
		if _, err := EncodeErr(p); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: err = %v, want ErrInvalid", i, err)
		}
		if Encode(p) != nil {
			t.Errorf("case %d: Encode should return nil", i)
		}
	}
	// A failed AppendEncode leaves dst at its original length.
	dst := []byte{1, 2, 3}
	out, err := AppendEncode(dst, bad[0])
	if err == nil || len(out) != 3 {
		t.Errorf("AppendEncode on error: len=%d err=%v", len(out), err)
	}
}

func TestDepthLimit(t *testing.T) {
	var p Pod = Int(1)
	for i := 0; i < maxDepth+2; i++ {
		p = NewStruct(p)
	}
	if _, err := EncodeErr(p); !errors.Is(err, ErrInvalid) {
		t.Errorf("EncodeErr deep = %v", err)
	}
	// Hand-build the same nesting and make sure Decode refuses it.
	raw := Encode(Int(1))
	for i := 0; i < maxDepth+2; i++ {
		hdr := put32(nil, uint32(len(raw)))
		hdr = put32(hdr, TypeStruct)
		raw = append(hdr, raw...)
	}
	if _, _, err := Decode(raw); !errors.Is(err, ErrInvalid) {
		t.Errorf("Decode deep = %v", err)
	}
}

// nested builds an Object inside a Struct inside another Struct, with
// Choices as property values and a Struct property that holds an Object.
// A Choice cannot hold a Struct or an Object, because its children are
// headerless fixed-size values, so the nesting is Struct, Object, Choice.
func nested() Pod {
	inner := NewObject(ObjectFormat, ParamFormat,
		P(FormatMediaType, Id(MediaTypeVideo)),
		P(FormatVideoSize, ChoiceRange(Rect(1920, 1080), Rect(1, 1), Rect(16384, 16384))),
		P(FormatVideoFramerate, ChoiceRange(Frac(30, 1), Frac(0, 1), Frac(1000, 1))),
		P(FormatVideoFormat, ChoiceEnum(Id(VideoFormatBGRx), Id(VideoFormatBGRx), Id(VideoFormatBGRA))),
	)
	return NewStruct(
		Int(2),
		NewStruct(String("k"), inner, NewStruct()),
		NewObject(ObjectProps, ParamProps,
			P(PropParams, NewStruct(inner, ArrayIds(1, 2, 3), ChoiceFlags(Int(6), Int(2), Int(4))))),
		Fd(1),
	)
}

func TestNestedRoundTrip(t *testing.T) {
	p := nested()
	raw, err := EncodeErr(p)
	if err != nil {
		t.Fatal(err)
	}
	got, rest, err := Decode(raw)
	if err != nil || len(rest) != 0 {
		t.Fatalf("Decode err=%v rest=%d", err, len(rest))
	}
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("nested mismatch:\n got %#v\nwant %#v", got, p)
	}
	// Sizes of containers count their padded children.
	if sz := le32(raw); int(sz) != len(raw)-8 {
		t.Fatalf("outer size %d, buffer %d", sz, len(raw))
	}
}

func TestDecodeReturnsRestAndSkipsFooter(t *testing.T) {
	msg := Encode(NewStruct(Int(4)))
	footer := Encode(NewStruct(Id(0), NewStruct(Long(5))))
	p, rest, err := Decode(append(append([]byte{}, msg...), footer...))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, NewStruct(Int(4))) {
		t.Fatalf("got %#v", p)
	}
	if !bytes.Equal(rest, footer) {
		t.Fatalf("rest = %x, want footer", rest)
	}
	f, rest, err := Decode(rest)
	if err != nil || len(rest) != 0 || !reflect.DeepEqual(f, NewStruct(Id(0), NewStruct(Long(5)))) {
		t.Fatalf("footer decode: %#v %v", f, err)
	}
}

func TestEveryTruncationFails(t *testing.T) {
	var raws [][]byte
	for _, v := range vectors() {
		raws = append(raws, hx(t, v.hex))
	}
	raws = append(raws, Encode(nested()))
	for _, raw := range raws {
		for n := 0; n < len(raw); n++ {
			if _, _, err := Decode(raw[:n]); err == nil {
				t.Fatalf("prefix %d of %d bytes decoded without error: %x", n, len(raw), raw[:n])
			}
		}
	}
}

func TestOversizeAndMalformedHeaders(t *testing.T) {
	cases := map[string]string{
		"empty":                    "",
		"seven bytes":              "00000000010000",
		"size 0xffffffff":          "ffffffff 04000000 00000000 00000000",
		"size 0xfffffff9":          "f9ffffff 04000000 00000000 00000000",
		"int size 3":               "03000000 04000000 00000000 00000000",
		"size 0x7fffffff":          "ffffff7f 0e000000",
		"unknown type 0":           "00000000 00000000",
		"unknown type 99":          "00000000 63000000",
		"type Pod marker":          "00000000 14000000",
		"int too short":            "00000000 04000000",
		"long with 4 bytes":        "04000000 05000000 01000000 00000000",
		"string without NUL":       "02000000 08000000 68690000 00000000",
		"string size 0":            "00000000 08000000",
		"rectangle short":          "04000000 0a000000 01000000 00000000",
		"pointer short":            "08000000 11000000 00000000 00000000",
		"array body short":         "04000000 0d000000 04000000 00000000",
		"array zero child size":    "08000000 0d000000 00000000 04000000",
		"array wrong child size":   "08000000 0d000000 08000000 04000000",
		"array string child":       "08000000 0d000000 04000000 08000000",
		"array ragged":             "0b000000 0d000000 04000000 04000000 01000000 02000000",
		"choice body short":        "08000000 13000000 03000000 00000000",
		"choice bad child":         "10000000 13000000 03000000 00000000 04000000 09000000",
		"object body short":        "04000000 0f000000 00000000 00000000",
		"object prop cut":          "0c000000 0f000000 03000400 03000000 01000000 00000000",
		"object prop value oversz": "18000000 0f000000 03000400 03000000 01000000 00000000 ffffffff 03000000",
		"sequence body short":      "04000000 10000000 00000000 00000000",
		"struct child oversize":    "10000000 0e000000 ffffffff 04000000 00000000 00000000",
		"struct child cut":         "08000000 0e000000 04000000 04000000",
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			_, _, err := Decode(hx(t, h))
			if err == nil {
				t.Fatal("decoded without error")
			}
			if !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrInvalid) {
				t.Fatalf("error %v is neither ErrTruncated nor ErrInvalid", err)
			}
		})
	}
}

func decodeNoPanic(t testing.TB, b []byte) (Pod, error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Decode panicked on %x: %v", b, r)
		}
	}()
	p, rest, err := Decode(b)
	if err == nil && len(rest) > len(b) {
		t.Fatalf("rest longer than input")
	}
	return p, err
}

func checkMutant(t testing.TB, b []byte) {
	p, err := decodeNoPanic(t, b)
	if err != nil {
		return
	}
	enc, err := EncodeErr(p)
	if err != nil {
		t.Fatalf("decoded pod from %x does not encode: %v", b, err)
	}
	p2, rest, err := Decode(enc)
	if err != nil || len(rest) != 0 {
		t.Fatalf("re-decode of %x: err=%v rest=%d", enc, err, len(rest))
	}
	if !bytes.Equal(Encode(p2), enc) {
		t.Fatalf("encode is not stable for %x", b)
	}
}

func TestMutatedBuffersNeverPanic(t *testing.T) {
	var seeds [][]byte
	for _, v := range vectors() {
		seeds = append(seeds, hx(t, v.hex))
	}
	seeds = append(seeds, Encode(nested()))
	rng := rand.New(rand.NewSource(1))
	for _, seed := range seeds {
		for i := 0; i < 400; i++ {
			m := append([]byte{}, seed...)
			for k := rng.Intn(4) + 1; k > 0; k-- {
				m[rng.Intn(len(m))] = byte(rng.Intn(256))
			}
			if rng.Intn(5) == 0 {
				m = m[:rng.Intn(len(m)+1)]
			}
			checkMutant(t, m)
		}
	}
	for i := 0; i < 2000; i++ {
		b := make([]byte, rng.Intn(80))
		rng.Read(b)
		checkMutant(t, b)
	}
}

func FuzzDecode(f *testing.F) {
	for _, v := range vectors() {
		raw, _ := hex.DecodeString(strings.Join(strings.Fields(v.hex), ""))
		f.Add(raw)
	}
	f.Add(Encode(nested()))
	f.Fuzz(func(t *testing.T, b []byte) { checkMutant(t, b) })
}

func TestConstantsMatchNotes(t *testing.T) {
	checks := []struct {
		name      string
		got, want uint32
	}{
		{"TypeStruct", TypeStruct, 14}, {"TypeChoice", TypeChoice, 19}, {"TypeFd", TypeFd, 18},
		{"ObjectFormat", ObjectFormat, 0x40003}, {"ObjectParamBuffers", ObjectParamBuffers, 0x40004},
		{"TypeCommandNode", TypeCommandNode, 0x30002}, {"TypeEventNode", TypeEventNode, 0x20002},
		{"ParamEnumFormat", ParamEnumFormat, 3}, {"ParamFormat", ParamFormat, 4}, {"ParamBuffers", ParamBuffers, 5},
		{"ParamMeta", ParamMeta, 6}, {"ParamIO", ParamIO, 7},
		{"FormatVideoSize", FormatVideoSize, 0x20003}, {"FormatVideoFramerate", FormatVideoFramerate, 0x20004},
		{"VideoFormatRGBx", VideoFormatRGBx, 7}, {"VideoFormatBGRx", VideoFormatBGRx, 8},
		{"VideoFormatRGBA", VideoFormatRGBA, 11}, {"VideoFormatBGRA", VideoFormatBGRA, 12},
		{"DataMaskMemPtr", DataMaskMemPtr, 2}, {"DataMaskMemFd", DataMaskMemFd, 4}, {"DataMaskDmaBuf", DataMaskDmaBuf, 8},
		{"IOAsyncBuffers", IOAsyncBuffers, 10}, {"MetaBusy", MetaBusy, 7}, {"MetaVideoCrop", MetaVideoCrop, 2},
		{"NodeCommandStart", NodeCommandStart, 2}, {"NodeCommandRequestProcess", NodeCommandRequestProcess, 10},
		{"ChoiceKindFlags", ChoiceKindFlags, 4},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}
}

func TestBuilders(t *testing.T) {
	s := NewBuilder().Int(1).Long(2).Id(3).Bool(true).Float(1).Double(2).String("s").
		Bytes([]byte{1}).Rectangle(4, 5).Fraction(6, 7).Fd(8).None().Pod(Int(9)).Build()
	want := NewStruct(Int(1), Long(2), Id(3), Bool(true), Float(1), Double(2), String("s"),
		Bytes([]byte{1}), Rect(4, 5), Frac(6, 7), Fd(8), None{}, Int(9))
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("Builder = %#v", s)
	}
	o := NewObjectBuilder(ObjectFormat, ParamEnumFormat).
		Id(FormatMediaType, MediaTypeVideo).Id(FormatMediaSubtype, MediaSubtypeRaw).
		Rectangle(FormatVideoSize, 1, 2).Fraction(FormatVideoFramerate, 3, 4).
		Int(100, 5).Long(101, 6).Bool(102, true).String(103, "x").
		Prop(104, PropFlagMandatory, Int(1)).Build()
	if len(o.Props) != 9 || o.Props[8].Flags != PropFlagMandatory || o.ObjType != ObjectFormat {
		t.Fatalf("ObjectBuilder = %#v", o)
	}
	// The vector for Object Format from the notes can be built both ways.
	a := NewObjectBuilder(ObjectFormat, ParamEnumFormat).
		Id(FormatMediaType, MediaTypeVideo).Id(FormatMediaSubtype, MediaSubtypeRaw).Build()
	b := NewObject(ObjectFormat, ParamEnumFormat,
		P(FormatMediaType, Id(MediaTypeVideo)), P(FormatMediaSubtype, Id(MediaSubtypeRaw)))
	if !bytes.Equal(Encode(a), Encode(b)) {
		t.Fatal("builders disagree")
	}
	// Builder.Build copies, so later calls do not change an earlier result.
	bb := NewBuilder().Int(1)
	first := bb.Build()
	bb.Int(2)
	if len(first.Fields) != 1 {
		t.Fatal("Build did not copy")
	}
}

func TestObjectGetters(t *testing.T) {
	o := NewObject(ObjectFormat, ParamFormat,
		P(FormatMediaType, Id(MediaTypeVideo)),
		P(FormatVideoFormat, ChoiceEnum(Id(VideoFormatBGRx), Id(VideoFormatBGRx), Id(VideoFormatRGBx))),
		P(FormatVideoSize, Rect(800, 600)),
		P(FormatVideoFramerate, ChoiceRange(Frac(30, 1), Frac(0, 1), Frac(60, 1))),
		P(FormatVideoModifier, Long(-5)),
		P(FormatVideoViews, ChoiceRange(Int(1), Int(1), Int(4))),
		P(PropLive, Bool(true)),
		P(PropDeviceName, String("dev")),
		P(FormatVideoSize+100, Id(1)),
	)
	if v, err := o.GetId(FormatMediaType); err != nil || v != MediaTypeVideo {
		t.Errorf("GetId = %d, %v", v, err)
	}
	if v, err := o.GetId(FormatVideoFormat); err != nil || v != VideoFormatBGRx {
		t.Errorf("GetId choice = %d, %v", v, err)
	}
	if v, err := o.GetRectangle(FormatVideoSize); err != nil || v != Rect(800, 600) {
		t.Errorf("GetRectangle = %v, %v", v, err)
	}
	if v, err := o.GetFraction(FormatVideoFramerate); err != nil || v != Frac(30, 1) {
		t.Errorf("GetFraction = %v, %v", v, err)
	}
	if v, err := o.GetLong(FormatVideoModifier); err != nil || v != -5 {
		t.Errorf("GetLong = %v, %v", v, err)
	}
	if v, err := o.GetInt(FormatVideoViews); err != nil || v != 1 {
		t.Errorf("GetInt = %v, %v", v, err)
	}
	if v, err := o.GetBool(PropLive); err != nil || !v {
		t.Errorf("GetBool = %v, %v", v, err)
	}
	if v, err := o.GetString(PropDeviceName); err != nil || v != "dev" {
		t.Errorf("GetString = %v, %v", v, err)
	}
	if _, err := o.GetId(0x99999); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing key err = %v", err)
	}
	if _, err := o.GetInt(FormatMediaType); !errors.Is(err, ErrType) {
		t.Errorf("wrong type err = %v", err)
	}
	if _, err := NewObject(1, 1, P(5, Choice{ChildType: TypeInt})).GetInt(5); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty choice err = %v", err)
	}
	k, vals, err := o.Values(FormatVideoFormat)
	if err != nil || k != ChoiceKindEnum || len(vals) != 3 {
		t.Errorf("Values = %d %v %v", k, vals, err)
	}
	k, vals, err = o.Values(FormatVideoSize)
	if err != nil || k != ChoiceKindNone || len(vals) != 1 {
		t.Errorf("Values plain = %d %v %v", k, vals, err)
	}
	if _, _, err := o.Values(0x99999); !errors.Is(err, ErrNotFound) {
		t.Errorf("Values missing err = %v", err)
	}
	if _, ok := o.Find(FormatVideoSize + 100); !ok {
		t.Error("Find missed a key")
	}
	if Default(Id(3)) != Id(3) || Default(ChoiceNone(Id(4))) != Id(4) || Default(Choice{}) != nil {
		t.Error("Default wrong")
	}
}

func TestStructParser(t *testing.T) {
	// Core.Info as the server marshals it, shortened to the field kinds.
	s := NewStruct(Int(1), Long(2), Id(3), Bool(true), Float(4), Double(5), String("a"), None{},
		Bytes([]byte{9}), Rect(1, 2), Frac(3, 4), Fd(1),
		NewStruct(Int(0)), NewObject(1, 2), Int(77))
	sp, err := NewStructParser(s)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	if v, err := sp.Int(); err != nil || v != 1 {
		t.Fatalf("Int %v %v", v, err)
	}
	if v, err := sp.Long(); err != nil || v != 2 {
		t.Fatalf("Long %v %v", v, err)
	}
	if v, err := sp.Id(); err != nil || v != 3 {
		t.Fatalf("Id %v %v", v, err)
	}
	if v, err := sp.Bool(); err != nil || !v {
		t.Fatalf("Bool %v %v", v, err)
	}
	if v, err := sp.Float(); err != nil || v != 4 {
		t.Fatalf("Float %v %v", v, err)
	}
	if v, err := sp.Double(); err != nil || v != 5 {
		t.Fatalf("Double %v %v", v, err)
	}
	if v, err := sp.String(); err != nil || v != "a" {
		t.Fatalf("String %v %v", v, err)
	}
	if v, ok, err := sp.OptString(); err != nil || ok || v != "" {
		t.Fatalf("OptString none %v %v %v", v, ok, err)
	}
	if v, err := sp.Bytes(); err != nil || !bytes.Equal(v, []byte{9}) {
		t.Fatalf("Bytes %v %v", v, err)
	}
	if v, err := sp.Rectangle(); err != nil || v != Rect(1, 2) {
		t.Fatalf("Rectangle %v %v", v, err)
	}
	if v, err := sp.Fraction(); err != nil || v != Frac(3, 4) {
		t.Fatalf("Fraction %v %v", v, err)
	}
	if v, err := sp.Fd(); err != nil || v != 1 {
		t.Fatalf("Fd %v %v", v, err)
	}
	inner, err := sp.Struct()
	must(err)
	if v, err := inner.Int(); err != nil || v != 0 {
		t.Fatalf("inner Int %v %v", v, err)
	}
	if _, err := inner.Int(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("inner exhausted err = %v", err)
	}
	if o, err := sp.Object(); err != nil || o.ID != 2 {
		t.Fatalf("Object %v %v", o, err)
	}
	// A wrong-type getter fails and does not consume the field.
	if _, err := sp.String(); !errors.Is(err, ErrType) {
		t.Fatalf("wrong type err = %v", err)
	}
	if sp.Remaining() != 1 {
		t.Fatalf("Remaining = %d", sp.Remaining())
	}
	if p, err := sp.Pod(); err != nil || p != Int(77) {
		t.Fatalf("Pod %v %v", p, err)
	}
	if _, err := sp.Pod(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Pod past end err = %v", err)
	}
	if _, err := NewStructParser(Int(1)); !errors.Is(err, ErrType) {
		t.Fatalf("NewStructParser(Int) err = %v", err)
	}
	if _, ok := AsObject(s); ok {
		t.Error("AsObject(Struct) ok")
	}
	if _, ok := AsStruct(s); !ok {
		t.Error("AsStruct(Struct) not ok")
	}
	sk := s.Parser()
	must(sk.Skip(2))
	if err := sk.Skip(100); !errors.Is(err, ErrNotFound) {
		t.Errorf("Skip too far err = %v", err)
	}
	if err := sk.Skip(-1); err == nil {
		t.Error("Skip(-1) succeeded")
	}
}

// TestParseDecodedCreateObjectLike parses a message the way the proto
// package will: decode the payload, then walk the Struct.
func TestParseDecodedMessage(t *testing.T) {
	payload := Encode(NewStruct(String("client-node"), String("PipeWire:Interface:ClientNode"),
		Int(6), NewStruct(Int(1), String("node.name"), String("rmm")), Int(2)))
	p, rest, err := Decode(append(payload, Encode(NewStruct(Id(0), NewStruct(Long(1))))...))
	if err != nil || len(rest) == 0 {
		t.Fatalf("decode: %v rest=%d", err, len(rest))
	}
	sp, err := NewStructParser(p)
	if err != nil {
		t.Fatal(err)
	}
	factory, _ := sp.String()
	typ, _ := sp.String()
	ver, _ := sp.Int()
	dict, err := sp.Struct()
	if err != nil {
		t.Fatal(err)
	}
	n, _ := dict.Int()
	k, _ := dict.String()
	v, _ := dict.String()
	id, err := sp.Int()
	if err != nil || factory != "client-node" || typ != "PipeWire:Interface:ClientNode" ||
		ver != 6 || n != 1 || k != "node.name" || v != "rmm" || id != 2 {
		t.Fatalf("parsed %q %q %d %d %q %q %d %v", factory, typ, ver, n, k, v, id, err)
	}
}
