// Package pod encodes and decodes SPA PODs, the self-describing binary values
// that PipeWire uses for params, events, commands and every argument of its
// native protocol.
//
// The package was written from the PipeWire 1.2.7 headers (spa/pod/pod.h,
// iter.h, builder.h, parser.h and spa/utils/type.h) as summarised in
// docs/plans/2026-10-25-pipewire-protocol-notes.md. There was no PipeWire
// daemon to test against, so the byte layout is checked only against
// vectors derived by hand from builder.h, not against traffic from a real
// server.
//
// Wire layout in short: every pod is an 8-byte header (body size u32, type
// u32), the body, then zero bytes up to the next multiple of 8. The size does
// not count the header or the padding after a scalar body, but a Struct or
// Object size counts the padded children, so it is always a multiple of 8.
// Integers are little endian, which is the host order of every PipeWire
// target.
//
// Each POD type is one Go type. Scalars are named basic types, so Int(42),
// Id(8) and String("hi") are already pods. Containers are Struct, Object,
// Array, Choice and Sequence. Encode and Decode convert between a Pod and
// bytes; Builder, ObjectBuilder and the Choice and Array constructors build
// values; StructParser and the Object getters read them.
package pod

import "fmt"

// Pod is any POD value. PodType returns the type id written in the pod
// header (TypeInt, TypeStruct and so on).
type Pod interface {
	PodType() uint32
}

// None is the empty pod. A C NULL value (for example a missing string) is
// written as None.
type None struct{}

// Bool is a boolean, stored as an int32 that is 0 or 1.
type Bool bool

// Id is an unsigned id such as a param id, a format id or a property key.
type Id uint32

// Int is a signed 32-bit integer.
type Int int32

// Long is a signed 64-bit integer.
type Long int64

// Float is a 32-bit float.
type Float float32

// Double is a 64-bit float.
type Double float64

// String is a UTF-8 string. On the wire it carries a terminating NUL that
// the Go value does not.
type String string

// Bytes is an opaque byte string.
type Bytes []byte

// Bitmap is a bit array stored as raw bytes.
type Bitmap []byte

// Rectangle is a width and height.
type Rectangle struct {
	Width, Height uint32
}

// Fraction is a numerator and denominator, for example a frame rate.
type Fraction struct {
	Num, Denom uint32
}

// Fd is an index into the fd array that travels with a native protocol
// message. It is not a file descriptor number. NoFd is the "no fd" value.
type Fd int64

// NoFd is the Fd value a sender writes when there is no fd (SPA_ID_INVALID).
const NoFd Fd = 0xffffffff

// Pointer is a host pointer with a pointer type. It means nothing outside
// the process that wrote it and is only carried for completeness.
type Pointer struct {
	PtrType uint32
	Ptr     uint64
}

// Struct is an ordered list of pods.
type Struct struct {
	Fields []Pod
}

// Prop is one property of an Object: a key, flags and a value pod.
type Prop struct {
	Key   uint32
	Flags uint32
	Value Pod
}

// Object is a typed, id-carrying list of properties. Formats and other
// params are Objects, and so are node commands and events.
type Object struct {
	ObjType uint32
	ID      uint32
	Props   []Prop
}

// Array is a list of values of one fixed-size type. Values carry no header
// on the wire, so every element must have PodType equal to ChildType and the
// type must have a fixed size (Bool, Id, Int, Long, Float, Double,
// Rectangle, Fraction or Fd).
type Array struct {
	ChildType uint32
	Values    []Pod
}

// Choice describes a value that may take several forms: Kind is one of the
// ChoiceKind constants. Values follow the order the kind defines: None has a
// default, Range has default, min, max, Step adds a step, Enum has the
// default followed by the alternatives and Flags has the default followed by
// the flag bits. Like Array, the children are headerless fixed-size values.
type Choice struct {
	Kind      uint32
	Flags     uint32
	ChildType uint32
	Values    []Pod
}

// Control is one entry of a Sequence.
type Control struct {
	Offset uint32
	Type   uint32
	Value  Pod
}

// Sequence is a timed list of controls.
type Sequence struct {
	Unit     uint32
	Controls []Control
}

// PodType implementations.

func (None) PodType() uint32      { return TypeNone }
func (Bool) PodType() uint32      { return TypeBool }
func (Id) PodType() uint32        { return TypeId }
func (Int) PodType() uint32       { return TypeInt }
func (Long) PodType() uint32      { return TypeLong }
func (Float) PodType() uint32     { return TypeFloat }
func (Double) PodType() uint32    { return TypeDouble }
func (String) PodType() uint32    { return TypeString }
func (Bytes) PodType() uint32     { return TypeBytes }
func (Bitmap) PodType() uint32    { return TypeBitmap }
func (Rectangle) PodType() uint32 { return TypeRectangle }
func (Fraction) PodType() uint32  { return TypeFraction }
func (Fd) PodType() uint32        { return TypeFd }
func (Pointer) PodType() uint32   { return TypePointer }
func (Struct) PodType() uint32    { return TypeStruct }
func (Object) PodType() uint32    { return TypeObject }
func (Array) PodType() uint32     { return TypeArray }
func (Choice) PodType() uint32    { return TypeChoice }
func (Sequence) PodType() uint32  { return TypeSequence }

// TypeName returns a short name for a pod type id, for error messages.
func TypeName(t uint32) string {
	switch t {
	case TypeNone:
		return "None"
	case TypeBool:
		return "Bool"
	case TypeId:
		return "Id"
	case TypeInt:
		return "Int"
	case TypeLong:
		return "Long"
	case TypeFloat:
		return "Float"
	case TypeDouble:
		return "Double"
	case TypeString:
		return "String"
	case TypeBytes:
		return "Bytes"
	case TypeRectangle:
		return "Rectangle"
	case TypeFraction:
		return "Fraction"
	case TypeBitmap:
		return "Bitmap"
	case TypeArray:
		return "Array"
	case TypeStruct:
		return "Struct"
	case TypeObject:
		return "Object"
	case TypeSequence:
		return "Sequence"
	case TypePointer:
		return "Pointer"
	case TypeFd:
		return "Fd"
	case TypeChoice:
		return "Choice"
	}
	return fmt.Sprintf("type(%d)", t)
}

func podName(p Pod) string {
	if p == nil {
		return "nil"
	}
	return TypeName(p.PodType())
}

// fixedSize returns the body size of one value of a fixed-size type, or 0
// when the type cannot be an Array or Choice child.
func fixedSize(t uint32) int {
	switch t {
	case TypeBool, TypeId, TypeInt, TypeFloat:
		return 4
	case TypeLong, TypeDouble, TypeRectangle, TypeFraction, TypeFd:
		return 8
	}
	return 0
}
