package pod

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// maxDepth bounds container nesting in both directions so that a hostile
// buffer cannot exhaust the stack.
const maxDepth = 32

// Errors returned by Decode and EncodeErr. They are wrapped with detail, so
// compare with errors.Is.
var (
	// ErrTruncated means the buffer ends before the pod does.
	ErrTruncated = errors.New("pod: truncated")
	// ErrInvalid means the bytes are not a valid pod or the value cannot be
	// encoded as one.
	ErrInvalid = errors.New("pod: invalid")
)

func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func put32(dst []byte, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(dst, v)
}

func put64(dst []byte, v uint64) []byte {
	return binary.LittleEndian.AppendUint64(dst, v)
}

func pad8(dst []byte) []byte {
	for len(dst)%8 != 0 {
		dst = append(dst, 0)
	}
	return dst
}

// Encode returns the wire bytes of p, padded to a multiple of 8. A nil Pod is
// written as None. It returns nil when p cannot be encoded (for example an
// Array whose elements do not match its ChildType); use EncodeErr to get the
// reason.
func Encode(p Pod) []byte {
	b, err := EncodeErr(p)
	if err != nil {
		return nil
	}
	return b
}

// EncodeErr is Encode with the error returned.
func EncodeErr(p Pod) ([]byte, error) {
	return AppendEncode(nil, p)
}

// AppendEncode appends the wire bytes of p to dst. On error dst is returned
// unchanged in length.
func AppendEncode(dst []byte, p Pod) ([]byte, error) {
	out, err := appendPod(dst, p, 0)
	if err != nil {
		return dst, err
	}
	return out, nil
}

func appendPod(dst []byte, p Pod, depth int) ([]byte, error) {
	if depth > maxDepth {
		return dst, fmt.Errorf("%w: nesting deeper than %d", ErrInvalid, maxDepth)
	}
	if p == nil {
		p = None{}
	}
	start := len(dst)
	dst = put32(dst, 0)
	dst = put32(dst, p.PodType())
	var err error
	switch v := p.(type) {
	case Struct:
		for i, f := range v.Fields {
			if dst, err = appendPod(dst, f, depth+1); err != nil {
				return dst, fmt.Errorf("struct field %d: %w", i, err)
			}
		}
	case Object:
		dst = put32(dst, v.ObjType)
		dst = put32(dst, v.ID)
		for _, pr := range v.Props {
			dst = put32(dst, pr.Key)
			dst = put32(dst, pr.Flags)
			if dst, err = appendPod(dst, pr.Value, depth+1); err != nil {
				return dst, fmt.Errorf("object property %#x: %w", pr.Key, err)
			}
		}
	case Sequence:
		dst = put32(dst, v.Unit)
		dst = put32(dst, 0)
		for i, c := range v.Controls {
			dst = put32(dst, c.Offset)
			dst = put32(dst, c.Type)
			if dst, err = appendPod(dst, c.Value, depth+1); err != nil {
				return dst, fmt.Errorf("sequence control %d: %w", i, err)
			}
		}
	case Array:
		if dst, err = appendFixedValues(dst, v.ChildType, v.Values); err != nil {
			return dst, fmt.Errorf("array: %w", err)
		}
	case Choice:
		dst = put32(dst, v.Kind)
		dst = put32(dst, v.Flags)
		if dst, err = appendFixedValues(dst, v.ChildType, v.Values); err != nil {
			return dst, fmt.Errorf("choice: %w", err)
		}
	default:
		dst, err = appendScalarBody(dst, p)
		if err != nil {
			return dst, err
		}
	}
	binary.LittleEndian.PutUint32(dst[start:], uint32(len(dst)-start-8))
	return pad8(dst), nil
}

// appendFixedValues writes child_size, child_type and the headerless values
// shared by Array and Choice bodies.
func appendFixedValues(dst []byte, childType uint32, vals []Pod) ([]byte, error) {
	size := fixedSize(childType)
	if size == 0 {
		return dst, fmt.Errorf("%w: child type %s has no fixed size", ErrInvalid, TypeName(childType))
	}
	dst = put32(dst, uint32(size))
	dst = put32(dst, childType)
	for i, v := range vals {
		if v == nil || v.PodType() != childType {
			return dst, fmt.Errorf("%w: value %d is %s, want %s", ErrInvalid, i, podName(v), TypeName(childType))
		}
		var err error
		if dst, err = appendScalarBody(dst, v); err != nil {
			return dst, err
		}
	}
	return dst, nil
}

func appendScalarBody(dst []byte, p Pod) ([]byte, error) {
	switch v := p.(type) {
	case None:
	case Bool:
		var n uint32
		if v {
			n = 1
		}
		dst = put32(dst, n)
	case Id:
		dst = put32(dst, uint32(v))
	case Int:
		dst = put32(dst, uint32(v))
	case Long:
		dst = put64(dst, uint64(v))
	case Float:
		dst = put32(dst, math.Float32bits(float32(v)))
	case Double:
		dst = put64(dst, math.Float64bits(float64(v)))
	case String:
		dst = append(dst, v...)
		dst = append(dst, 0)
	case Bytes:
		dst = append(dst, v...)
	case Bitmap:
		dst = append(dst, v...)
	case Rectangle:
		dst = put32(dst, v.Width)
		dst = put32(dst, v.Height)
	case Fraction:
		dst = put32(dst, v.Num)
		dst = put32(dst, v.Denom)
	case Fd:
		dst = put64(dst, uint64(v))
	case Pointer:
		dst = put32(dst, v.PtrType)
		dst = put32(dst, 0)
		dst = put64(dst, v.Ptr)
	default:
		return dst, fmt.Errorf("%w: cannot encode %T", ErrInvalid, p)
	}
	return dst, nil
}
