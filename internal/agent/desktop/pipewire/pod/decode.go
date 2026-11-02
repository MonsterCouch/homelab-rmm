package pod

import (
	"fmt"
	"math"
)

// Decode reads one pod from the start of b and returns it with the bytes that
// follow it. The pod, including its padding to a multiple of 8, must lie
// completely inside b, as in a message payload built by PipeWire; a buffer
// that ends inside the padding is reported as truncated. Bytes after the pod
// are returned untouched, which is how a footer after a message Struct is
// skipped. Decode never panics on malformed input.
func Decode(b []byte) (Pod, []byte, error) {
	return decode(b, 0)
}

func decode(b []byte, depth int) (Pod, []byte, error) {
	if depth > maxDepth {
		return nil, nil, fmt.Errorf("%w: nesting deeper than %d", ErrInvalid, maxDepth)
	}
	if len(b) < 8 {
		return nil, nil, fmt.Errorf("%w: need 8 header bytes, have %d", ErrTruncated, len(b))
	}
	size := uint64(le32(b))
	typ := le32(b[4:])
	total := 8 + (size+7)&^7
	if total > uint64(len(b)) {
		return nil, nil, fmt.Errorf("%w: %s pod of body size %d needs %d bytes, have %d",
			ErrTruncated, TypeName(typ), size, total, len(b))
	}
	p, err := decodeBody(typ, b[8:8+size], depth)
	if err != nil {
		return nil, nil, err
	}
	return p, b[total:], nil
}

func decodeBody(typ uint32, body []byte, depth int) (Pod, error) {
	switch typ {
	case TypeStruct:
		var fields []Pod
		for rest := body; len(rest) > 0; {
			f, r, err := decode(rest, depth+1)
			if err != nil {
				return nil, fmt.Errorf("struct field %d: %w", len(fields), err)
			}
			fields = append(fields, f)
			rest = r
		}
		return Struct{Fields: fields}, nil
	case TypeObject:
		if len(body) < 8 {
			return nil, fmt.Errorf("%w: object body is %d bytes, need 8", ErrTruncated, len(body))
		}
		o := Object{ObjType: le32(body), ID: le32(body[4:])}
		for rest := body[8:]; len(rest) > 0; {
			if len(rest) < 8 {
				return nil, fmt.Errorf("%w: property header", ErrTruncated)
			}
			key, flags := le32(rest), le32(rest[4:])
			v, r, err := decode(rest[8:], depth+1)
			if err != nil {
				return nil, fmt.Errorf("object property %#x: %w", key, err)
			}
			o.Props = append(o.Props, Prop{Key: key, Flags: flags, Value: v})
			rest = r
		}
		return o, nil
	case TypeSequence:
		if len(body) < 8 {
			return nil, fmt.Errorf("%w: sequence body is %d bytes, need 8", ErrTruncated, len(body))
		}
		s := Sequence{Unit: le32(body)}
		for rest := body[8:]; len(rest) > 0; {
			if len(rest) < 8 {
				return nil, fmt.Errorf("%w: control header", ErrTruncated)
			}
			c := Control{Offset: le32(rest), Type: le32(rest[4:])}
			v, r, err := decode(rest[8:], depth+1)
			if err != nil {
				return nil, fmt.Errorf("sequence control %d: %w", len(s.Controls), err)
			}
			c.Value = v
			s.Controls = append(s.Controls, c)
			rest = r
		}
		return s, nil
	case TypeArray:
		if len(body) < 8 {
			return nil, fmt.Errorf("%w: array body is %d bytes, need 8", ErrTruncated, len(body))
		}
		ct, vals, err := decodeFixedValues(body)
		if err != nil {
			return nil, fmt.Errorf("array: %w", err)
		}
		return Array{ChildType: ct, Values: vals}, nil
	case TypeChoice:
		if len(body) < 16 {
			return nil, fmt.Errorf("%w: choice body is %d bytes, need 16", ErrTruncated, len(body))
		}
		ct, vals, err := decodeFixedValues(body[8:])
		if err != nil {
			return nil, fmt.Errorf("choice: %w", err)
		}
		return Choice{Kind: le32(body), Flags: le32(body[4:]), ChildType: ct, Values: vals}, nil
	}
	return decodeScalar(typ, body)
}

// decodeFixedValues reads child_size, child_type and the values that follow.
func decodeFixedValues(b []byte) (uint32, []Pod, error) {
	childSize, childType := le32(b), le32(b[4:])
	want := fixedSize(childType)
	if want == 0 {
		return 0, nil, fmt.Errorf("%w: child type %s has no fixed size", ErrInvalid, TypeName(childType))
	}
	if int64(childSize) != int64(want) {
		return 0, nil, fmt.Errorf("%w: child size %d for %s, want %d", ErrInvalid, childSize, TypeName(childType), want)
	}
	data := b[8:]
	if len(data)%want != 0 {
		return 0, nil, fmt.Errorf("%w: %d value bytes is not a multiple of %d", ErrInvalid, len(data), want)
	}
	var vals []Pod
	for i := 0; i < len(data); i += want {
		v, err := decodeScalar(childType, data[i:i+want])
		if err != nil {
			return 0, nil, err
		}
		vals = append(vals, v)
	}
	return childType, vals, nil
}

func need(typ uint32, body []byte, n int) error {
	if len(body) < n {
		return fmt.Errorf("%w: %s body is %d bytes, need %d", ErrTruncated, TypeName(typ), len(body), n)
	}
	return nil
}

func decodeScalar(typ uint32, body []byte) (Pod, error) {
	switch typ {
	case TypeNone:
		return None{}, nil
	case TypeBool:
		if err := need(typ, body, 4); err != nil {
			return nil, err
		}
		return Bool(le32(body) != 0), nil
	case TypeId:
		if err := need(typ, body, 4); err != nil {
			return nil, err
		}
		return Id(le32(body)), nil
	case TypeInt:
		if err := need(typ, body, 4); err != nil {
			return nil, err
		}
		return Int(int32(le32(body))), nil
	case TypeLong:
		if err := need(typ, body, 8); err != nil {
			return nil, err
		}
		return Long(int64(le64(body))), nil
	case TypeFloat:
		if err := need(typ, body, 4); err != nil {
			return nil, err
		}
		return Float(math.Float32frombits(le32(body))), nil
	case TypeDouble:
		if err := need(typ, body, 8); err != nil {
			return nil, err
		}
		return Double(math.Float64frombits(le64(body))), nil
	case TypeString:
		if len(body) == 0 || body[len(body)-1] != 0 {
			return nil, fmt.Errorf("%w: string is not NUL terminated", ErrInvalid)
		}
		return String(body[:len(body)-1]), nil
	case TypeBytes:
		return Bytes(append([]byte{}, body...)), nil
	case TypeBitmap:
		return Bitmap(append([]byte{}, body...)), nil
	case TypeRectangle:
		if err := need(typ, body, 8); err != nil {
			return nil, err
		}
		return Rectangle{Width: le32(body), Height: le32(body[4:])}, nil
	case TypeFraction:
		if err := need(typ, body, 8); err != nil {
			return nil, err
		}
		return Fraction{Num: le32(body), Denom: le32(body[4:])}, nil
	case TypeFd:
		if err := need(typ, body, 8); err != nil {
			return nil, err
		}
		return Fd(int64(le64(body))), nil
	case TypePointer:
		if err := need(typ, body, 16); err != nil {
			return nil, err
		}
		return Pointer{PtrType: le32(body), Ptr: le64(body[8:])}, nil
	}
	return nil, fmt.Errorf("%w: unknown pod type %d", ErrInvalid, typ)
}
