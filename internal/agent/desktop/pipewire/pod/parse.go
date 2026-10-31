package pod

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned by the Object getters when the key is absent, and
// by StructParser when no fields are left. Compare with errors.Is.
var ErrNotFound = errors.New("pod: not found")

// ErrType is returned by the getters when a pod has another type than the
// getter reads.
var ErrType = errors.New("pod: wrong type")

// Values returns the kind and the values of p the way spa_pod_get_values
// does: a Choice gives its kind and values, any other pod is a Choice of
// kind None with itself as the only value. Accept both forms wherever a
// param is parsed, because a server sends fixated plain values while a
// producer's EnumFormat carries Choices.
func Values(p Pod) (kind uint32, vals []Pod) {
	if c, ok := p.(Choice); ok {
		return c.Kind, c.Values
	}
	return ChoiceKindNone, []Pod{p}
}

// Default returns the default value of p: the first value of a Choice, or p
// itself when it is not a Choice. It returns nil for an empty Choice.
func Default(p Pod) Pod {
	if c, ok := p.(Choice); ok {
		if len(c.Values) == 0 {
			return nil
		}
		return c.Values[0]
	}
	return p
}

// AsObject returns p as an Object.
func AsObject(p Pod) (Object, bool) {
	o, ok := p.(Object)
	return o, ok
}

// AsStruct returns p as a Struct.
func AsStruct(p Pod) (Struct, bool) {
	s, ok := p.(Struct)
	return s, ok
}

// Find returns the value of the first property with the given key.
func (o Object) Find(key uint32) (Pod, bool) {
	for _, pr := range o.Props {
		if pr.Key == key {
			return pr.Value, true
		}
	}
	return nil, false
}

// Values returns the kind and values of a property, see the package-level
// Values.
func (o Object) Values(key uint32) (uint32, []Pod, error) {
	v, ok := o.Find(key)
	if !ok {
		return 0, nil, fmt.Errorf("%w: property %#x", ErrNotFound, key)
	}
	k, vals := Values(v)
	return k, vals, nil
}

// getDefault finds a property and unwraps a Choice to its default value.
func (o Object) getDefault(key uint32) (Pod, error) {
	v, ok := o.Find(key)
	if !ok {
		return nil, fmt.Errorf("%w: property %#x", ErrNotFound, key)
	}
	d := Default(v)
	if d == nil {
		return nil, fmt.Errorf("%w: property %#x is an empty choice", ErrNotFound, key)
	}
	return d, nil
}

func wrongType(what string, want uint32, got Pod) error {
	return fmt.Errorf("%w: %s is %s, want %s", ErrType, what, podName(got), TypeName(want))
}

// GetId reads an Id property. A Choice is read as its default value.
func (o Object) GetId(key uint32) (uint32, error) {
	d, err := o.getDefault(key)
	if err != nil {
		return 0, err
	}
	v, ok := d.(Id)
	if !ok {
		return 0, wrongType(fmt.Sprintf("property %#x", key), TypeId, d)
	}
	return uint32(v), nil
}

// GetInt reads an Int property. A Choice is read as its default value.
func (o Object) GetInt(key uint32) (int32, error) {
	d, err := o.getDefault(key)
	if err != nil {
		return 0, err
	}
	v, ok := d.(Int)
	if !ok {
		return 0, wrongType(fmt.Sprintf("property %#x", key), TypeInt, d)
	}
	return int32(v), nil
}

// GetLong reads a Long property. A Choice is read as its default value.
func (o Object) GetLong(key uint32) (int64, error) {
	d, err := o.getDefault(key)
	if err != nil {
		return 0, err
	}
	v, ok := d.(Long)
	if !ok {
		return 0, wrongType(fmt.Sprintf("property %#x", key), TypeLong, d)
	}
	return int64(v), nil
}

// GetBool reads a Bool property. A Choice is read as its default value.
func (o Object) GetBool(key uint32) (bool, error) {
	d, err := o.getDefault(key)
	if err != nil {
		return false, err
	}
	v, ok := d.(Bool)
	if !ok {
		return false, wrongType(fmt.Sprintf("property %#x", key), TypeBool, d)
	}
	return bool(v), nil
}

// GetString reads a String property.
func (o Object) GetString(key uint32) (string, error) {
	d, err := o.getDefault(key)
	if err != nil {
		return "", err
	}
	v, ok := d.(String)
	if !ok {
		return "", wrongType(fmt.Sprintf("property %#x", key), TypeString, d)
	}
	return string(v), nil
}

// GetRectangle reads a Rectangle property. A Choice is read as its default
// value.
func (o Object) GetRectangle(key uint32) (Rectangle, error) {
	d, err := o.getDefault(key)
	if err != nil {
		return Rectangle{}, err
	}
	v, ok := d.(Rectangle)
	if !ok {
		return Rectangle{}, wrongType(fmt.Sprintf("property %#x", key), TypeRectangle, d)
	}
	return v, nil
}

// GetFraction reads a Fraction property. A Choice is read as its default
// value.
func (o Object) GetFraction(key uint32) (Fraction, error) {
	d, err := o.getDefault(key)
	if err != nil {
		return Fraction{}, err
	}
	v, ok := d.(Fraction)
	if !ok {
		return Fraction{}, wrongType(fmt.Sprintf("property %#x", key), TypeFraction, d)
	}
	return v, nil
}

// StructParser walks the fields of a Struct in order, with typed getters.
// Every getter consumes one field and returns an error, leaving the position
// unchanged, if there is none or it has the wrong type.
type StructParser struct {
	fields []Pod
	pos    int
}

// NewStructParser returns a parser over the fields of p, which must be a
// Struct.
func NewStructParser(p Pod) (*StructParser, error) {
	s, ok := p.(Struct)
	if !ok {
		return nil, wrongType("pod", TypeStruct, p)
	}
	return &StructParser{fields: s.Fields}, nil
}

// Parser returns a StructParser over s.
func (s Struct) Parser() *StructParser { return &StructParser{fields: s.Fields} }

// Remaining returns the number of fields not yet consumed.
func (sp *StructParser) Remaining() int { return len(sp.fields) - sp.pos }

// Pod consumes and returns the next field of any type.
func (sp *StructParser) Pod() (Pod, error) {
	if sp.pos >= len(sp.fields) {
		return nil, fmt.Errorf("%w: struct has %d fields", ErrNotFound, len(sp.fields))
	}
	p := sp.fields[sp.pos]
	sp.pos++
	return p, nil
}

// Skip consumes n fields.
func (sp *StructParser) Skip(n int) error {
	if n < 0 || sp.Remaining() < n {
		return fmt.Errorf("%w: cannot skip %d of %d remaining fields", ErrNotFound, n, sp.Remaining())
	}
	sp.pos += n
	return nil
}

// peek returns the next field without consuming it.
func (sp *StructParser) peek() (Pod, error) {
	if sp.pos >= len(sp.fields) {
		return nil, fmt.Errorf("%w: struct has %d fields", ErrNotFound, len(sp.fields))
	}
	return sp.fields[sp.pos], nil
}

func (sp *StructParser) fieldErr(want uint32, got Pod) error {
	return wrongType(fmt.Sprintf("struct field %d", sp.pos), want, got)
}

// Bool consumes a Bool.
func (sp *StructParser) Bool() (bool, error) {
	p, err := sp.peek()
	if err != nil {
		return false, err
	}
	v, ok := p.(Bool)
	if !ok {
		return false, sp.fieldErr(TypeBool, p)
	}
	sp.pos++
	return bool(v), nil
}

// Id consumes an Id.
func (sp *StructParser) Id() (uint32, error) {
	p, err := sp.peek()
	if err != nil {
		return 0, err
	}
	v, ok := p.(Id)
	if !ok {
		return 0, sp.fieldErr(TypeId, p)
	}
	sp.pos++
	return uint32(v), nil
}

// Int consumes an Int.
func (sp *StructParser) Int() (int32, error) {
	p, err := sp.peek()
	if err != nil {
		return 0, err
	}
	v, ok := p.(Int)
	if !ok {
		return 0, sp.fieldErr(TypeInt, p)
	}
	sp.pos++
	return int32(v), nil
}

// Long consumes a Long.
func (sp *StructParser) Long() (int64, error) {
	p, err := sp.peek()
	if err != nil {
		return 0, err
	}
	v, ok := p.(Long)
	if !ok {
		return 0, sp.fieldErr(TypeLong, p)
	}
	sp.pos++
	return int64(v), nil
}

// Float consumes a Float.
func (sp *StructParser) Float() (float32, error) {
	p, err := sp.peek()
	if err != nil {
		return 0, err
	}
	v, ok := p.(Float)
	if !ok {
		return 0, sp.fieldErr(TypeFloat, p)
	}
	sp.pos++
	return float32(v), nil
}

// Double consumes a Double.
func (sp *StructParser) Double() (float64, error) {
	p, err := sp.peek()
	if err != nil {
		return 0, err
	}
	v, ok := p.(Double)
	if !ok {
		return 0, sp.fieldErr(TypeDouble, p)
	}
	sp.pos++
	return float64(v), nil
}

// String consumes a String.
func (sp *StructParser) String() (string, error) {
	p, err := sp.peek()
	if err != nil {
		return "", err
	}
	v, ok := p.(String)
	if !ok {
		return "", sp.fieldErr(TypeString, p)
	}
	sp.pos++
	return string(v), nil
}

// OptString consumes a String or a None. The C side writes a NULL string as
// None; present is false for that case.
func (sp *StructParser) OptString() (s string, present bool, err error) {
	p, err := sp.peek()
	if err != nil {
		return "", false, err
	}
	switch v := p.(type) {
	case String:
		sp.pos++
		return string(v), true, nil
	case None:
		sp.pos++
		return "", false, nil
	}
	return "", false, sp.fieldErr(TypeString, p)
}

// Bytes consumes a Bytes pod.
func (sp *StructParser) Bytes() ([]byte, error) {
	p, err := sp.peek()
	if err != nil {
		return nil, err
	}
	v, ok := p.(Bytes)
	if !ok {
		return nil, sp.fieldErr(TypeBytes, p)
	}
	sp.pos++
	return []byte(v), nil
}

// Rectangle consumes a Rectangle.
func (sp *StructParser) Rectangle() (Rectangle, error) {
	p, err := sp.peek()
	if err != nil {
		return Rectangle{}, err
	}
	v, ok := p.(Rectangle)
	if !ok {
		return Rectangle{}, sp.fieldErr(TypeRectangle, p)
	}
	sp.pos++
	return v, nil
}

// Fraction consumes a Fraction.
func (sp *StructParser) Fraction() (Fraction, error) {
	p, err := sp.peek()
	if err != nil {
		return Fraction{}, err
	}
	v, ok := p.(Fraction)
	if !ok {
		return Fraction{}, sp.fieldErr(TypeFraction, p)
	}
	sp.pos++
	return v, nil
}

// Fd consumes an Fd and returns its index into the message's fd array.
func (sp *StructParser) Fd() (int64, error) {
	p, err := sp.peek()
	if err != nil {
		return 0, err
	}
	v, ok := p.(Fd)
	if !ok {
		return 0, sp.fieldErr(TypeFd, p)
	}
	sp.pos++
	return int64(v), nil
}

// Struct consumes a nested Struct and returns a parser over it.
func (sp *StructParser) Struct() (*StructParser, error) {
	p, err := sp.peek()
	if err != nil {
		return nil, err
	}
	v, ok := p.(Struct)
	if !ok {
		return nil, sp.fieldErr(TypeStruct, p)
	}
	sp.pos++
	return v.Parser(), nil
}

// Object consumes an Object.
func (sp *StructParser) Object() (Object, error) {
	p, err := sp.peek()
	if err != nil {
		return Object{}, err
	}
	v, ok := p.(Object)
	if !ok {
		return Object{}, sp.fieldErr(TypeObject, p)
	}
	sp.pos++
	return v, nil
}
