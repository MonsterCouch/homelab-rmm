package pod

// Rect returns a Rectangle.
func Rect(width, height uint32) Rectangle { return Rectangle{Width: width, Height: height} }

// Frac returns a Fraction.
func Frac(num, denom uint32) Fraction { return Fraction{Num: num, Denom: denom} }

// NewStruct returns a Struct of the given fields.
func NewStruct(fields ...Pod) Struct { return Struct{Fields: fields} }

// NewObject returns an Object of the given object type and id.
func NewObject(objType, id uint32, props ...Prop) Object {
	return Object{ObjType: objType, ID: id, Props: props}
}

// P returns a property with flags 0.
func P(key uint32, value Pod) Prop { return Prop{Key: key, Value: value} }

// PF returns a property with explicit flags.
func PF(key, flags uint32, value Pod) Prop { return Prop{Key: key, Flags: flags, Value: value} }

// NewArray returns an Array of the given child type. All values must have
// that type.
func NewArray(childType uint32, values ...Pod) Array {
	return Array{ChildType: childType, Values: values}
}

// ArrayIds returns an Array of Id values.
func ArrayIds(ids ...uint32) Array {
	a := Array{ChildType: TypeId}
	for _, v := range ids {
		a.Values = append(a.Values, Id(v))
	}
	return a
}

// ArrayInts returns an Array of Int values.
func ArrayInts(ints ...int32) Array {
	a := Array{ChildType: TypeInt}
	for _, v := range ints {
		a.Values = append(a.Values, Int(v))
	}
	return a
}

// ArrayLongs returns an Array of Long values.
func ArrayLongs(longs ...int64) Array {
	a := Array{ChildType: TypeLong}
	for _, v := range longs {
		a.Values = append(a.Values, Long(v))
	}
	return a
}

func childTypeOf(p Pod) uint32 {
	if p == nil {
		return 0
	}
	return p.PodType()
}

func choice(kind uint32, values ...Pod) Choice {
	return Choice{Kind: kind, ChildType: childTypeOf(values[0]), Values: values}
}

// ChoiceNone returns a Choice that holds only a default value.
func ChoiceNone(def Pod) Choice { return choice(ChoiceKindNone, def) }

// ChoiceRange returns a Choice with a default and an inclusive range.
func ChoiceRange(def, min, max Pod) Choice { return choice(ChoiceKindRange, def, min, max) }

// ChoiceStep returns a Choice with a default, a range and a step.
func ChoiceStep(def, min, max, step Pod) Choice {
	return choice(ChoiceKindStep, def, min, max, step)
}

// ChoiceEnum returns a Choice with a default and a list of alternatives.
// PipeWire's own applications repeat the default as the first alternative,
// so ChoiceEnum(Id(8), Id(8), Id(7)) is the usual spelling.
func ChoiceEnum(def Pod, alts ...Pod) Choice {
	return choice(ChoiceKindEnum, append([]Pod{def}, alts...)...)
}

// ChoiceFlags returns a Choice with a default and the possible flag bits.
func ChoiceFlags(def Pod, flags ...Pod) Choice {
	return choice(ChoiceKindFlags, append([]Pod{def}, flags...)...)
}

// Builder collects the fields of a Struct. Methods return the builder so
// calls chain.
type Builder struct {
	fields []Pod
}

// NewBuilder returns an empty Struct builder.
func NewBuilder() *Builder { return &Builder{} }

// Pod appends any pod.
func (b *Builder) Pod(p Pod) *Builder { b.fields = append(b.fields, p); return b }

// None appends a None pod.
func (b *Builder) None() *Builder { return b.Pod(None{}) }

// Bool appends a Bool.
func (b *Builder) Bool(v bool) *Builder { return b.Pod(Bool(v)) }

// Int appends an Int.
func (b *Builder) Int(v int32) *Builder { return b.Pod(Int(v)) }

// Long appends a Long.
func (b *Builder) Long(v int64) *Builder { return b.Pod(Long(v)) }

// Id appends an Id.
func (b *Builder) Id(v uint32) *Builder { return b.Pod(Id(v)) }

// Float appends a Float.
func (b *Builder) Float(v float32) *Builder { return b.Pod(Float(v)) }

// Double appends a Double.
func (b *Builder) Double(v float64) *Builder { return b.Pod(Double(v)) }

// String appends a String.
func (b *Builder) String(v string) *Builder { return b.Pod(String(v)) }

// Bytes appends a Bytes pod.
func (b *Builder) Bytes(v []byte) *Builder { return b.Pod(Bytes(v)) }

// Rectangle appends a Rectangle.
func (b *Builder) Rectangle(w, h uint32) *Builder { return b.Pod(Rect(w, h)) }

// Fraction appends a Fraction.
func (b *Builder) Fraction(num, denom uint32) *Builder { return b.Pod(Frac(num, denom)) }

// Fd appends an Fd index. Use NoFd for "no fd".
func (b *Builder) Fd(index int64) *Builder { return b.Pod(Fd(index)) }

// Build returns the Struct built so far.
func (b *Builder) Build() Struct { return Struct{Fields: append([]Pod(nil), b.fields...)} }

// ObjectBuilder collects the properties of an Object. All properties get
// flags 0 unless added with Prop.
type ObjectBuilder struct {
	obj Object
}

// NewObjectBuilder returns a builder for an Object of the given type and id.
func NewObjectBuilder(objType, id uint32) *ObjectBuilder {
	return &ObjectBuilder{obj: Object{ObjType: objType, ID: id}}
}

// Prop appends a property with explicit flags.
func (o *ObjectBuilder) Prop(key, flags uint32, value Pod) *ObjectBuilder {
	o.obj.Props = append(o.obj.Props, Prop{Key: key, Flags: flags, Value: value})
	return o
}

// Pod appends a property with flags 0.
func (o *ObjectBuilder) Pod(key uint32, value Pod) *ObjectBuilder {
	return o.Prop(key, 0, value)
}

// Bool appends a Bool property.
func (o *ObjectBuilder) Bool(key uint32, v bool) *ObjectBuilder { return o.Pod(key, Bool(v)) }

// Int appends an Int property.
func (o *ObjectBuilder) Int(key uint32, v int32) *ObjectBuilder { return o.Pod(key, Int(v)) }

// Long appends a Long property.
func (o *ObjectBuilder) Long(key uint32, v int64) *ObjectBuilder { return o.Pod(key, Long(v)) }

// Id appends an Id property.
func (o *ObjectBuilder) Id(key, v uint32) *ObjectBuilder { return o.Pod(key, Id(v)) }

// String appends a String property.
func (o *ObjectBuilder) String(key uint32, v string) *ObjectBuilder { return o.Pod(key, String(v)) }

// Rectangle appends a Rectangle property.
func (o *ObjectBuilder) Rectangle(key, w, h uint32) *ObjectBuilder {
	return o.Pod(key, Rect(w, h))
}

// Fraction appends a Fraction property.
func (o *ObjectBuilder) Fraction(key, num, denom uint32) *ObjectBuilder {
	return o.Pod(key, Frac(num, denom))
}

// Build returns the Object built so far.
func (o *ObjectBuilder) Build() Object {
	out := o.obj
	out.Props = append([]Prop(nil), o.obj.Props...)
	return out
}
