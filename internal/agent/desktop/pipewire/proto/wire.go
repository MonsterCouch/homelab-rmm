package proto

import (
	"fmt"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

// Limits PipeWire applies while parsing (protocol-native.c and
// module-client-node/protocol-native.c). A decoder checks every count from
// the wire against these before it allocates.
const (
	maxDictItems   = 1024
	maxParamInfos  = 128
	maxParams      = 4096
	maxBuffers     = 64
	maxMetas       = 16
	maxDatas       = 64
	maxPermissions = 4096
)

// DictItem is one key and value of a PipeWire property dict.
type DictItem struct {
	Key, Value string
}

// Dict is an ordered property dict, as sent in Info, CreateObject,
// UpdateProperties, AddPort and PortSetMixInfo.
type Dict []DictItem

// Get returns the value of the first item with the given key.
func (d Dict) Get(key string) (string, bool) {
	for _, it := range d {
		if it.Key == key {
			return it.Value, true
		}
	}
	return "", false
}

// appendInline writes n_items and the key/value strings straight into b, the
// form used inside NodeInfo and PortInfo. A value that starts with "pointer:"
// is sent as an empty string, as push_item does in the C code.
func (d Dict) appendInline(b *pod.Builder) {
	b.Int(int32(len(d)))
	for _, it := range d {
		v := it.Value
		if strings.HasPrefix(v, "pointer:") {
			v = ""
		}
		b.String(it.Key).String(v)
	}
}

// pod returns the dict as the nested Struct form.
func (d Dict) pod() pod.Struct {
	b := pod.NewBuilder()
	d.appendInline(b)
	return b.Build()
}

// wreader reads the fields of one Struct and keeps the first error, so a
// message decoder can read straight through and check once at the end.
type wreader struct {
	sp  *pod.StructParser
	fl  *FdList
	err error
}

func newReader(st pod.Struct, fl *FdList) *wreader {
	return &wreader{sp: st.Parser(), fl: fl}
}

func (r *wreader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *wreader) i32() int32 {
	if r.err != nil {
		return 0
	}
	v, err := r.sp.Int()
	r.fail(err)
	return v
}

func (r *wreader) u32() uint32 { return uint32(r.i32()) }

func (r *wreader) id() uint32 {
	if r.err != nil {
		return 0
	}
	v, err := r.sp.Id()
	r.fail(err)
	return v
}

func (r *wreader) long() int64 {
	if r.err != nil {
		return 0
	}
	v, err := r.sp.Long()
	r.fail(err)
	return v
}

func (r *wreader) boolean() bool {
	if r.err != nil {
		return false
	}
	v, err := r.sp.Bool()
	r.fail(err)
	return v
}

// str reads a String; a None (a C NULL) reads as the empty string.
func (r *wreader) str() string {
	if r.err != nil {
		return ""
	}
	s, _, err := r.sp.OptString()
	r.fail(err)
	return s
}

// fd reads an Fd pod and resolves it through the message's descriptor list.
func (r *wreader) fd() int {
	if r.err != nil {
		return -1
	}
	idx, err := r.sp.Fd()
	if err != nil {
		r.fail(err)
		return -1
	}
	fd, err := r.fl.Get(idx)
	r.fail(err)
	return fd
}

func (r *wreader) pod() pod.Pod {
	if r.err != nil {
		return nil
	}
	p, err := r.sp.Pod()
	r.fail(err)
	return p
}

// count reads an Int that gives a number of items and checks it against max.
func (r *wreader) count(max int, what string) int {
	n := r.i32()
	if r.err != nil {
		return 0
	}
	if n < 0 || int(n) > max {
		r.fail(fmt.Errorf("%s count %d is outside 0..%d", what, n, max))
		return 0
	}
	return int(n)
}

// sub reads a nested Struct.
func (r *wreader) sub() *wreader {
	if r.err != nil {
		return &wreader{sp: pod.Struct{}.Parser(), fl: r.fl, err: r.err}
	}
	sp, err := r.sp.Struct()
	if err != nil {
		r.fail(err)
		return &wreader{sp: pod.Struct{}.Parser(), fl: r.fl, err: err}
	}
	return &wreader{sp: sp, fl: r.fl}
}

// optSub reads a nested Struct, or None, which gives nil.
func (r *wreader) optSub() *wreader {
	p := r.pod()
	if r.err != nil {
		return nil
	}
	switch v := p.(type) {
	case pod.None:
		return nil
	case pod.Struct:
		return &wreader{sp: v.Parser(), fl: r.fl}
	}
	r.fail(fmt.Errorf("expected a Struct or None, found %s", pod.TypeName(p.PodType())))
	return nil
}

// dictInline reads n_items and the key/value pairs from the current Struct.
func (r *wreader) dictInline() Dict {
	n := r.count(maxDictItems, "dict item")
	if n == 0 {
		return nil
	}
	d := make(Dict, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		k := r.str()
		v := r.str()
		d = append(d, DictItem{Key: k, Value: v})
	}
	return d
}

// dict reads a dict that is a nested Struct. A missing field reads as an
// empty dict, so a decoder tolerates an older server that omits it.
func (r *wreader) dict() Dict {
	if r.err == nil && r.sp.Remaining() == 0 {
		return nil
	}
	s := r.sub()
	d := s.dictInline()
	r.fail(s.err)
	return d
}

// params reads n_params and that many pods.
func (r *wreader) params() []pod.Pod {
	n := r.count(maxParams, "param")
	var out []pod.Pod
	for i := 0; i < n && r.err == nil; i++ {
		out = append(out, r.pod())
	}
	return out
}

// paramInfos reads n_params and that many (Id param_id, Int flags) pairs.
func (r *wreader) paramInfos() []ParamInfo {
	n := r.count(maxParamInfos, "param info")
	var out []ParamInfo
	for i := 0; i < n && r.err == nil; i++ {
		out = append(out, ParamInfo{ID: r.id(), Flags: r.u32()})
	}
	return out
}

// ParamInfo describes one param a node or port can enumerate or accept.
type ParamInfo struct {
	ID    uint32
	Flags uint32
}

// Param info flags (spa/param/param.h).
const (
	ParamInfoSerial uint32 = 1 << 0
	ParamInfoRead   uint32 = 1 << 1
	ParamInfoWrite  uint32 = 1 << 2
)

func appendParamInfos(b *pod.Builder, infos []ParamInfo) {
	b.Int(int32(len(infos)))
	for _, p := range infos {
		b.Id(p.ID).Int(int32(p.Flags))
	}
}

func appendParams(b *pod.Builder, params []pod.Pod) {
	b.Int(int32(len(params)))
	for _, p := range params {
		b.Pod(orNone(p))
	}
}

// orNone turns a nil Pod into None, which is how a C NULL is written.
func orNone(p pod.Pod) pod.Pod {
	if p == nil {
		return pod.None{}
	}
	return p
}

// IsNone reports whether p is absent or the None pod.
func IsNone(p pod.Pod) bool {
	if p == nil {
		return true
	}
	_, ok := p.(pod.None)
	return ok
}

// opTable maps an opcode to a function that decodes that message's fields.
type opTable map[uint8]func(r *wreader) any

type unmarshaler[T any] interface {
	*T
	unmarshal(r *wreader)
}

// dec returns a table entry that decodes into a fresh T.
func dec[T any, PT unmarshaler[T]]() func(r *wreader) any {
	return func(r *wreader) any {
		var v T
		PT(&v).unmarshal(r)
		return v
	}
}

// decode runs the table entry for op over st.
func (t opTable) decode(what string, op uint8, st pod.Struct, fl *FdList) (any, error) {
	f, ok := t[op]
	if !ok {
		return nil, fmt.Errorf("%w: %s opcode %d", errUnknownOpcode, what, op)
	}
	r := newReader(st, fl)
	v := f(r)
	if r.err != nil {
		return nil, &decodeError{fmt.Errorf("proto: decoding %s opcode %d: %w", what, op, r.err)}
	}
	return v, nil
}

// decodeError marks a message whose fields did not match its layout. No
// handler saw the message, so the connection still owns its descriptors.
type decodeError struct{ err error }

func (e *decodeError) Error() string { return e.err.Error() }
func (e *decodeError) Unwrap() error { return e.err }
