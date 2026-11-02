package proto

import (
	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

// Client methods, client to server (client.h). Opcode 0 is AddListener.
const (
	ClientMethodError             uint8 = 1
	ClientMethodUpdateProperties  uint8 = 2
	ClientMethodGetPermissions    uint8 = 3
	ClientMethodUpdatePermissions uint8 = 4
)

// Client events, server to client.
const (
	ClientEventInfo        uint8 = 0
	ClientEventPermissions uint8 = 1
)

// Permission is one (object id, permission bits) pair.
type Permission struct {
	ID          uint32
	Permissions uint32
}

func appendPermissions(b *pod.Builder, items []Permission) {
	b.Int(int32(len(items)))
	for _, p := range items {
		b.Int(int32(p.ID)).Int(int32(p.Permissions))
	}
}

func (r *wreader) permissions() []Permission {
	n := r.count(maxPermissions, "permission")
	var out []Permission
	for i := 0; i < n && r.err == nil; i++ {
		out = append(out, Permission{ID: r.u32(), Permissions: r.u32()})
	}
	return out
}

// ClientErrorMethod is the Client.Error method, Struct{Int id, Int res,
// String error}.
type ClientErrorMethod struct {
	ID, Res int32
	Error   string
}

func (ClientErrorMethod) Opcode() uint8 { return ClientMethodError }
func (m ClientErrorMethod) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.ID).Int(m.Res).String(m.Error).Build()
}
func (m *ClientErrorMethod) unmarshal(r *wreader) { m.ID, m.Res, m.Error = r.i32(), r.i32(), r.str() }

// ClientUpdateProperties is Client.UpdateProperties, Struct{Dict props} with
// the dict as a nested Struct.
type ClientUpdateProperties struct{ Props Dict }

func (ClientUpdateProperties) Opcode() uint8 { return ClientMethodUpdateProperties }
func (m ClientUpdateProperties) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Pod(m.Props.pod()).Build()
}
func (m *ClientUpdateProperties) unmarshal(r *wreader) { m.Props = r.dict() }

// ClientGetPermissions is Client.GetPermissions, Struct{Int index, Int num}.
type ClientGetPermissions struct{ Index, Num int32 }

func (ClientGetPermissions) Opcode() uint8 { return ClientMethodGetPermissions }
func (m ClientGetPermissions) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.Index).Int(m.Num).Build()
}
func (m *ClientGetPermissions) unmarshal(r *wreader) { m.Index, m.Num = r.i32(), r.i32() }

// ClientUpdatePermissions is Client.UpdatePermissions, Struct{Int n, (Int id,
// Int permissions)*n}.
type ClientUpdatePermissions struct{ Items []Permission }

func (ClientUpdatePermissions) Opcode() uint8 { return ClientMethodUpdatePermissions }
func (m ClientUpdatePermissions) Marshal(*FdSet) pod.Struct {
	b := pod.NewBuilder()
	appendPermissions(b, m.Items)
	return b.Build()
}
func (m *ClientUpdatePermissions) unmarshal(r *wreader) { m.Items = r.permissions() }

// ClientInfo is the Client.Info event, Struct{Int id, Long change_mask, Dict
// props}.
type ClientInfo struct {
	ID         uint32
	ChangeMask int64
	Props      Dict
}

func (ClientInfo) Opcode() uint8 { return ClientEventInfo }
func (m ClientInfo) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.ID)).Long(m.ChangeMask).Pod(m.Props.pod()).Build()
}
func (m *ClientInfo) unmarshal(r *wreader) {
	m.ID, m.ChangeMask = r.u32(), r.long()
	m.Props = r.dict()
}

// ClientPermissions is the Client.Permissions event, Struct{Int index,
// Struct{Int n, (Int id, Int permissions)*n}}.
type ClientPermissions struct {
	Index int32
	Items []Permission
}

func (ClientPermissions) Opcode() uint8 { return ClientEventPermissions }
func (m ClientPermissions) Marshal(*FdSet) pod.Struct {
	inner := pod.NewBuilder()
	appendPermissions(inner, m.Items)
	return pod.NewBuilder().Int(m.Index).Pod(inner.Build()).Build()
}
func (m *ClientPermissions) unmarshal(r *wreader) {
	m.Index = r.i32()
	s := r.sub()
	m.Items = s.permissions()
	r.fail(s.err)
}

var clientMethods = opTable{
	ClientMethodError:             dec[ClientErrorMethod](),
	ClientMethodUpdateProperties:  dec[ClientUpdateProperties](),
	ClientMethodGetPermissions:    dec[ClientGetPermissions](),
	ClientMethodUpdatePermissions: dec[ClientUpdatePermissions](),
}

var clientEvents = opTable{
	ClientEventInfo:        dec[ClientInfo](),
	ClientEventPermissions: dec[ClientPermissions](),
}

// DecodeClientEvent decodes a server-to-client message for the client object
// (id 1).
func DecodeClientEvent(op uint8, st pod.Struct, fl *FdList) (any, error) {
	return clientEvents.decode("Client event", op, st, fl)
}

// DecodeClientMethod decodes a client-to-server message for the client object.
func DecodeClientMethod(op uint8, st pod.Struct, fl *FdList) (any, error) {
	return clientMethods.decode("Client method", op, st, fl)
}
