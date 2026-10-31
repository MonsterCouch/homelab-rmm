package proto

import (
	"fmt"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

// Interface names and versions (core.h, client.h, extensions/client-node.h).
const (
	InterfaceCore       = "PipeWire:Interface:Core"
	InterfaceClient     = "PipeWire:Interface:Client"
	InterfaceClientNode = "PipeWire:Interface:ClientNode"
	InterfaceNode       = "PipeWire:Interface:Node"
	InterfaceRegistry   = "PipeWire:Interface:Registry"

	// VersionCore is the Core interface version sent in Hello.
	VersionCore = 4
	// VersionClient is the Client interface version.
	VersionClient = 3
	// VersionClientNode is the ClientNode interface version sent in CreateObject.
	VersionClientNode = 6
)

// Core methods, client to server (core.h). Opcode 0 is AddListener, which is
// local and never on the wire.
const (
	CoreMethodHello        uint8 = 1
	CoreMethodSync         uint8 = 2
	CoreMethodPong         uint8 = 3
	CoreMethodError        uint8 = 4
	CoreMethodGetRegistry  uint8 = 5
	CoreMethodCreateObject uint8 = 6
	CoreMethodDestroy      uint8 = 7
)

// Core events, server to client.
const (
	CoreEventInfo       uint8 = 0
	CoreEventDone       uint8 = 1
	CoreEventPing       uint8 = 2
	CoreEventError      uint8 = 3
	CoreEventRemoveId   uint8 = 4
	CoreEventBoundId    uint8 = 5
	CoreEventAddMem     uint8 = 6
	CoreEventRemoveMem  uint8 = 7
	CoreEventBoundProps uint8 = 8
)

// CoreHello is Core.Hello, Struct{Int version}.
type CoreHello struct{ Version int32 }

func (CoreHello) Opcode() uint8 { return CoreMethodHello }
func (m CoreHello) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.Version).Build()
}
func (m *CoreHello) unmarshal(r *wreader) { m.Version = r.i32() }

// CoreSync is Core.Sync, Struct{Int id, Int seq}. Seq is AsyncBit | the
// header sequence number of the Sync message itself.
type CoreSync struct{ ID, Seq int32 }

func (CoreSync) Opcode() uint8 { return CoreMethodSync }
func (m CoreSync) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.ID).Int(m.Seq).Build()
}
func (m *CoreSync) unmarshal(r *wreader) { m.ID, m.Seq = r.i32(), r.i32() }

// CorePong is Core.Pong, Struct{Int id, Int seq}, echoing a Ping.
type CorePong struct{ ID, Seq int32 }

func (CorePong) Opcode() uint8 { return CoreMethodPong }
func (m CorePong) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.ID).Int(m.Seq).Build()
}
func (m *CorePong) unmarshal(r *wreader) { m.ID, m.Seq = r.i32(), r.i32() }

// CoreError is the Core.Error method, Struct{Int id, Int seq, Int res, String
// message}. A client reports an error on proxy ID with the header sequence
// number of the message that caused it.
type CoreError struct {
	ID, Seq, Res int32
	Message      string
}

func (CoreError) Opcode() uint8 { return CoreMethodError }
func (m CoreError) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.ID).Int(m.Seq).Int(m.Res).String(m.Message).Build()
}
func (m *CoreError) unmarshal(r *wreader) {
	m.ID, m.Seq, m.Res, m.Message = r.i32(), r.i32(), r.i32(), r.str()
}

// CoreGetRegistry is Core.GetRegistry, Struct{Int version, Int new_id}.
type CoreGetRegistry struct {
	Version int32
	NewID   uint32
}

func (CoreGetRegistry) Opcode() uint8 { return CoreMethodGetRegistry }
func (m CoreGetRegistry) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.Version).Int(int32(m.NewID)).Build()
}
func (m *CoreGetRegistry) unmarshal(r *wreader) { m.Version, m.NewID = r.i32(), r.u32() }

// CoreCreateObject is Core.CreateObject, Struct{String factory_name, String
// type, Int version, Dict props, Int new_id}.
type CoreCreateObject struct {
	FactoryName string
	Type        string
	Version     uint32
	Props       Dict
	NewID       uint32
}

func (CoreCreateObject) Opcode() uint8 { return CoreMethodCreateObject }
func (m CoreCreateObject) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().String(m.FactoryName).String(m.Type).Int(int32(m.Version)).
		Pod(m.Props.pod()).Int(int32(m.NewID)).Build()
}
func (m *CoreCreateObject) unmarshal(r *wreader) {
	m.FactoryName, m.Type, m.Version = r.str(), r.str(), r.u32()
	m.Props = r.dict()
	m.NewID = r.u32()
}

// CoreDestroy is Core.Destroy, Struct{Int id}, the proxy id to destroy.
type CoreDestroy struct{ ID uint32 }

func (CoreDestroy) Opcode() uint8 { return CoreMethodDestroy }
func (m CoreDestroy) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.ID)).Build()
}
func (m *CoreDestroy) unmarshal(r *wreader) { m.ID = r.u32() }

// CoreInfo is the Core.Info event, Struct{Int id, Int cookie, String
// user_name, String host_name, String version, String name, Long
// change_mask, Dict props}.
type CoreInfo struct {
	ID         uint32
	Cookie     int32
	UserName   string
	HostName   string
	Version    string
	Name       string
	ChangeMask int64
	Props      Dict
}

func (CoreInfo) Opcode() uint8 { return CoreEventInfo }
func (m CoreInfo) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.ID)).Int(m.Cookie).String(m.UserName).String(m.HostName).
		String(m.Version).String(m.Name).Long(m.ChangeMask).Pod(m.Props.pod()).Build()
}
func (m *CoreInfo) unmarshal(r *wreader) {
	m.ID, m.Cookie = r.u32(), r.i32()
	m.UserName, m.HostName, m.Version, m.Name = r.str(), r.str(), r.str(), r.str()
	m.ChangeMask = r.long()
	m.Props = r.dict()
}

// CoreDone is the Core.Done event, Struct{Int id, Int seq}.
type CoreDone struct{ ID, Seq int32 }

func (CoreDone) Opcode() uint8 { return CoreEventDone }
func (m CoreDone) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.ID).Int(m.Seq).Build()
}
func (m *CoreDone) unmarshal(r *wreader) { m.ID, m.Seq = r.i32(), r.i32() }

// CorePing is the Core.Ping event, Struct{Int id, Int seq}. A Conn answers it
// with Pong on its own.
type CorePing struct{ ID, Seq int32 }

func (CorePing) Opcode() uint8 { return CoreEventPing }
func (m CorePing) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.ID).Int(m.Seq).Build()
}
func (m *CorePing) unmarshal(r *wreader) { m.ID, m.Seq = r.i32(), r.i32() }

// CoreErrorEvent is the Core.Error event, Struct{Int id, Int seq, Int res,
// String message}. Res is a negative errno.
type CoreErrorEvent struct {
	ID, Seq, Res int32
	Message      string
}

func (CoreErrorEvent) Opcode() uint8 { return CoreEventError }
func (m CoreErrorEvent) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.ID).Int(m.Seq).Int(m.Res).String(m.Message).Build()
}
func (m *CoreErrorEvent) unmarshal(r *wreader) {
	m.ID, m.Seq, m.Res, m.Message = r.i32(), r.i32(), r.i32(), r.str()
}

// CoreRemoveId is the Core.RemoveId event, Struct{Int id}.
type CoreRemoveId struct{ ID uint32 }

func (CoreRemoveId) Opcode() uint8 { return CoreEventRemoveId }
func (m CoreRemoveId) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.ID)).Build()
}
func (m *CoreRemoveId) unmarshal(r *wreader) { m.ID = r.u32() }

// CoreBoundId is the Core.BoundId event, Struct{Int id, Int global_id}.
type CoreBoundId struct{ ID, GlobalID uint32 }

func (CoreBoundId) Opcode() uint8 { return CoreEventBoundId }
func (m CoreBoundId) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.ID)).Int(int32(m.GlobalID)).Build()
}
func (m *CoreBoundId) unmarshal(r *wreader) { m.ID, m.GlobalID = r.u32(), r.u32() }

// CoreBoundProps is the Core.BoundProps event, Struct{Int id, Int global_id,
// Dict props}.
type CoreBoundProps struct {
	ID, GlobalID uint32
	Props        Dict
}

func (CoreBoundProps) Opcode() uint8 { return CoreEventBoundProps }
func (m CoreBoundProps) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.ID)).Int(int32(m.GlobalID)).Pod(m.Props.pod()).Build()
}
func (m *CoreBoundProps) unmarshal(r *wreader) {
	m.ID, m.GlobalID = r.u32(), r.u32()
	m.Props = r.dict()
}

// CoreAddMem is the Core.AddMem event, Struct{Int id, Id type, Fd fd_index,
// Int flags}. Fd is the received descriptor (the Fd pod index already
// resolved), or -1 when the server sent none. Type is a spa_data_type.
type CoreAddMem struct {
	ID    uint32
	Type  uint32
	Fd    int
	Flags uint32
}

func (CoreAddMem) Opcode() uint8 { return CoreEventAddMem }
func (m CoreAddMem) Marshal(fds *FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.ID)).Id(m.Type).Pod(fds.Index(m.Fd)).Int(int32(m.Flags)).Build()
}
func (m *CoreAddMem) unmarshal(r *wreader) {
	m.ID, m.Type, m.Fd, m.Flags = r.u32(), r.id(), r.fd(), r.u32()
}

// CoreRemoveMem is the Core.RemoveMem event, Struct{Int id}.
type CoreRemoveMem struct{ ID uint32 }

func (CoreRemoveMem) Opcode() uint8 { return CoreEventRemoveMem }
func (m CoreRemoveMem) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.ID)).Build()
}
func (m *CoreRemoveMem) unmarshal(r *wreader) { m.ID = r.u32() }

var coreMethods = opTable{
	CoreMethodHello:        dec[CoreHello](),
	CoreMethodSync:         dec[CoreSync](),
	CoreMethodPong:         dec[CorePong](),
	CoreMethodError:        dec[CoreError](),
	CoreMethodGetRegistry:  dec[CoreGetRegistry](),
	CoreMethodCreateObject: dec[CoreCreateObject](),
	CoreMethodDestroy:      dec[CoreDestroy](),
}

var coreEvents = opTable{
	CoreEventInfo:       dec[CoreInfo](),
	CoreEventDone:       dec[CoreDone](),
	CoreEventPing:       dec[CorePing](),
	CoreEventError:      dec[CoreErrorEvent](),
	CoreEventRemoveId:   dec[CoreRemoveId](),
	CoreEventBoundId:    dec[CoreBoundId](),
	CoreEventAddMem:     dec[CoreAddMem](),
	CoreEventRemoveMem:  dec[CoreRemoveMem](),
	CoreEventBoundProps: dec[CoreBoundProps](),
}

// DecodeCoreEvent decodes a server-to-client message for the core object
// (id 0) into one of the Core* event structs. An unknown opcode gives an
// error for which IsUnknownOpcode is true.
func DecodeCoreEvent(op uint8, st pod.Struct, fl *FdList) (any, error) {
	return coreEvents.decode("Core event", op, st, fl)
}

// DecodeCoreMethod decodes a client-to-server message for the core object.
// A server or a test uses it.
func DecodeCoreMethod(op uint8, st pod.Struct, fl *FdList) (any, error) {
	return coreMethods.decode("Core method", op, st, fl)
}

// ServerError is a Core.Error event turned into a Go error. The Conn ends
// with it only for -EPIPE on the core; for a proxy the handler receives the
// CoreErrorEvent and may wrap it in a ServerError itself.
type ServerError struct {
	ID      int32
	Seq     int32
	Res     int32
	Message string
}

func (e *ServerError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = "no message given"
	}
	return fmt.Sprintf("the PipeWire server reported an error on object %d (result %d): %s", e.ID, e.Res, msg)
}
