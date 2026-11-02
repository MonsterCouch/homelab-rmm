package proto

import (
	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

// ClientNode methods, client to server (extensions/client-node.h). Opcode 0
// is AddListener.
const (
	ClientNodeMethodGetNode     uint8 = 1
	ClientNodeMethodUpdate      uint8 = 2
	ClientNodeMethodPortUpdate  uint8 = 3
	ClientNodeMethodSetActive   uint8 = 4
	ClientNodeMethodEvent       uint8 = 5
	ClientNodeMethodPortBuffers uint8 = 6
)

// ClientNode events, server to client.
const (
	ClientNodeEventTransport      uint8 = 0
	ClientNodeEventSetParam       uint8 = 1
	ClientNodeEventSetIO          uint8 = 2
	ClientNodeEventEvent          uint8 = 3
	ClientNodeEventCommand        uint8 = 4
	ClientNodeEventAddPort        uint8 = 5
	ClientNodeEventRemovePort     uint8 = 6
	ClientNodeEventPortSetParam   uint8 = 7
	ClientNodeEventPortUseBuffers uint8 = 8
	ClientNodeEventPortSetIO      uint8 = 9
	ClientNodeEventSetActivation  uint8 = 10
	ClientNodeEventPortSetMixInfo uint8 = 11
)

// Change masks of ClientNode.Update and ClientNode.PortUpdate.
const (
	UpdateParams int32 = 1 << 0
	UpdateInfo   int32 = 1 << 1
)

// Node info change mask bits and flags (spa/node/node.h).
const (
	NodeChangeFlags  int64 = 1 << 0
	NodeChangeProps  int64 = 1 << 1
	NodeChangeParams int64 = 1 << 2

	NodeFlagRT    int64 = 1 << 0
	NodeFlagAsync int64 = 1 << 6
)

// Port info change mask bits and flags (spa/node/node.h).
const (
	PortChangeFlags  int64 = 1 << 0
	PortChangeRate   int64 = 1 << 1
	PortChangeProps  int64 = 1 << 2
	PortChangeParams int64 = 1 << 3

	PortFlagRemovable       int64 = 1 << 0
	PortFlagOptional        int64 = 1 << 1
	PortFlagCanAllocBuffers int64 = 1 << 2
	PortFlagInPlace         int64 = 1 << 3
	PortFlagNoRef           int64 = 1 << 4
	PortFlagLive            int64 = 1 << 5
	PortFlagPhysical        int64 = 1 << 6
	PortFlagTerminal        int64 = 1 << 7
	PortFlagDynamicData     int64 = 1 << 8
)

// Port directions.
const (
	DirectionInput  uint32 = 0
	DirectionOutput uint32 = 1
)

// NodeInfo is the node description inside ClientNode.Update:
// Struct{Int max_input_ports, Int max_output_ports, Long change_mask, Long
// flags, Int n_items, (String key, String value)*n_items, Int n_params, (Id
// param_id, Int param_flags)*n_params}. The props are inline, not a nested
// Struct.
type NodeInfo struct {
	MaxInputPorts  int32
	MaxOutputPorts int32
	ChangeMask     int64
	Flags          int64
	Props          Dict
	Params         []ParamInfo
}

func (n NodeInfo) pod() pod.Struct {
	b := pod.NewBuilder().Int(n.MaxInputPorts).Int(n.MaxOutputPorts).Long(n.ChangeMask).Long(n.Flags)
	n.Props.appendInline(b)
	appendParamInfos(b, n.Params)
	return b.Build()
}

func (r *wreader) nodeInfo() *NodeInfo {
	s := r.optSub()
	if s == nil {
		return nil
	}
	n := &NodeInfo{MaxInputPorts: s.i32(), MaxOutputPorts: s.i32(), ChangeMask: s.long(), Flags: s.long()}
	n.Props = s.dictInline()
	n.Params = s.paramInfos()
	r.fail(s.err)
	return n
}

// PortInfo is the port description inside ClientNode.PortUpdate:
// Struct{Long change_mask, Long flags, Int rate_num, Int rate_denom, Int
// n_items, (String key, String value)*n_items, Int n_params, (Id param_id,
// Int param_flags)*n_params}.
type PortInfo struct {
	ChangeMask int64
	Flags      int64
	RateNum    int32
	RateDenom  int32
	Props      Dict
	Params     []ParamInfo
}

func (p PortInfo) pod() pod.Struct {
	b := pod.NewBuilder().Long(p.ChangeMask).Long(p.Flags).Int(p.RateNum).Int(p.RateDenom)
	p.Props.appendInline(b)
	appendParamInfos(b, p.Params)
	return b.Build()
}

func (r *wreader) portInfo() *PortInfo {
	s := r.optSub()
	if s == nil {
		return nil
	}
	p := &PortInfo{ChangeMask: s.long(), Flags: s.long(), RateNum: s.i32(), RateDenom: s.i32()}
	p.Props = s.dictInline()
	p.Params = s.paramInfos()
	r.fail(s.err)
	return p
}

// ClientNodeGetNode is ClientNode.GetNode, Struct{Int version, Int new_id}.
type ClientNodeGetNode struct {
	Version int32
	NewID   uint32
}

func (ClientNodeGetNode) Opcode() uint8 { return ClientNodeMethodGetNode }
func (m ClientNodeGetNode) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(m.Version).Int(int32(m.NewID)).Build()
}
func (m *ClientNodeGetNode) unmarshal(r *wreader) { m.Version, m.NewID = r.i32(), r.u32() }

// ClientNodeUpdate is ClientNode.Update, Struct{Int change_mask, Int
// n_params, Pod param * n_params, NodeInfo | None}. ChangeMask bit 0 is
// params, bit 1 is info; a nil Info is written as None.
type ClientNodeUpdate struct {
	ChangeMask int32
	Params     []pod.Pod
	Info       *NodeInfo
}

func (ClientNodeUpdate) Opcode() uint8 { return ClientNodeMethodUpdate }
func (m ClientNodeUpdate) Marshal(*FdSet) pod.Struct {
	b := pod.NewBuilder().Int(m.ChangeMask)
	appendParams(b, m.Params)
	if m.Info == nil {
		b.None()
	} else {
		b.Pod(m.Info.pod())
	}
	return b.Build()
}
func (m *ClientNodeUpdate) unmarshal(r *wreader) {
	m.ChangeMask = r.i32()
	m.Params = r.params()
	m.Info = r.nodeInfo()
}

// ClientNodePortUpdate is ClientNode.PortUpdate, Struct{Int direction, Int
// port_id, Int change_mask, Int n_params, Pod param * n_params, PortInfo |
// None}. ChangeMask 0 with no params and no info removes the port.
type ClientNodePortUpdate struct {
	Direction  uint32
	PortID     uint32
	ChangeMask int32
	Params     []pod.Pod
	Info       *PortInfo
}

func (ClientNodePortUpdate) Opcode() uint8 { return ClientNodeMethodPortUpdate }
func (m ClientNodePortUpdate) Marshal(*FdSet) pod.Struct {
	b := pod.NewBuilder().Int(int32(m.Direction)).Int(int32(m.PortID)).Int(m.ChangeMask)
	appendParams(b, m.Params)
	if m.Info == nil {
		b.None()
	} else {
		b.Pod(m.Info.pod())
	}
	return b.Build()
}
func (m *ClientNodePortUpdate) unmarshal(r *wreader) {
	m.Direction, m.PortID, m.ChangeMask = r.u32(), r.u32(), r.i32()
	m.Params = r.params()
	m.Info = r.portInfo()
}

// ClientNodeSetActive is ClientNode.SetActive, Struct{Bool active}.
type ClientNodeSetActive struct{ Active bool }

func (ClientNodeSetActive) Opcode() uint8 { return ClientNodeMethodSetActive }
func (m ClientNodeSetActive) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Bool(m.Active).Build()
}
func (m *ClientNodeSetActive) unmarshal(r *wreader) { m.Active = r.boolean() }

// ClientNodeSendEvent is the ClientNode.Event method, Struct{Pod event}.
type ClientNodeSendEvent struct{ Event pod.Pod }

func (ClientNodeSendEvent) Opcode() uint8 { return ClientNodeMethodEvent }
func (m ClientNodeSendEvent) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Pod(orNone(m.Event)).Build()
}
func (m *ClientNodeSendEvent) unmarshal(r *wreader) { m.Event = r.pod() }

// BufferData is one data block of a ClientNode.PortBuffers buffer: Id type,
// Fd fd_index, Int flags, Int mapoffset, Int maxsize. Fd is a descriptor, or
// -1 for none.
type BufferData struct {
	Type      uint32
	Fd        int
	Flags     uint32
	MapOffset uint32
	MaxSize   uint32
}

// ClientNodePortBuffers is ClientNode.PortBuffers, Struct{Int direction, Int
// port_id, Int mix_id, Int n_buffers, per buffer: Int n_datas, per data: Id
// type, Fd fd_index, Int flags, Int mapoffset, Int maxsize}. A video input
// stream does not send it.
type ClientNodePortBuffers struct {
	Direction uint32
	PortID    uint32
	MixID     uint32
	Buffers   [][]BufferData
}

func (ClientNodePortBuffers) Opcode() uint8 { return ClientNodeMethodPortBuffers }
func (m ClientNodePortBuffers) Marshal(fds *FdSet) pod.Struct {
	b := pod.NewBuilder().Int(int32(m.Direction)).Int(int32(m.PortID)).Int(int32(m.MixID)).Int(int32(len(m.Buffers)))
	for _, datas := range m.Buffers {
		b.Int(int32(len(datas)))
		for _, d := range datas {
			b.Id(d.Type).Pod(fds.Index(d.Fd)).Int(int32(d.Flags)).Int(int32(d.MapOffset)).Int(int32(d.MaxSize))
		}
	}
	return b.Build()
}
func (m *ClientNodePortBuffers) unmarshal(r *wreader) {
	m.Direction, m.PortID, m.MixID = r.u32(), r.u32(), r.u32()
	nb := r.count(maxBuffers, "buffer")
	for i := 0; i < nb && r.err == nil; i++ {
		nd := r.count(maxDatas, "data")
		var datas []BufferData
		for j := 0; j < nd && r.err == nil; j++ {
			datas = append(datas, BufferData{Type: r.id(), Fd: r.fd(), Flags: r.u32(), MapOffset: r.u32(), MaxSize: r.u32()})
		}
		m.Buffers = append(m.Buffers, datas)
	}
}

// ClientNodeTransport is the Transport event, Struct{Fd read_fd, Fd
// write_fd, Int mem_id, Int offset, Int size}. ReadFd and WriteFd are the
// received descriptors. MemID, Offset and Size locate the node's activation
// block (2312 bytes).
type ClientNodeTransport struct {
	ReadFd, WriteFd int
	MemID           uint32
	Offset, Size    uint32
}

func (ClientNodeTransport) Opcode() uint8 { return ClientNodeEventTransport }
func (m ClientNodeTransport) Marshal(fds *FdSet) pod.Struct {
	return pod.NewBuilder().Pod(fds.Index(m.ReadFd)).Pod(fds.Index(m.WriteFd)).
		Int(int32(m.MemID)).Int(int32(m.Offset)).Int(int32(m.Size)).Build()
}
func (m *ClientNodeTransport) unmarshal(r *wreader) {
	m.ReadFd, m.WriteFd = r.fd(), r.fd()
	m.MemID, m.Offset, m.Size = r.u32(), r.u32(), r.u32()
}

// ClientNodeSetParam is the SetParam event, Struct{Id param_id, Int flags,
// Pod param}, a node-level param.
type ClientNodeSetParam struct {
	ParamID uint32
	Flags   uint32
	Param   pod.Pod
}

func (ClientNodeSetParam) Opcode() uint8 { return ClientNodeEventSetParam }
func (m ClientNodeSetParam) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Id(m.ParamID).Int(int32(m.Flags)).Pod(orNone(m.Param)).Build()
}
func (m *ClientNodeSetParam) unmarshal(r *wreader) {
	m.ParamID, m.Flags, m.Param = r.id(), r.u32(), r.pod()
}

// ClientNodeSetIO is the SetIO event, Struct{Id io_id, Int mem_id, Int
// offset, Int size}. MemID InvalidID with offset 0 and size 0 clears the area.
type ClientNodeSetIO struct {
	IOID         uint32
	MemID        uint32
	Offset, Size uint32
}

func (ClientNodeSetIO) Opcode() uint8 { return ClientNodeEventSetIO }
func (m ClientNodeSetIO) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Id(m.IOID).Int(int32(m.MemID)).Int(int32(m.Offset)).Int(int32(m.Size)).Build()
}
func (m *ClientNodeSetIO) unmarshal(r *wreader) {
	m.IOID, m.MemID, m.Offset, m.Size = r.id(), r.u32(), r.u32(), r.u32()
}

// ClientNodeNodeEvent is the ClientNode.Event event, Struct{Pod event}.
type ClientNodeNodeEvent struct{ Event pod.Pod }

func (ClientNodeNodeEvent) Opcode() uint8 { return ClientNodeEventEvent }
func (m ClientNodeNodeEvent) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Pod(orNone(m.Event)).Build()
}
func (m *ClientNodeNodeEvent) unmarshal(r *wreader) { m.Event = r.pod() }

// ClientNodeCommand is the Command event, Struct{Pod command}. The pod is an
// Object of type pod.TypeCommandNode whose id is the command.
type ClientNodeCommand struct{ Command pod.Pod }

func (ClientNodeCommand) Opcode() uint8 { return ClientNodeEventCommand }
func (m ClientNodeCommand) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Pod(orNone(m.Command)).Build()
}
func (m *ClientNodeCommand) unmarshal(r *wreader) { m.Command = r.pod() }

// NodeCommandID returns the node command number (pod.NodeCommandStart and so
// on) when the pod is a node command object.
func (m ClientNodeCommand) NodeCommandID() (uint32, bool) {
	o, ok := pod.AsObject(m.Command)
	if !ok || o.ObjType != pod.TypeCommandNode {
		return 0, false
	}
	return o.ID, true
}

// ClientNodeAddPort is the AddPort event, Struct{Int direction, Int port_id,
// Dict props}.
type ClientNodeAddPort struct {
	Direction, PortID uint32
	Props             Dict
}

func (ClientNodeAddPort) Opcode() uint8 { return ClientNodeEventAddPort }
func (m ClientNodeAddPort) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.Direction)).Int(int32(m.PortID)).Pod(m.Props.pod()).Build()
}
func (m *ClientNodeAddPort) unmarshal(r *wreader) {
	m.Direction, m.PortID = r.u32(), r.u32()
	m.Props = r.dict()
}

// ClientNodeRemovePort is the RemovePort event, Struct{Int direction, Int
// port_id}.
type ClientNodeRemovePort struct{ Direction, PortID uint32 }

func (ClientNodeRemovePort) Opcode() uint8 { return ClientNodeEventRemovePort }
func (m ClientNodeRemovePort) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.Direction)).Int(int32(m.PortID)).Build()
}
func (m *ClientNodeRemovePort) unmarshal(r *wreader) { m.Direction, m.PortID = r.u32(), r.u32() }

// ClientNodePortSetParam is the PortSetParam event, Struct{Int direction, Int
// port_id, Id param_id, Int flags, Pod param}. Param is None to clear.
type ClientNodePortSetParam struct {
	Direction, PortID uint32
	ParamID           uint32
	Flags             uint32
	Param             pod.Pod
}

func (ClientNodePortSetParam) Opcode() uint8 { return ClientNodeEventPortSetParam }
func (m ClientNodePortSetParam) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.Direction)).Int(int32(m.PortID)).Id(m.ParamID).
		Int(int32(m.Flags)).Pod(orNone(m.Param)).Build()
}
func (m *ClientNodePortSetParam) unmarshal(r *wreader) {
	m.Direction, m.PortID, m.ParamID, m.Flags, m.Param = r.u32(), r.u32(), r.id(), r.u32(), r.pod()
}

// BufferMeta is a meta entry of a buffer: Id meta_type, Int meta_size.
type BufferMeta struct {
	Type uint32
	Size uint32
}

// UseBufferData is a data entry of a buffer: Id data_type, Int data_id, Int
// data_flags, Int mapoffset, Int maxsize.
type UseBufferData struct {
	Type      uint32
	DataID    uint32
	Flags     uint32
	MapOffset uint32
	MaxSize   uint32
}

// UseBuffer is one buffer of PortUseBuffers: Int mem_id, Int offset, Int
// size, then the metas and the datas.
type UseBuffer struct {
	MemID  uint32
	Offset uint32
	Size   uint32
	Metas  []BufferMeta
	Datas  []UseBufferData
}

// ClientNodePortUseBuffers is the PortUseBuffers event, Struct{Int direction,
// Int port_id, Int mix_id, Int flags, Int n_buffers, per buffer: Int mem_id,
// Int offset, Int size, Int n_metas, (Id meta_type, Int meta_size)*n_metas,
// Int n_datas, (Id data_type, Int data_id, Int data_flags, Int mapoffset, Int
// maxsize)*n_datas}. No buffers clears the port's buffers.
type ClientNodePortUseBuffers struct {
	Direction, PortID, MixID uint32
	Flags                    uint32
	Buffers                  []UseBuffer
}

func (ClientNodePortUseBuffers) Opcode() uint8 { return ClientNodeEventPortUseBuffers }
func (m ClientNodePortUseBuffers) Marshal(*FdSet) pod.Struct {
	b := pod.NewBuilder().Int(int32(m.Direction)).Int(int32(m.PortID)).Int(int32(m.MixID)).
		Int(int32(m.Flags)).Int(int32(len(m.Buffers)))
	for _, buf := range m.Buffers {
		b.Int(int32(buf.MemID)).Int(int32(buf.Offset)).Int(int32(buf.Size)).Int(int32(len(buf.Metas)))
		for _, mt := range buf.Metas {
			b.Id(mt.Type).Int(int32(mt.Size))
		}
		b.Int(int32(len(buf.Datas)))
		for _, d := range buf.Datas {
			b.Id(d.Type).Int(int32(d.DataID)).Int(int32(d.Flags)).Int(int32(d.MapOffset)).Int(int32(d.MaxSize))
		}
	}
	return b.Build()
}
func (m *ClientNodePortUseBuffers) unmarshal(r *wreader) {
	m.Direction, m.PortID, m.MixID, m.Flags = r.u32(), r.u32(), r.u32(), r.u32()
	nb := r.count(maxBuffers, "buffer")
	for i := 0; i < nb && r.err == nil; i++ {
		buf := UseBuffer{MemID: r.u32(), Offset: r.u32(), Size: r.u32()}
		nm := r.count(maxMetas, "meta")
		for j := 0; j < nm && r.err == nil; j++ {
			buf.Metas = append(buf.Metas, BufferMeta{Type: r.id(), Size: r.u32()})
		}
		nd := r.count(maxDatas, "data")
		for j := 0; j < nd && r.err == nil; j++ {
			buf.Datas = append(buf.Datas, UseBufferData{Type: r.id(), DataID: r.u32(), Flags: r.u32(), MapOffset: r.u32(), MaxSize: r.u32()})
		}
		m.Buffers = append(m.Buffers, buf)
	}
}

// ClientNodePortSetIO is the PortSetIO event, Struct{Int direction, Int
// port_id, Int mix_id, Id io_id, Int mem_id, Int offset, Int size}.
type ClientNodePortSetIO struct {
	Direction, PortID, MixID uint32
	IOID                     uint32
	MemID                    uint32
	Offset, Size             uint32
}

func (ClientNodePortSetIO) Opcode() uint8 { return ClientNodeEventPortSetIO }
func (m ClientNodePortSetIO) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.Direction)).Int(int32(m.PortID)).Int(int32(m.MixID)).Id(m.IOID).
		Int(int32(m.MemID)).Int(int32(m.Offset)).Int(int32(m.Size)).Build()
}
func (m *ClientNodePortSetIO) unmarshal(r *wreader) {
	m.Direction, m.PortID, m.MixID, m.IOID = r.u32(), r.u32(), r.u32(), r.id()
	m.MemID, m.Offset, m.Size = r.u32(), r.u32(), r.u32()
}

// ClientNodeSetActivation is the SetActivation event, Struct{Int node_id, Fd
// signal_fd, Int mem_id, Int offset, Int size}. MemID InvalidID removes the
// peer.
type ClientNodeSetActivation struct {
	NodeID       uint32
	SignalFd     int
	MemID        uint32
	Offset, Size uint32
}

func (ClientNodeSetActivation) Opcode() uint8 { return ClientNodeEventSetActivation }
func (m ClientNodeSetActivation) Marshal(fds *FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.NodeID)).Pod(fds.Index(m.SignalFd)).
		Int(int32(m.MemID)).Int(int32(m.Offset)).Int(int32(m.Size)).Build()
}
func (m *ClientNodeSetActivation) unmarshal(r *wreader) {
	m.NodeID, m.SignalFd = r.u32(), r.fd()
	m.MemID, m.Offset, m.Size = r.u32(), r.u32(), r.u32()
}

// ClientNodePortSetMixInfo is the PortSetMixInfo event, Struct{Int direction,
// Int port_id, Int mix_id, Int peer_id, Dict props}. PeerID InvalidID removes
// the mix.
type ClientNodePortSetMixInfo struct {
	Direction, PortID, MixID, PeerID uint32
	Props                            Dict
}

func (ClientNodePortSetMixInfo) Opcode() uint8 { return ClientNodeEventPortSetMixInfo }
func (m ClientNodePortSetMixInfo) Marshal(*FdSet) pod.Struct {
	return pod.NewBuilder().Int(int32(m.Direction)).Int(int32(m.PortID)).Int(int32(m.MixID)).
		Int(int32(m.PeerID)).Pod(m.Props.pod()).Build()
}
func (m *ClientNodePortSetMixInfo) unmarshal(r *wreader) {
	m.Direction, m.PortID, m.MixID, m.PeerID = r.u32(), r.u32(), r.u32(), r.u32()
	m.Props = r.dict()
}

var clientNodeMethods = opTable{
	ClientNodeMethodGetNode:     dec[ClientNodeGetNode](),
	ClientNodeMethodUpdate:      dec[ClientNodeUpdate](),
	ClientNodeMethodPortUpdate:  dec[ClientNodePortUpdate](),
	ClientNodeMethodSetActive:   dec[ClientNodeSetActive](),
	ClientNodeMethodEvent:       dec[ClientNodeSendEvent](),
	ClientNodeMethodPortBuffers: dec[ClientNodePortBuffers](),
}

var clientNodeEvents = opTable{
	ClientNodeEventTransport:      dec[ClientNodeTransport](),
	ClientNodeEventSetParam:       dec[ClientNodeSetParam](),
	ClientNodeEventSetIO:          dec[ClientNodeSetIO](),
	ClientNodeEventEvent:          dec[ClientNodeNodeEvent](),
	ClientNodeEventCommand:        dec[ClientNodeCommand](),
	ClientNodeEventAddPort:        dec[ClientNodeAddPort](),
	ClientNodeEventRemovePort:     dec[ClientNodeRemovePort](),
	ClientNodeEventPortSetParam:   dec[ClientNodePortSetParam](),
	ClientNodeEventPortUseBuffers: dec[ClientNodePortUseBuffers](),
	ClientNodeEventPortSetIO:      dec[ClientNodePortSetIO](),
	ClientNodeEventSetActivation:  dec[ClientNodeSetActivation](),
	ClientNodeEventPortSetMixInfo: dec[ClientNodePortSetMixInfo](),
}

// DecodeClientNodeEvent decodes a server-to-client message for a ClientNode
// proxy.
func DecodeClientNodeEvent(op uint8, st pod.Struct, fl *FdList) (any, error) {
	return clientNodeEvents.decode("ClientNode event", op, st, fl)
}

// DecodeClientNodeMethod decodes a client-to-server message for a ClientNode
// proxy. A server or a test uses it.
func DecodeClientNodeMethod(op uint8, st pod.Struct, fl *FdList) (any, error) {
	return clientNodeMethods.decode("ClientNode method", op, st, fl)
}
