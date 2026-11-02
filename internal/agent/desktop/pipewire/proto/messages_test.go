package proto

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
)

func enumFormat() pod.Pod {
	return pod.NewObject(pod.ObjectFormat, pod.ParamEnumFormat,
		pod.P(pod.FormatMediaType, pod.Id(pod.MediaTypeVideo)),
		pod.P(pod.FormatVideoSize, pod.ChoiceRange(pod.Rect(320, 240), pod.Rect(1, 1), pod.Rect(4096, 4096))))
}

func startCommand() pod.Pod {
	return pod.NewObject(pod.TypeCommandNode, pod.NodeCommandStart)
}

type decodeFn func(op uint8, st pod.Struct, fl *FdList) (any, error)

// roundTrip marshals m, decodes it with fn and marshals the result again. The
// two payloads and the two fd lists must be identical, and the decoded value
// is returned for field checks.
func roundTrip(t *testing.T, m Message, fn decodeFn) any {
	t.Helper()
	_, payload, fds, err := BuildMessage(2, 0, m)
	if err != nil {
		t.Fatalf("%T: %v", m, err)
	}
	st, _, err := SplitPayload(payload)
	if err != nil {
		t.Fatalf("%T: %v", m, err)
	}
	fl := NewFdList(fds)
	v, err := fn(m.Opcode(), st, fl)
	if err != nil {
		t.Fatalf("%T: decode: %v", m, err)
	}
	if u := fl.Unused(); len(u) != 0 {
		t.Fatalf("%T: decoder left fds %v unused", m, u)
	}
	m2, ok := v.(Message)
	if !ok {
		t.Fatalf("%T decoded to %T which is not a Message", m, v)
	}
	if reflect.TypeOf(m2) != reflect.TypeOf(m) {
		t.Fatalf("decoded to %T, want %T", m2, m)
	}
	_, payload2, fds2, err := BuildMessage(2, 0, m2)
	if err != nil {
		t.Fatalf("%T: re-marshal: %v", m, err)
	}
	if !bytes.Equal(payload, payload2) || !reflect.DeepEqual(fds, fds2) {
		t.Fatalf("%T: re-marshal differs\n got % x %v\nwant % x %v", m, payload2, fds2, payload, fds)
	}
	return v
}

func TestRoundTripCore(t *testing.T) {
	props := Dict{{"core.name", "pipewire-0"}, {"k", "v"}}
	methods := []Message{
		CoreHello{Version: 4},
		CoreSync{ID: 0, Seq: int32(AsyncBit | 9)},
		CorePong{ID: 3, Seq: 77},
		CoreError{ID: 2, Seq: 5, Res: -22, Message: "bad argument"},
		CoreGetRegistry{Version: 3, NewID: 4},
		CoreCreateObject{FactoryName: "client-node", Type: InterfaceClientNode, Version: 6, Props: props, NewID: 2},
		CoreDestroy{ID: 2},
	}
	for _, m := range methods {
		v := roundTrip(t, m, DecodeCoreMethod)
		if !reflect.DeepEqual(v, m) {
			t.Errorf("method %T: got %+v, want %+v", m, v, m)
		}
	}
	events := []Message{
		CoreInfo{ID: 0, Cookie: 123, UserName: "u", HostName: "h", Version: "1.2.7", Name: "pipewire-0", ChangeMask: 1, Props: props},
		CoreDone{ID: 0, Seq: int32(AsyncBit | 2)},
		CorePing{ID: 2, Seq: 8},
		CoreErrorEvent{ID: 2, Seq: 1, Res: -2, Message: "no such factory"},
		CoreRemoveId{ID: 2},
		CoreBoundId{ID: 2, GlobalID: 50},
		CoreBoundProps{ID: 2, GlobalID: 50, Props: props},
		CoreAddMem{ID: 3, Type: 2, Fd: 31, Flags: 3},
		CoreRemoveMem{ID: 3},
	}
	for _, m := range events {
		v := roundTrip(t, m, DecodeCoreEvent)
		if !reflect.DeepEqual(v, m) {
			t.Errorf("event %T: got %+v, want %+v", m, v, m)
		}
	}
}

func TestRoundTripClient(t *testing.T) {
	props := Dict{{"application.name", "rmm"}}
	perms := []Permission{{ID: 0, Permissions: 0x1ff}, {ID: 2, Permissions: 7}}
	for _, m := range []Message{
		ClientErrorMethod{ID: 2, Res: -1, Error: "nope"},
		ClientUpdateProperties{Props: props},
		ClientGetPermissions{Index: 0, Num: 4},
		ClientUpdatePermissions{Items: perms},
	} {
		if v := roundTrip(t, m, DecodeClientMethod); !reflect.DeepEqual(v, m) {
			t.Errorf("method %T: got %+v, want %+v", m, v, m)
		}
	}
	for _, m := range []Message{
		ClientInfo{ID: 1, ChangeMask: 1, Props: props},
		ClientPermissions{Index: 0, Items: perms},
	} {
		if v := roundTrip(t, m, DecodeClientEvent); !reflect.DeepEqual(v, m) {
			t.Errorf("event %T: got %+v, want %+v", m, v, m)
		}
	}
}

func TestRoundTripClientNodeMethods(t *testing.T) {
	nodeProps := Dict{{"media.type", "Video"}, {"node.name", "rmm"}}
	nodeInfo := &NodeInfo{
		MaxInputPorts: 1, MaxOutputPorts: 0,
		ChangeMask: NodeChangeFlags | NodeChangeProps | NodeChangeParams,
		Flags:      NodeFlagRT | NodeFlagAsync, Props: nodeProps,
		Params: []ParamInfo{{1, 0}, {2, ParamInfoWrite}, {3, ParamInfoRead}, {4, ParamInfoWrite}},
	}
	portInfo := &PortInfo{
		ChangeMask: PortChangeFlags | PortChangeRate | PortChangeProps | PortChangeParams,
		RateNum:    0, RateDenom: 1, Props: Dict{{"port.group", "stream.0"}},
		Params: []ParamInfo{{3, ParamInfoRead}, {6, ParamInfoRead}, {7, ParamInfoRead}, {4, ParamInfoWrite}},
	}
	for _, m := range []Message{
		ClientNodeGetNode{Version: 6, NewID: 3},
		ClientNodeUpdate{ChangeMask: UpdateParams | UpdateInfo, Params: []pod.Pod{enumFormat()}, Info: nodeInfo},
		ClientNodeUpdate{ChangeMask: UpdateParams},
		ClientNodePortUpdate{Direction: 0, PortID: 0, ChangeMask: 3, Params: []pod.Pod{enumFormat(), enumFormat()}, Info: portInfo},
		ClientNodePortUpdate{Direction: 0, PortID: 0},
		ClientNodeSetActive{Active: true},
		ClientNodeSendEvent{Event: pod.NewObject(pod.TypeEventNode, pod.NodeEventRequestProcess)},
		ClientNodePortBuffers{Direction: 1, PortID: 0, MixID: InvalidID, Buffers: [][]BufferData{
			{{Type: pod.DataMemFd, Fd: 20, Flags: 3, MapOffset: 0, MaxSize: 4096}, {Type: pod.DataMemFd, Fd: 20, MaxSize: 64}},
			{{Type: pod.DataMemFd, Fd: 21, MaxSize: 4096}},
		}},
	} {
		v := roundTrip(t, m, DecodeClientNodeMethod)
		if u, ok := m.(ClientNodeUpdate); ok {
			got := v.(ClientNodeUpdate)
			if got.ChangeMask != u.ChangeMask || len(got.Params) != len(u.Params) || (got.Info == nil) != (u.Info == nil) {
				t.Errorf("Update decoded to %+v", got)
			}
			if u.Info != nil && !reflect.DeepEqual(got.Info, u.Info) {
				t.Errorf("NodeInfo decoded to %+v, want %+v", got.Info, u.Info)
			}
		}
		if p, ok := m.(ClientNodePortUpdate); ok {
			got := v.(ClientNodePortUpdate)
			if p.Info != nil && !reflect.DeepEqual(got.Info, p.Info) {
				t.Errorf("PortInfo decoded to %+v, want %+v", got.Info, p.Info)
			}
			if p.Info == nil && (got.Info != nil || got.ChangeMask != 0) {
				t.Errorf("a port removal decoded to %+v", got)
			}
		}
		if b, ok := m.(ClientNodePortBuffers); ok && !reflect.DeepEqual(v, b) {
			t.Errorf("PortBuffers decoded to %+v", v)
		}
	}
}

func TestPortBuffersDeduplicatesFds(t *testing.T) {
	m := ClientNodePortBuffers{Buffers: [][]BufferData{{{Type: pod.DataMemFd, Fd: 20}, {Type: pod.DataMemFd, Fd: 20}}}}
	_, _, fds, err := BuildMessage(2, 0, m)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fds, []int{20}) {
		t.Fatalf("fds = %v, want [20]", fds)
	}
}

func TestRoundTripClientNodeEvents(t *testing.T) {
	events := []Message{
		ClientNodeTransport{ReadFd: 40, WriteFd: 41, MemID: 3, Offset: 0, Size: 2312},
		ClientNodeSetParam{ParamID: pod.ParamProps, Flags: 0, Param: pod.NewObject(pod.ObjectProps, pod.ParamProps)},
		ClientNodeSetIO{IOID: pod.IOClock, MemID: 4, Offset: 64, Size: 32},
		ClientNodeSetIO{IOID: pod.IOPosition, MemID: InvalidID},
		ClientNodeNodeEvent{Event: pod.NewObject(pod.TypeEventNode, pod.NodeEventRequestProcess)},
		ClientNodeCommand{Command: startCommand()},
		ClientNodeAddPort{Direction: 0, PortID: 1, Props: Dict{{"a", "b"}}},
		ClientNodeRemovePort{Direction: 0, PortID: 1},
		ClientNodePortSetParam{Direction: 0, PortID: 0, ParamID: pod.ParamFormat, Flags: 0, Param: enumFormat()},
		ClientNodePortSetParam{Direction: 0, PortID: 0, ParamID: pod.ParamFormat, Param: pod.None{}},
		ClientNodePortUseBuffers{Direction: 0, PortID: 0, MixID: InvalidID, Flags: 0, Buffers: []UseBuffer{
			{MemID: 5, Offset: 0, Size: 8192,
				Metas: []BufferMeta{{Type: pod.MetaHeader, Size: 32}, {Type: pod.MetaVideoCrop, Size: 16}},
				Datas: []UseBufferData{{Type: pod.DataMemId, DataID: 6, Flags: 1, MapOffset: 0, MaxSize: 4096}}},
			{MemID: 5, Offset: 8192, Size: 8192},
		}},
		ClientNodePortUseBuffers{},
		ClientNodePortSetIO{Direction: 0, PortID: 0, MixID: InvalidID, IOID: pod.IOBuffers, MemID: 7, Offset: 0, Size: 8},
		ClientNodeSetActivation{NodeID: 90, SignalFd: 44, MemID: 8, Offset: 0, Size: 2312},
		ClientNodeSetActivation{NodeID: 90, SignalFd: -1, MemID: InvalidID},
		ClientNodePortSetMixInfo{Direction: 0, PortID: 0, MixID: 1, PeerID: 90, Props: Dict{{"x", "y"}}},
		ClientNodePortSetMixInfo{PeerID: InvalidID, MixID: 1},
	}
	for _, m := range events {
		v := roundTrip(t, m, DecodeClientNodeEvent)
		switch m.(type) {
		case ClientNodeSetParam, ClientNodeNodeEvent, ClientNodeCommand, ClientNodePortSetParam:
			continue // pods compare by bytes above
		}
		if !reflect.DeepEqual(v, m) {
			t.Errorf("event %T: got %+v, want %+v", m, v, m)
		}
	}
}

func TestCommandNodeCommandID(t *testing.T) {
	v := roundTrip(t, ClientNodeCommand{Command: startCommand()}, DecodeClientNodeEvent).(ClientNodeCommand)
	if id, ok := v.NodeCommandID(); !ok || id != pod.NodeCommandStart {
		t.Fatalf("NodeCommandID = %d, %v", id, ok)
	}
	if _, ok := (ClientNodeCommand{Command: pod.Int(2)}).NodeCommandID(); ok {
		t.Fatal("an Int was taken for a node command")
	}
}

func TestPortSetParamNoneClearsParam(t *testing.T) {
	v := roundTrip(t, ClientNodePortSetParam{ParamID: pod.ParamFormat}, DecodeClientNodeEvent).(ClientNodePortSetParam)
	if !IsNone(v.Param) {
		t.Fatalf("a nil param decoded to %#v", v.Param)
	}
}

func TestDecodeRejectsWrongShapes(t *testing.T) {
	// Core.Done with a String where the first Int belongs.
	st := pod.NewStruct(pod.String("x"), pod.Int(1))
	_, err := DecodeCoreEvent(CoreEventDone, st, NewFdList(nil))
	if err == nil || IsUnknownOpcode(err) {
		t.Fatalf("a wrongly typed field gave %v", err)
	}
	// A truncated Struct.
	if _, err := DecodeCoreEvent(CoreEventDone, pod.NewStruct(pod.Int(1)), NewFdList(nil)); err == nil {
		t.Fatal("a Struct with a missing field was accepted")
	}
	// An Fd index past the fd list.
	st = pod.NewStruct(pod.Int(1), pod.Id(2), pod.Fd(3), pod.Int(0))
	if _, err := DecodeCoreEvent(CoreEventAddMem, st, NewFdList([]int{9})); err == nil {
		t.Fatal("an out-of-range fd index was accepted")
	}
	// Unknown opcodes are reported as such.
	if _, err := DecodeCoreEvent(200, pod.Struct{}, NewFdList(nil)); !IsUnknownOpcode(err) {
		t.Fatalf("opcode 200 gave %v", err)
	}
	// Extra trailing fields are tolerated for newer servers.
	st = pod.NewStruct(pod.Int(4), pod.Int(5), pod.String("extra"))
	if _, err := DecodeCoreEvent(CoreEventDone, st, NewFdList(nil)); err != nil {
		t.Fatalf("a trailing field was rejected: %v", err)
	}
}

func TestDecodeEnforcesCountLimits(t *testing.T) {
	// ClientNode.PortUseBuffers with more buffers than the limit.
	st := pod.NewBuilder().Int(0).Int(0).Int(0).Int(0).Int(maxBuffers + 1).Build()
	if _, err := DecodeClientNodeEvent(ClientNodeEventPortUseBuffers, st, NewFdList(nil)); err == nil {
		t.Fatal("65 buffers were accepted")
	}
	// A negative count.
	st = pod.NewBuilder().Int(0).Int(0).Int(0).Int(0).Int(-1).Build()
	if _, err := DecodeClientNodeEvent(ClientNodeEventPortUseBuffers, st, NewFdList(nil)); err == nil {
		t.Fatal("a negative buffer count was accepted")
	}
	// A dict with too many items, before any item is read.
	st = pod.NewBuilder().Int(2).Long(1).Pod(pod.NewBuilder().Int(maxDictItems + 1).Build()).Build()
	if _, err := DecodeClientEvent(ClientEventInfo, st, NewFdList(nil)); err == nil {
		t.Fatal("1025 dict items were accepted")
	}
	// Update with more params than the limit.
	st = pod.NewBuilder().Int(1).Int(maxParams + 1).Build()
	if _, err := DecodeClientNodeMethod(ClientNodeMethodUpdate, st, NewFdList(nil)); err == nil {
		t.Fatal("4097 params were accepted")
	}
}

func TestPointerValuesAreSentEmpty(t *testing.T) {
	m := ClientUpdateProperties{Props: Dict{{"ptr", "pointer:0x1234"}, {"k", "v"}}}
	v := roundTrip(t, m, DecodeClientMethod).(ClientUpdateProperties)
	if v.Props[0].Value != "" || v.Props[1].Value != "v" {
		t.Fatalf("props = %+v", v.Props)
	}
}

func TestServerErrorSentence(t *testing.T) {
	e := &ServerError{ID: 2, Seq: 1, Res: -2, Message: "no such factory"}
	want := "the PipeWire server reported an error on object 2 (result -2): no such factory"
	if e.Error() != want {
		t.Fatalf("Error() = %q", e.Error())
	}
	var target *ServerError
	if !errors.As(error(e), &target) {
		t.Fatal("errors.As failed")
	}
}
