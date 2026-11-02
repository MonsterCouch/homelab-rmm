package stream

import (
	"fmt"
	"strconv"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/pod"
	"github.com/MonsterCouch/homelab-rmm/internal/agent/desktop/pipewire/proto"
)

// Limits on what the stream accepts as a frame size.
const (
	maxDimension = 16384
	minBuffers   = 2
	maxBuffers   = 16
	defBuffers   = 4
)

// Format is the video format the server chose for the stream.
type Format struct {
	// PixelFormat is the SPA video format id: pod.VideoFormatBGRx,
	// BGRA, RGBx or RGBA.
	PixelFormat uint32
	Width       int
	Height      int
}

// Stride is the row length in bytes the stream asks producers for.
func (f Format) Stride() int { return f.Width * 4 }

// offeredFormats are the pixel formats of the EnumFormat param, the preferred
// one first. DMA-BUF and every format that needs a modifier are not offered.
var offeredFormats = []uint32{pod.VideoFormatBGRx, pod.VideoFormatBGRA, pod.VideoFormatRGBx, pod.VideoFormatRGBA}

func isOffered(format uint32) bool {
	for _, f := range offeredFormats {
		if f == format {
			return true
		}
	}
	return false
}

// enumFormat is the EnumFormat param: video/raw in the offered formats, any
// size from 1x1 to 16384x16384, any frame rate up to 1000. The enum repeats
// its default first and the first value of every choice is what the server
// fixates to, as in PipeWire's own examples.
func enumFormat() pod.Object {
	alts := make([]pod.Pod, 0, len(offeredFormats))
	for _, f := range offeredFormats {
		alts = append(alts, pod.Id(f))
	}
	return pod.NewObject(pod.ObjectFormat, pod.ParamEnumFormat,
		pod.P(pod.FormatMediaType, pod.Id(pod.MediaTypeVideo)),
		pod.P(pod.FormatMediaSubtype, pod.Id(pod.MediaSubtypeRaw)),
		pod.P(pod.FormatVideoFormat, pod.ChoiceEnum(pod.Id(offeredFormats[0]), alts...)),
		pod.P(pod.FormatVideoSize, pod.ChoiceRange(pod.Rect(1920, 1080), pod.Rect(1, 1), pod.Rect(maxDimension, maxDimension))),
		pod.P(pod.FormatVideoFramerate, pod.ChoiceRange(pod.Frac(60, 1), pod.Frac(0, 1), pod.Frac(1000, 1))),
	)
}

func metaParam(typ uint32, size pod.Pod) pod.Object {
	return pod.NewObject(pod.ObjectParamMeta, pod.ParamMeta,
		pod.P(pod.ParamMetaType, pod.Id(typ)),
		pod.P(pod.ParamMetaSize, size),
	)
}

// metaParams are the Meta params: the Busy meta pw_stream always adds, then
// VideoCrop (one region). VideoDamage is not requested: the frame copy does not use it.
func metaParams() []pod.Pod {
	return []pod.Pod{
		metaParam(pod.MetaBusy, pod.Int(8)),
		metaParam(pod.MetaVideoCrop, pod.Int(regionSize)),
	}
}

// ioParam is the IO param for the Buffers area. AsyncBuffers is not offered.
func ioParam() pod.Object {
	return pod.NewObject(pod.ObjectParamIO, pod.ParamIO,
		pod.P(pod.ParamIOId, pod.Id(pod.IOBuffers)),
		pod.P(pod.ParamIOSize, pod.Int(ioBuffersSize)),
	)
}

// buffersParam is the Buffers param for a chosen format: one block of packed
// pixels per buffer, MemFd or MemPtr data only (mask 4|2, never the DMA-BUF
// bit 8, so the producer falls back to shared memory).
func buffersParam(f Format) (pod.Object, error) {
	stride := int64(f.Stride())
	size := stride * int64(f.Height)
	if size <= 0 || size > maxMapSize {
		return pod.Object{}, fmt.Errorf("a %dx%d frame needs %d bytes per buffer, which is out of range", f.Width, f.Height, size)
	}
	return pod.NewObject(pod.ObjectParamBuffers, pod.ParamBuffers,
		pod.P(pod.ParamBuffersBuffers, pod.ChoiceRange(pod.Int(defBuffers), pod.Int(minBuffers), pod.Int(maxBuffers))),
		pod.P(pod.ParamBuffersBlocks, pod.Int(1)),
		pod.P(pod.ParamBuffersSize, pod.Int(int32(size))),
		pod.P(pod.ParamBuffersStride, pod.Int(int32(stride))),
		pod.P(pod.ParamBuffersAlign, pod.Int(16)),
		pod.P(pod.ParamBuffersDataType, pod.ChoiceFlags(pod.Int(int32(pod.DataMaskMemFd|pod.DataMaskMemPtr)))),
	), nil
}

// parseFormat reads the Format object the server sends in PortSetParam and
// checks it is video/raw in one of the offered pixel formats.
func parseFormat(p pod.Pod) (Format, error) {
	o, ok := pod.AsObject(p)
	if !ok || o.ObjType != pod.ObjectFormat {
		return Format{}, fmt.Errorf("the server sent a %s pod where a Format object was expected", pod.TypeName(p.PodType()))
	}
	mt, err := o.GetId(pod.FormatMediaType)
	if err != nil {
		return Format{}, fmt.Errorf("the server's format has no media type: %w", err)
	}
	st, err := o.GetId(pod.FormatMediaSubtype)
	if err != nil {
		return Format{}, fmt.Errorf("the server's format has no media subtype: %w", err)
	}
	if mt != pod.MediaTypeVideo || st != pod.MediaSubtypeRaw {
		return Format{}, fmt.Errorf("the server chose media type %d subtype %d, but this client only offered video/raw", mt, st)
	}
	pf, err := o.GetId(pod.FormatVideoFormat)
	if err != nil {
		return Format{}, fmt.Errorf("the server's format has no pixel format: %w", err)
	}
	if !isOffered(pf) {
		return Format{}, fmt.Errorf("the server chose %s, which this client did not offer (BGRx, BGRA, RGBx and RGBA)", formatName(pf))
	}
	r, err := o.GetRectangle(pod.FormatVideoSize)
	if err != nil {
		return Format{}, fmt.Errorf("the server's format has no size: %w", err)
	}
	if r.Width == 0 || r.Height == 0 || r.Width > maxDimension || r.Height > maxDimension {
		return Format{}, fmt.Errorf("the server chose a frame size of %dx%d", r.Width, r.Height)
	}
	return Format{PixelFormat: pf, Width: int(r.Width), Height: int(r.Height)}, nil
}

// clientProps are the properties sent with Client.UpdateProperties.
func clientProps(name string) proto.Dict {
	return proto.Dict{
		{Key: "application.name", Value: "homelab-rmm"},
		{Key: "media.type", Value: "Video"},
		{Key: "media.category", Value: "Capture"},
		{Key: "media.role", Value: "Screen"},
		{Key: "node.name", Value: name},
	}
}

// nodeProps are the properties of the node and of the CreateObject call
// (notes 4.1). node.target is the deprecated key the portal path still uses;
// target.object is left out because newer servers read it as an object
// serial or a node name, not as a node id.
func nodeProps(o Options) proto.Dict {
	d := proto.Dict{
		{Key: "media.type", Value: "Video"},
		{Key: "media.category", Value: "Capture"},
		{Key: "media.role", Value: "Screen"},
		{Key: "media.class", Value: "Stream/Input/Video"},
		{Key: "node.name", Value: o.Name},
		{Key: "node.target", Value: strconv.FormatUint(uint64(o.NodeID), 10)},
		{Key: "node.autoconnect", Value: "true"},
		{Key: "node.dont-reconnect", Value: "true"},
		{Key: "port.group", Value: "stream.0"},
	}
	if o.Async {
		d = append(d, proto.DictItem{Key: "node.async", Value: "true"})
	}
	return d
}

// nodeUpdate is ClientNode.Update: the EnumFormat as the node's params and
// the node info (one input port, no output).
func nodeUpdate(o Options) proto.ClientNodeUpdate {
	flags := proto.NodeFlagRT
	if o.Async {
		flags |= proto.NodeFlagAsync
	}
	return proto.ClientNodeUpdate{
		ChangeMask: proto.UpdateParams | proto.UpdateInfo,
		Params:     []pod.Pod{enumFormat()},
		Info: &proto.NodeInfo{
			MaxInputPorts:  1,
			MaxOutputPorts: 0,
			ChangeMask:     proto.NodeChangeFlags | proto.NodeChangeProps | proto.NodeChangeParams,
			Flags:          flags,
			Props:          nodeProps(o),
			Params: []proto.ParamInfo{
				{ID: pod.ParamPropInfo, Flags: 0},
				{ID: pod.ParamProps, Flags: proto.ParamInfoWrite},
				{ID: pod.ParamEnumFormat, Flags: proto.ParamInfoRead},
				{ID: pod.ParamFormat, Flags: proto.ParamInfoWrite},
			},
		},
	}
}

// portUpdate is ClientNode.PortUpdate for the one input port. Every update
// that carries params replaces the server's whole list, so once a format is
// chosen it also carries the Format and Buffers params.
func portUpdate(format *Format, formatPod pod.Pod, serials paramSerials) (proto.ClientNodePortUpdate, error) {
	params := []pod.Pod{enumFormat()}
	params = append(params, metaParams()...)
	params = append(params, ioParam())
	infos := []proto.ParamInfo{
		{ID: pod.ParamEnumFormat, Flags: proto.ParamInfoRead},
		{ID: pod.ParamMeta, Flags: proto.ParamInfoRead},
		{ID: pod.ParamIO, Flags: proto.ParamInfoRead},
		{ID: pod.ParamFormat, Flags: proto.ParamInfoWrite | serials.format},
		{ID: pod.ParamBuffers, Flags: serials.buffers},
	}
	if format != nil {
		bp, err := buffersParam(*format)
		if err != nil {
			return proto.ClientNodePortUpdate{}, err
		}
		params = append(params, formatPod, bp)
		infos[3].Flags = proto.ParamInfoRead | proto.ParamInfoWrite | serials.format
		infos[4].Flags = proto.ParamInfoRead | serials.buffers
	}
	return proto.ClientNodePortUpdate{
		Direction:  proto.DirectionInput,
		PortID:     0,
		ChangeMask: proto.UpdateParams | proto.UpdateInfo,
		Params:     params,
		Info: &proto.PortInfo{
			ChangeMask: proto.PortChangeFlags | proto.PortChangeRate | proto.PortChangeProps | proto.PortChangeParams,
			Flags:      0,
			RateNum:    0,
			RateDenom:  1,
			Props:      proto.Dict{{Key: "port.group", Value: "stream.0"}},
			Params:     infos,
		},
	}, nil
}

// paramSerials holds the SERIAL bit of the Format and Buffers param infos.
// impl-port.c update_info ignores a param whose flags equal the previous
// ones, so every change of either param flips its bit.
type paramSerials struct {
	format, buffers uint32
}

func (p *paramSerials) toggle() {
	p.format ^= proto.ParamInfoSerial
	p.buffers ^= proto.ParamInfoSerial
}
