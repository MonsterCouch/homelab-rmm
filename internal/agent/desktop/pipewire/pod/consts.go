package pod

// Type ids of the POD types as they appear in the 8-byte pod header
// (spa/utils/type.h, SPA_TYPE_*).
const (
	TypeNone      uint32 = 1
	TypeBool      uint32 = 2
	TypeId        uint32 = 3
	TypeInt       uint32 = 4
	TypeLong      uint32 = 5
	TypeFloat     uint32 = 6
	TypeDouble    uint32 = 7
	TypeString    uint32 = 8
	TypeBytes     uint32 = 9
	TypeRectangle uint32 = 10
	TypeFraction  uint32 = 11
	TypeBitmap    uint32 = 12
	TypeArray     uint32 = 13
	TypeStruct    uint32 = 14
	TypeObject    uint32 = 15
	TypeSequence  uint32 = 16
	TypePointer   uint32 = 17
	TypeFd        uint32 = 18
	TypeChoice    uint32 = 19
	// TypePod is the "any pod" marker of the C parser. It never appears on
	// the wire and this package rejects it.
	TypePod uint32 = 20
)

// Pointer types, used in the type field of a Pointer pod.
const (
	TypeBuffer uint32 = 0x10001
	TypeMeta   uint32 = 0x10002
	TypeDict   uint32 = 0x10003
)

// Event and command types. Events and commands are Objects whose object type
// is one of these and whose object id is the event or command number.
const (
	TypeEventDevice   uint32 = 0x20001
	TypeEventNode     uint32 = 0x20002
	TypeCommandDevice uint32 = 0x30001
	TypeCommandNode   uint32 = 0x30002
)

// Object types (SPA_TYPE_OBJECT_*).
const (
	ObjectPropInfo            uint32 = 0x40001
	ObjectProps               uint32 = 0x40002
	ObjectFormat              uint32 = 0x40003
	ObjectParamBuffers        uint32 = 0x40004
	ObjectParamMeta           uint32 = 0x40005
	ObjectParamIO             uint32 = 0x40006
	ObjectParamProfile        uint32 = 0x40007
	ObjectParamPortConfig     uint32 = 0x40008
	ObjectParamRoute          uint32 = 0x40009
	ObjectProfiler            uint32 = 0x4000a
	ObjectParamLatency        uint32 = 0x4000b
	ObjectParamProcessLatency uint32 = 0x4000c
	ObjectParamTag            uint32 = 0x4000d
)

// Choice kinds (enum spa_choice_type).
const (
	ChoiceKindNone  uint32 = 0
	ChoiceKindRange uint32 = 1
	ChoiceKindStep  uint32 = 2
	ChoiceKindEnum  uint32 = 3
	ChoiceKindFlags uint32 = 4
)

// Property flags (struct spa_pod_prop).
const (
	PropFlagReadOnly   uint32 = 1 << 0
	PropFlagHardware   uint32 = 1 << 1
	PropFlagHintDict   uint32 = 1 << 2
	PropFlagMandatory  uint32 = 1 << 3
	PropFlagDontFixate uint32 = 1 << 4
)

// Node commands (spa/node/command.h), object type TypeCommandNode.
const (
	NodeCommandSuspend        uint32 = 0
	NodeCommandPause          uint32 = 1
	NodeCommandStart          uint32 = 2
	NodeCommandEnable         uint32 = 3
	NodeCommandDisable        uint32 = 4
	NodeCommandFlush          uint32 = 5
	NodeCommandDrain          uint32 = 6
	NodeCommandMarker         uint32 = 7
	NodeCommandParamBegin     uint32 = 8
	NodeCommandParamEnd       uint32 = 9
	NodeCommandRequestProcess uint32 = 10
)

// Node events (spa/node/event.h), object type TypeEventNode.
const (
	NodeEventError          uint32 = 0
	NodeEventBuffering      uint32 = 1
	NodeEventRequestRefresh uint32 = 2
	NodeEventRequestProcess uint32 = 3
)

// Param ids (enum spa_param_type, SPA_PARAM_*). They are the object ids of
// param objects and the ids used in param info lists.
const (
	ParamInvalid        uint32 = 0
	ParamPropInfo       uint32 = 1
	ParamProps          uint32 = 2
	ParamEnumFormat     uint32 = 3
	ParamFormat         uint32 = 4
	ParamBuffers        uint32 = 5
	ParamMeta           uint32 = 6
	ParamIO             uint32 = 7
	ParamEnumProfile    uint32 = 8
	ParamProfile        uint32 = 9
	ParamEnumPortConfig uint32 = 10
	ParamPortConfig     uint32 = 11
	ParamEnumRoute      uint32 = 12
	ParamRoute          uint32 = 13
	ParamControl        uint32 = 14
	ParamLatency        uint32 = 15
	ParamProcessLatency uint32 = 16
	ParamTag            uint32 = 17
)

// Format object keys (enum spa_format, SPA_FORMAT_*).
const (
	FormatMediaType             uint32 = 1
	FormatMediaSubtype          uint32 = 2
	FormatVideoFormat           uint32 = 0x20001
	FormatVideoModifier         uint32 = 0x20002
	FormatVideoSize             uint32 = 0x20003
	FormatVideoFramerate        uint32 = 0x20004
	FormatVideoMaxFramerate     uint32 = 0x20005
	FormatVideoViews            uint32 = 0x20006
	FormatVideoInterlaceMode    uint32 = 0x20007
	FormatVideoPixelAspectRatio uint32 = 0x20008
	FormatVideoMultiviewMode    uint32 = 0x20009
	FormatVideoMultiviewFlags   uint32 = 0x2000a
	FormatVideoChromaSite       uint32 = 0x2000b
	FormatVideoColorRange       uint32 = 0x2000c
	FormatVideoColorMatrix      uint32 = 0x2000d
	FormatVideoTransferFunction uint32 = 0x2000e
	FormatVideoColorPrimaries   uint32 = 0x2000f
)

// Media types and subtypes (SPA_MEDIA_TYPE_*, SPA_MEDIA_SUBTYPE_*).
const (
	MediaTypeUnknown     uint32 = 0
	MediaTypeAudio       uint32 = 1
	MediaTypeVideo       uint32 = 2
	MediaTypeImage       uint32 = 3
	MediaTypeBinary      uint32 = 4
	MediaTypeStream      uint32 = 5
	MediaTypeApplication uint32 = 6

	MediaSubtypeUnknown uint32 = 0
	MediaSubtypeRaw     uint32 = 1
	MediaSubtypeDsp     uint32 = 2
	MediaSubtypeIec958  uint32 = 3
	MediaSubtypeDsd     uint32 = 4
)

// Video formats this client offers (enum spa_video_format,
// SPA_VIDEO_FORMAT_*). The byte order in the comments is the order in memory
// and comes from the naming convention in video/raw.h, not from a captured
// frame.
const (
	VideoFormatUnknown uint32 = 0
	VideoFormatRGBx    uint32 = 7  // bytes R, G, B, x
	VideoFormatBGRx    uint32 = 8  // bytes B, G, R, x
	VideoFormatRGBA    uint32 = 11 // bytes R, G, B, A
	VideoFormatBGRA    uint32 = 12 // bytes B, G, R, A
)

// Keys of the Buffers param object (SPA_PARAM_BUFFERS_*), object type
// ObjectParamBuffers, object id ParamBuffers.
const (
	ParamBuffersBuffers  uint32 = 1
	ParamBuffersBlocks   uint32 = 2
	ParamBuffersSize     uint32 = 3
	ParamBuffersStride   uint32 = 4
	ParamBuffersAlign    uint32 = 5
	ParamBuffersDataType uint32 = 6
	ParamBuffersMetaType uint32 = 7
)

// Keys of the Meta and IO param objects (SPA_PARAM_META_*, SPA_PARAM_IO_*).
const (
	ParamMetaType uint32 = 1
	ParamMetaSize uint32 = 2
	ParamIOId     uint32 = 1
	ParamIOSize   uint32 = 2
)

// Data types of a buffer data block (enum spa_data_type, SPA_DATA_*).
const (
	DataInvalid uint32 = 0
	DataMemPtr  uint32 = 1
	DataMemFd   uint32 = 2
	DataDmaBuf  uint32 = 3
	DataMemId   uint32 = 4
	DataSyncObj uint32 = 5
)

// Bit masks for the dataType key of the Buffers param, which is a mask of
// 1 << data type: MemPtr 2, MemFd 4, DmaBuf 8.
const (
	DataMaskMemPtr uint32 = 1 << DataMemPtr
	DataMaskMemFd  uint32 = 1 << DataMemFd
	DataMaskDmaBuf uint32 = 1 << DataDmaBuf
)

// Meta types (enum spa_meta_type, SPA_META_*).
const (
	MetaInvalid        uint32 = 0
	MetaHeader         uint32 = 1
	MetaVideoCrop      uint32 = 2
	MetaVideoDamage    uint32 = 3
	MetaBitmap         uint32 = 4
	MetaCursor         uint32 = 5
	MetaControl        uint32 = 6
	MetaBusy           uint32 = 7
	MetaVideoTransform uint32 = 8
	MetaSyncTimeline   uint32 = 9
)

// IO types (enum spa_io_type, SPA_IO_*).
const (
	IOInvalid      uint32 = 0
	IOBuffers      uint32 = 1
	IORange        uint32 = 2
	IOClock        uint32 = 3
	IOLatency      uint32 = 4
	IOControl      uint32 = 5
	IONotify       uint32 = 6
	IOPosition     uint32 = 7
	IORateMatch    uint32 = 8
	IOMemory       uint32 = 9
	IOAsyncBuffers uint32 = 10
)

// Props keys (SPA_PROP_*). These are not in the protocol notes: they were
// written from memory of spa/param/props.h and the video path does not use
// them. Check them against the header before relying on them.
const (
	PropUnknown     uint32 = 1
	PropDevice      uint32 = 0x101
	PropDeviceName  uint32 = 0x102
	PropDeviceFd    uint32 = 0x103
	PropCard        uint32 = 0x104
	PropCardName    uint32 = 0x105
	PropMinLatency  uint32 = 0x106
	PropMaxLatency  uint32 = 0x107
	PropPeriods     uint32 = 0x108
	PropPeriodSize  uint32 = 0x109
	PropPeriodEvent uint32 = 0x10a
	PropLive        uint32 = 0x10b
	PropRate        uint32 = 0x10c
	PropVolume      uint32 = 0x10003
	PropMute        uint32 = 0x10004
	PropParams      uint32 = 0x80001
)
