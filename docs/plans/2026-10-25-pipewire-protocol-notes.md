# PipeWire protocol notes for a pure-Go capture client (2026-10-25)

Audience: engineers who implement `internal/agent/desktop/pipewire/{pod,proto,stream}` from
`docs/plans/2026-10-25-loose-ends.md` with no PipeWire daemon to test against.

## 0. Sources and how they were checked

- Every file below was fetched from `https://gitlab.freedesktop.org/pipewire/pipewire/-/raw/1.2.7/<path>`
  (tag 1.2.7). The tag 1.0.0 and master were not needed. Paths are relative to the repository root.
  Line numbers in this file are line numbers of those 1.2.7 files.
- Where a fact says "symbol", search that symbol in the named file.
- The POD byte examples in section 1.6 and the message examples in section 2.8 were produced by a
  small independent encoder (Python, written for this note) that follows `spa/pod/builder.h`. They
  are not copied from PipeWire. PipeWire's own tests carry no byte vectors: `test/test-spa-pod.c` only
  asserts struct sizes (lines 22-65, quoted in 1.1) and builds pods through the C builder, and
  `src/modules/module-protocol-native/test-connection.c` writes and reads one message through the C
  connection code. So "byte vectors from PipeWire's own tests" does not exist; the C struct-size
  assertions are the only test-side ground truth.
- The `pw_node_activation` offsets in 4.5 were checked by compiling a copy of the struct definitions
  with gcc (x86-64) and printing `offsetof`.
- All integers on the wire are host byte order. Every PipeWire target here is little endian (x86-64,
  arm64), so write little endian. Nothing in the protocol converts byte order.
- Nothing here was tested against a running daemon. Section 7 lists what is unverified.

## 1. SPA POD wire format

Files: `spa/include/spa/pod/pod.h`, `iter.h`, `builder.h`, `parser.h`; `spa/include/spa/utils/type.h`;
`spa/include/spa/utils/defs.h`; `test/test-spa-pod.c`.

### 1.1 Header, alignment, padding

| Fact | Value | Source |
|---|---|---|
| Header | 8 bytes: `size u32`, `type u32` | `pod.h` `struct spa_pod`; `test-spa-pod.c:22` asserts 8 |
| `size` | size of the body only, not counting the 8-byte header and not counting padding after the body | `pod.h` `SPA_POD_BODY_SIZE`, `SPA_POD_SIZE = 8 + size` |
| Alignment | every pod starts on an 8-byte boundary | `iter.h` `spa_pod_next`: `ROUND_UP_N(SPA_POD_SIZE(iter), 8)` |
| Padding | after each pod, zero bytes up to the next multiple of 8 | `builder.h` `spa_pod_builder_pad`, `spa_pod_builder_pop` |
| Next pod | `next = this + roundup8(8 + size)` | `iter.h:37` |
| Container size | a Struct or Object `size` counts its children including each child's padding, so it is a multiple of 8 | `builder.h` `spa_pod_builder_pop` writes the frame size after the children are padded |
| Validity | `spa_pod_is_inside`: header fits in the remaining bytes and `size` fits after the header | `iter.h:29` |
| Struct sizes asserted by tests | pod 8, bool/id/int/long/float/double 16, string/bytes/bitmap 8, rectangle/fraction 16, array body 8, array 16, choice body 16, choice 24, struct 8, object body 8, object 16, pointer body 16, pointer 24, fd 16, prop 16, control 16, sequence body 8, sequence 16 | `test-spa-pod.c:22-48` |

Decoder rule: read 8 bytes, check `size <= remaining - 8`, take `size` body bytes, advance by
`roundup8(8 + size)`. Reject a pod whose rounded size passes the end of the buffer.

### 1.2 Type ids (`spa/include/spa/utils/type.h`, enum starting at `SPA_TYPE_START = 0`)

| Id | Name | Body layout |
|---|---|---|
| 1 | None | empty body (`size 0`), pod is exactly 8 bytes |
| 2 | Bool | `int32` (0 or 1) |
| 3 | Id | `uint32` |
| 4 | Int | `int32` |
| 5 | Long | `int64` |
| 6 | Float | `float32` |
| 7 | Double | `float64` |
| 8 | String | UTF-8 bytes plus a terminating NUL; `size` includes the NUL |
| 9 | Bytes | raw bytes |
| 10 | Rectangle | `width u32`, `height u32` (`defs.h` `struct spa_rectangle`) |
| 11 | Fraction | `num u32`, `denom u32` (`defs.h` `struct spa_fraction`) |
| 12 | Bitmap | raw bytes |
| 13 | Array | see 1.4 |
| 14 | Struct | consecutive pods |
| 15 | Object | see 1.3 |
| 16 | Sequence | see 1.5 |
| 17 | Pointer | `type u32`, `pad u32`, `pointer 8 bytes` (host pointer, not usable across processes) |
| 18 | Fd | `int64` |
| 19 | Choice | see 1.4 |
| 20 | Pod | a "any pod" marker used by the C parser, never on the wire as a body type |

Other id ranges in the same enum (used as object types, `type` fields of Pointer, Event and Command):

| Range start | Meaning | Members that matter here |
|---|---|---|
| `0x10000` | Pointer types | Buffer `0x10001`, Meta `0x10002`, Dict `0x10003` |
| `0x20000` | Event types | Device `0x20001`, Node `0x20002` |
| `0x30000` | Command types | Device `0x30001`, Node `0x30002` |
| `0x40000` | Object types | PropInfo `0x40001`, Props `0x40002`, Format `0x40003`, ParamBuffers `0x40004`, ParamMeta `0x40005`, ParamIO `0x40006`, ParamProfile `0x40007`, ParamPortConfig `0x40008`, ParamRoute `0x40009`, Profiler `0x4000a`, ParamLatency `0x4000b`, ParamProcessLatency `0x4000c`, ParamTag `0x4000d` |

Basic String rule: `spa_pod_is_string` requires `size > 0` and last byte `0`
(`iter.h:215`). A C `NULL` string argument is written as a None pod, not an empty string
(`builder.h` `case 's'`, line 489). An empty string is `size 1`, body `00`.

Fd: the body is an `int64` that is an index into the fd array that came with the message, not a file
descriptor number (see 2.4). A sender writes `0xffffffff` (as int64 `4294967295`) for "no fd";
`pw_protocol_native_connection_get_fd` maps `index == SPA_ID_INVALID` to `-1`
(`connection.c:77-90`, `add_fd` returns `SPA_IDX_INVALID` for `fd < 0`, line 102).

### 1.3 Object and properties

Object body: `object_type u32`, `object_id u32`, then zero or more properties
(`pod.h` `struct spa_pod_object_body`).

Property: `key u32`, `flags u32`, then a complete pod (header, body, padding). The next property starts
at `prop + roundup8(16 + value.size)` (`iter.h` `spa_pod_prop_next`, line 58). Because the value pod
already pads itself to 8, this equals `prop + 8 + roundup8(8 + value.size)`.

Property flags (`pod.h` `struct spa_pod_prop`): READONLY `1<<0`, HARDWARE `1<<1`, HINT_DICT `1<<2`,
MANDATORY `1<<3`, DONT_FIXATE `1<<4`. All the params in this note use flags `0`.

Command and Event pods are Objects: `object_type` is `0x30002` (Node command) or `0x20002` (Node
event) and `object_id` is the command or event number, with no properties unless the command defines
some (`spa/pod/command.h`, `event.h`: `struct spa_command_body` is just the object body).

Node command ids (`spa/node/command.h`): Suspend 0, Pause 1, Start 2, Enable 3, Disable 4, Flush 5,
Drain 6, Marker 7, ParamBegin 8, ParamEnd 9, RequestProcess 10.
Node event ids (`spa/node/event.h`): Error 0, Buffering 1, RequestRefresh 2, RequestProcess 3.

### 1.4 Array and Choice

Array body: `child_size u32`, `child_type u32`, then `n * child_size` bytes of values, with no header and
no padding between values (`builder.h` `spa_pod_builder_array`, line 357; `pod.h`
`struct spa_pod_array_body`). `n = (size - 8) / child_size`.

Choice body: `choice_type u32`, `flags u32`, `child_size u32`, `child_type u32`, then values, again with no
per-value header and no padding between values (`pod.h` `struct spa_pod_choice_body`; `builder.h`
`spa_pod_builder_push_choice`, line 382). `flags` has no defined bit in 1.2.7 ("extra flags"); write 0.

| Choice type | Id | Values in order |
|---|---|---|
| None | 0 | `default` (only the first value is used) |
| Range | 1 | `default`, `min`, `max` |
| Step | 2 | `default`, `min`, `max`, `step` |
| Enum | 3 | `default`, `alt1`, `alt2`, ... (the default is repeated as the first alternative by PipeWire's own code, see `src/examples/sdl.h` `sdl_build_formats`: it writes the first id twice) |
| Flags | 4 | `default`, then the possible flag bits |

Source: `pod.h` `enum spa_choice_type`; `test/test-spa-pod.c:72-80` `pod_abi` asserts the numbers 0..4.

A reader treats a plain value (not a Choice) as a Choice with one value: `iter.h` `spa_pod_get_values`
(line 348) returns `n_vals = 1`, `choice = None` for non-choice pods. For `None` choices only the
first value counts even if more are present. Accept both forms everywhere a param is parsed. When the
server fixates a format it sends plain values; EnumFormat from a producer carries Choices.

Array and Choice child types are fixed-size types (Int, Id, Long, Rectangle, Fraction and so on);
the child header's `size` is the size of one value.

### 1.5 Sequence

Body: `unit u32`, `pad u32`, then controls. Control: `offset u32`, `type u32`, then a value pod
(`pod.h` `struct spa_pod_sequence_body`, `struct spa_pod_control`; next control at
`roundup8(16 + value.size)`, `iter.h:77`). Not used by the video path.

### 1.6 Worked examples (little endian hex, bytes in file order)

Each line is 16 bytes. Padding bytes are shown as `00`.

```text
None                                    (8 bytes)
  00 00 00 00 01 00 00 00

Bool true                               (16)
  04 00 00 00 02 00 00 00 01 00 00 00 00 00 00 00

Int 42                                  (16)
  04 00 00 00 04 00 00 00 2a 00 00 00 00 00 00 00

Long 1                                  (16)
  08 00 00 00 05 00 00 00 01 00 00 00 00 00 00 00

Id 8                                    (16)  8 = SPA_VIDEO_FORMAT_BGRx
  04 00 00 00 03 00 00 00 08 00 00 00 00 00 00 00

String "hi"                             (16)  size 3 = 'h','i',NUL; 5 bytes of padding
  03 00 00 00 08 00 00 00 68 69 00 00 00 00 00 00

Rectangle 1920x1080                     (16)
  08 00 00 00 0a 00 00 00 80 07 00 00 38 04 00 00

Fraction 30/1                           (16)
  08 00 00 00 0b 00 00 00 1e 00 00 00 01 00 00 00

Fd index 0                              (16)
  08 00 00 00 12 00 00 00 00 00 00 00 00 00 00 00

Struct { Int 1, String "a" }            (40)  size 0x20 = 16 (Int) + 16 (String)
  20 00 00 00 0e 00 00 00 04 00 00 00 04 00 00 00
  01 00 00 00 00 00 00 00 02 00 00 00 08 00 00 00
  61 00 00 00 00 00 00 00

Array of Int {1,2,3}                    (32)  body = 8 + 12 = 20 = 0x14, padded by 4
  14 00 00 00 0d 00 00 00 04 00 00 00 04 00 00 00
  01 00 00 00 02 00 00 00 03 00 00 00 00 00 00 00

Choice Enum of Id {default 8, 8, 7, 12} (40)  body = 16 + 16 = 32 = 0x20
  20 00 00 00 13 00 00 00 03 00 00 00 00 00 00 00
  04 00 00 00 03 00 00 00 08 00 00 00 08 00 00 00
  07 00 00 00 0c 00 00 00

Choice Range of Int {8, 2, 64}          (40)  body = 16 + 12 = 28 = 0x1c, padded by 4
  1c 00 00 00 13 00 00 00 01 00 00 00 00 00 00 00
  04 00 00 00 04 00 00 00 08 00 00 00 02 00 00 00
  40 00 00 00 00 00 00 00

Choice Range of Rectangle {320x240, 1x1, 4096x4096}   (48)
  28 00 00 00 13 00 00 00 01 00 00 00 00 00 00 00
  08 00 00 00 0a 00 00 00 40 01 00 00 f0 00 00 00
  01 00 00 00 01 00 00 00 00 10 00 00 00 10 00 00

Object type Format (0x40003) id EnumFormat (3), props mediaType=Id 2 (video), mediaSubtype=Id 1 (raw)  (64)
  38 00 00 00 0f 00 00 00 03 00 04 00 03 00 00 00
  01 00 00 00 00 00 00 00 04 00 00 00 03 00 00 00
  02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00
  04 00 00 00 03 00 00 00 01 00 00 00 00 00 00 00
  (object body 0x38 = 8 + 24 + 24; each property is key, flags, then a 16-byte Id pod)

Command Start: Object type 0x30002, id 2, no props   (16)
  08 00 00 00 0f 00 00 00 02 00 03 00 02 00 00 00
```

## 2. Native protocol (`PipeWire:Protocol:Native`)

Files: `src/modules/module-protocol-native/connection.c`, `connection.h`, `protocol-native.c`,
`protocol-footer.c`, `protocol-footer.h`, `defs.h`; `src/modules/module-protocol-native.c`;
`src/pipewire/extensions/protocol-native.h`; `src/pipewire/core.c`; `src/pipewire/impl-core.c`;
`spa/include/spa/utils/result.h`.

### 2.1 Transport

A `SOCK_STREAM` Unix socket (portal case: an already connected fd). Messages are written back to back;
file descriptors travel in `SCM_RIGHTS` control data of the same `sendmsg`/`recvmsg` calls as the bytes.
The receiver reads with `MSG_DONTWAIT | MSG_CMSG_CLOEXEC` (`connection.c` `refill_buffer`, line 198).

### 2.2 Message header (protocol version 3), 16 bytes

| Offset | Field | Meaning | Source |
|---|---|---|---|
| 0 | `id u32` | destination proxy id (client side) or resource id (server side). 0 = core, 1 = client | `connection.c` `prepare_packet` line 493 `buf->msg.id = p[0]` |
| 4 | `u32` | `opcode << 24 | size`: opcode is the top 8 bits, size the low 24 bits (payload bytes after the header, so at most 16 MiB - 1) | `prepare_packet`: `opcode = p[1] >> 24`, `len = p[1] & 0xffffff`; `connection_end` line 697: `(opcode << 24) | (size & 0xffffff)` |
| 8 | `seq u32` | per-direction sequence number, incremented for each message sent and masked with `0x3fffffff` (`SPA_ASYNC_SEQ_MASK`) | `connection_end`: `buf->seq = (buf->seq + 1) & SPA_ASYNC_SEQ_MASK`; `result.h:25-34` |
| 12 | `n_fds u32` | number of fds that belong to this message | `prepare_packet`: `buf->msg.n_fds = p[3]` |

The payload follows immediately. It is one Struct pod (every method and event in 1.2.7 is marshalled as
exactly one Struct), optionally followed by a footer pod (2.5). The payload size in the header is the
padded size of everything after the header, so it is a multiple of 8.

Version 0 headers (8 bytes, no seq and no n_fds) exist for ancient peers: the server decides by looking at
the first `Hello` (`id 0, opcode 1`); `p[3] >= 4` there means the old header (`prepare_packet`
lines ~512-520). The client is always version 3 and the connection object starts with
`impl->version = 3` (`connection.c:434`). A client never needs the 8-byte form.

Seq in method arguments: `Sync` sends `Int(SPA_RESULT_RETURN_ASYNC(msg->seq))` where `msg->seq` is the header
seq of that same Sync message, so the argument is `0x40000000 | header_seq`
(`protocol-native.c` `core_method_marshal_sync`, line ~49). The server echoes the argument unchanged in
`Done`. `Ping` events from the server use the same encoding and `Pong` must echo both ints unchanged
(`core_event_marshal_ping`, `core.c` `core_event_ping` line 24 calls `pw_core_pong(this, id, seq)`).

### 2.3 Proxy id space

`core.c` `core_new`: `pw_map_init(&p->objects, 64, 32)` and ids are handed out by `pw_map_insert_new`
(`proxy.c` `pw_proxy_init` line 32). The core proxy gets id 0 (`PW_ID_CORE`, `core.h:48`), the client
proxy id 1 (`PW_ID_CLIENT`, `client.h:34`), and the next proxy created gets id 2. For this client the
ClientNode proxy is therefore id 2 unless something else was created first. Ids freed by `RemoveId` may be
reused by the allocator.

### 2.4 File descriptors in messages

- A message's `n_fds` fds are the next `n_fds` entries of the receive-side fd queue. Fds are appended to
  the queue in the order `recvmsg` delivers them and a message consumes `n_fds` from the head
  (`prepare_packet`: `buf->msg.fds = &buf->fds[buf->fds_offset]`, `fds_offset += n_fds`).
- An Fd pod value is an index into that message's own fd list, starting at 0. The sender
  de-duplicates: the same fd added twice to one message gets the same index
  (`connection.c:102` `add_fd`, loop over `buf->msg.fds`).
- The first fds can arrive in an earlier or later `recvmsg` than the bytes of their message: the sender
  attaches all queued fds to the first `sendmsg` of the flush (`connection_flush`, line 749). With more than
  28 fds queued it sends 4 bytes per `sendmsg` with 28 fds each until the fds are gone (`MAX_FDS_MSG 28`).
  A receiver must therefore keep a connection-wide fd queue and a byte buffer and only pair them when a
  full message is available.
- Received fds are close-on-exec. The sender duplicates each fd with `F_DUPFD_CLOEXEC` when adding it and
  closes its own copy after the flush, so the caller's fd stays valid.
- A message with `n_fds + queued > 1024` is a protocol error (`MAX_FDS 1024`).

### 2.5 Footers

What: a second pod that follows the message Struct inside the same payload, layout
`Struct { Id opcode, Struct { ...entry fields... } }*` (`module-protocol-native.c` `pre_demarshal`, lines
286-330: it pushes the outer Struct, then repeatedly reads an `Id` opcode and pushes an inner Struct).
Only one footer opcode exists in 1.2.7: opcode 0 `GENERATION`, entry `Struct { Long generation }`
(`protocol-footer.h`: `FOOTER_CORE_OPCODE_GENERATION = 0`, `FOOTER_CLIENT_OPCODE_GENERATION = 0`;
`protocol-footer.c`).

When the server sends one: `marshal_client_footers` runs for every server-to-client message
(`module-protocol-native.c` `impl_ext_end_resource`, line ~1614) and writes a footer only when
`client->context->generation != client->sent_generation`, then updates `sent_generation`. The generation
counter is the registry generation; it changes when globals appear or disappear. In practice the first
messages after connect carry a footer and then it appears again after every registry change. A client may
see a footer on any server message.

When the client sends one: `marshal_core_footers` appends the last received generation when it changed
(`protocol-footer.c`). A client that never sends footers is accepted: the server ignores a missing footer
(`pre_demarshal` returns silently when `get_footer` is NULL).

How to skip safely:

1. Take the message payload from the header size.
2. Parse exactly one pod at offset 0 and use that Struct for the message arguments.
3. Ignore every byte after `roundup8(8 + struct.size)`. Do not require the payload to end there.
4. If you want to read it: apply `get_first_pod_from_data` rules (`defs.h`): the remaining bytes, rounded
   down to a multiple of 8, must hold the 8-byte header plus `size` bytes; otherwise there is no footer
   (`connection.c:618` `get_footer`). Unknown footer opcodes are ignored by PipeWire itself.
5. Never reject a message because its payload is longer than its argument Struct.

### 2.6 Versions

| What | Value | Source |
|---|---|---|
| Protocol (header) version | 3 | `connection.c:434` `impl->version = 3` |
| Core interface version, sent in Hello | 4 | `core.h:39` `PW_VERSION_CORE`; `core.c:361` `pw_core_hello(p, PW_VERSION_CORE)` |
| Core events table version | 1 | `core.h:102` `PW_VERSION_CORE_EVENTS` |
| Client interface version | 3 | `client.h:30` `PW_VERSION_CLIENT` |
| Registry interface version | 3 | `core.h:41` |
| ClientNode interface version | 6 | `extensions/client-node.h:30`: 4 added PortSetMixInfo, 5 driver nodes scheduled on the client, 6 client sets activation INACTIVE to FINISHED |
| Server binds the Client object on Hello only if | `version >= 3` | `impl-core.c` `core_hello` |

### 2.7 Connection sequence

1. Connect the socket (or use the portal's fd). Nothing is sent by the server first.
2. Client: `Core.Hello(Struct{Int 4})` on id 0, opcode 1 (`core.c:361`).
3. Client: `Client.UpdateProperties(Struct{Struct{dict}})` on id 1, opcode 2 (`core.c:362`). The client sends
   both without waiting for any reply. The client proxy id 1 exists on the client from the start.
4. Server, in response to Hello (`impl-core.c` `core_hello`): `Core.Info` (id 0, opcode 0) with change mask
   all; then, because `version >= 3`, it binds the client global at id 1, which sends `Client.Info`
   (id 1, opcode 0, from `impl-client.c` `global_bind`) and, from `global.c:264`, a
   `Core.BoundProps` (or `BoundId`) for id 1. The
   server may add a `Client.Info` again after it processed `UpdateProperties`
   (`impl-client.c` `update_properties`). Dispatch by (id, opcode); do not depend on the exact order.
5. `Core.Sync` / `Core.Done`: pw_stream does not Sync at connect. `pw_core_sync` is used by
   `pw_proxy_sync` (`proxy.c:308`) only. A client may send `Sync(id 0, seq)` to know the server has
   processed everything sent so far; the answer is `Done(Struct{Int id, Int seq})` with the same values.
   `Done` with `id == 0xffffffff` is ignored by PipeWire (`core_event_demarshal_done`).
6. Client: `Core.CreateObject("client-node", "PipeWire:Interface:ClientNode", 6, props, new_id)` (2.9, section 4).
7. After this the server sends `Core.BoundProps` (id = new_id, global id, props) when the node is registered,
   then `ClientNode.Transport`, and so on (section 4).

Errors: the server reports a failed request with `Core.Error(id, seq, res, message)` where `id` is the proxy id
involved and `res` a negative errno; after a failed `CreateObject` it also sends `Core.RemoveId(new_id)`
(`impl-core.c` `core_create_object` error paths). The client reports errors on a proxy with the
`Core.Error` method using that proxy id and the header `seq` of the message that caused it
(`proxy.c:315-339` `pw_proxy_error*` call `pw_core_error(core, proxy->id, core->recv_seq, res, msg)`).

The C client keeps going after most errors: `core_event_error` (`core.c:36-50`) looks the proxy up by id and emits the
error on that proxy only, `Core.Error` on id 0 with `res = -EPIPE` is the disconnect, and a message that fails to
demarshal is logged and skipped (`protocol-native.c` "invalid message received", `res = 0`). The Go `Conn` does the same:
it hands `CoreErrorEvent` to the handler of the proxy it names, ends only on `-EPIPE` for id 0, and drops messages that do
not decode (closing their fds). Port param infos need the SERIAL bit flipped when a param changes, because
`impl-port.c:652` skips a param whose flags are unchanged (`stream.c:565-590` does the flip); the stream flips it for
Format and Buffers on every format negotiation.

Limits PipeWire enforces while parsing (use the same in a Go decoder): dict items 1024, param infos 128,
params per update 4096, buffers 64, metas per buffer 16, datas per buffer 64, permissions 4096
(`protocol-native.c:18-20`, `module-client-node/protocol-native.c:16-21`).

### 2.8 Message examples

```text
Hello: id 0, opcode 1, size 24, seq 0, n_fds 0, body Struct{Int 4}
  00 00 00 00 18 00 00 01 00 00 00 00 00 00 00 00      header  (u32 0x01000018 = 1<<24 | 24)
  10 00 00 00 0e 00 00 00 04 00 00 00 04 00 00 00      Struct size 16, Int pod header
  04 00 00 00 00 00 00 00                              Int value 4, padding

Sync: id 0, opcode 2, size 40, seq 1, body Struct{Int 0, Int 0x40000001}
  00 00 00 00 28 00 00 02 01 00 00 00 00 00 00 00
  20 00 00 00 0e 00 00 00 04 00 00 00 04 00 00 00
  00 00 00 00 00 00 00 00 04 00 00 00 04 00 00 00
  01 00 00 40 00 00 00 00

A footer pod (generation 5):  Struct{ Id 0, Struct{ Long 5 } }   (48 bytes)
  28 00 00 00 0e 00 00 00 04 00 00 00 03 00 00 00
  00 00 00 00 00 00 00 00 10 00 00 00 0e 00 00 00
  08 00 00 00 05 00 00 00 05 00 00 00 00 00 00 00

Transport event body (fd indexes 0 and 1, mem id 3, offset 0, size 2312), n_fds 2   (88 bytes)
  50 00 00 00 0e 00 00 00 08 00 00 00 12 00 00 00
  00 00 00 00 00 00 00 00 08 00 00 00 12 00 00 00
  01 00 00 00 00 00 00 00 04 00 00 00 04 00 00 00
  03 00 00 00 00 00 00 00 04 00 00 00 04 00 00 00
  00 00 00 00 00 00 00 00 04 00 00 00 04 00 00 00
  08 09 00 00 00 00 00 00

Client.UpdateProperties body, one property media.type=Video   (72 bytes)
  40 00 00 00 0e 00 00 00 38 00 00 00 0e 00 00 00
  04 00 00 00 04 00 00 00 01 00 00 00 00 00 00 00
  0b 00 00 00 08 00 00 00 6d 65 64 69 61 2e 74 79
  70 65 00 00 00 00 00 00 06 00 00 00 08 00 00 00
  56 69 64 65 6f 00 00 00
```

### 2.9 Dict encoding (used by Info, CreateObject, UpdateProperties, AddPort, PortSetMixInfo)

A dict is `Struct { Int n_items, (String key, String value) * n_items }`
(`protocol-native.c` `push_dict` / `parse_dict_struct`, lines 118-165). Where the dict is a field of an
outer Struct it is a nested Struct pod, except in `ClientNode.Update` / `PortUpdate` where the props are
written inline inside the info Struct (no nested Struct, see 3.3). A value that begins with
`pointer:` is sent as an empty string (`push_item`). A dict with 0 items is still a Struct with `Int 0`.

## 3. Core, Client, ClientNode: opcodes and argument layouts

Notation: "Struct{...}" is the one top-level Struct of the payload. `Int` is an Int pod, `Id` an Id pod,
`Pod` an arbitrary pod copied in place (`SPA_POD_Pod`), `Dict` is the nested Struct from 2.9. `None` replaces a
`Pod` when the C side passed NULL (`builder.h:548-556`).

### 3.1 Core (id 0). Interface `PipeWire:Interface:Core` version 4

Methods, client to server (`core.h:218-226`, marshal in `protocol-native.c`):

| Opcode | Name | Args | Source |
|---|---|---|---|
| 0 | AddListener | local only, never on the wire | |
| 1 | Hello | `Struct{Int version}` (send 4) | `core_method_marshal_hello` |
| 2 | Sync | `Struct{Int id, Int seq}`; seq = `0x40000000 \| header seq` | `core_method_marshal_sync` |
| 3 | Pong | `Struct{Int id, Int seq}`, echo the Ping | `core_method_marshal_pong` |
| 4 | Error | `Struct{Int id, Int seq, Int res, String message}` | `core_method_marshal_error` |
| 5 | GetRegistry | `Struct{Int version, Int new_id}` (not needed) | `core_method_marshal_get_registry` |
| 6 | CreateObject | `Struct{String factory_name, String type, Int version, Dict props, Int new_id}` | `core_method_marshal_create_object` (line 243) |
| 7 | Destroy | `Struct{Int id}` (proxy id to destroy) | `core_method_marshal_destroy` |

Events, server to client (`core.h:87-96`):

| Opcode | Name | Args | Source |
|---|---|---|---|
| 0 | Info | `Struct{Int id, Int cookie, String user_name, String host_name, String version, String name, Long change_mask, Dict props}`; `change_mask` bit 0 = props present | `core_event_marshal_info` (line 461), `core_event_demarshal_info` |
| 1 | Done | `Struct{Int id, Int seq}` | `core_event_demarshal_done` |
| 2 | Ping | `Struct{Int id, Int seq}`; answer with Pong echoing both | `core_event_demarshal_ping` |
| 3 | Error | `Struct{Int id, Int seq, Int res, String message}` | `core_event_demarshal_error` |
| 4 | RemoveId | `Struct{Int id}` | `core_event_demarshal_remove_id` |
| 5 | BoundId | `Struct{Int id, Int global_id}` | `core_event_demarshal_bound_id` |
| 6 | AddMem | `Struct{Int id, Id type, Fd fd_index, Int flags}`; `type` is a `spa_data_type` (MemFd 2, DmaBuf 3); `flags` are `PW_MEMBLOCK_FLAG_*` | `core_event_demarshal_add_mem` |
| 7 | RemoveMem | `Struct{Int id}` | `core_event_demarshal_remove_mem` |
| 8 | BoundProps | `Struct{Int id, Int global_id, Dict props}` | `core_event_demarshal_bound_props` |

Notes:

- The server sends BoundProps when the Hello version was 4 or more and BoundId otherwise
  (`resource.c:206-209`, `pw_resource_set_bound_id`; called from `global.c:264` when a client binds a global
  and from `client-node.c:1341` for the client node). The client sends Hello 4, so expect BoundProps.
  Handle both opcodes.
- AddMem id: the client's pool assigns block ids itself in arrival order and PipeWire checks that the id in
  the event equals the id it assigned (`core.c` `core_event_add_mem`, line 71). Treat the event id as the
  key for every later `mem_id` reference, and remove with RemoveMem.
- A mem id is only valid between its AddMem and RemoveMem.

### 3.2 Client (id 1). Interface `PipeWire:Interface:Client` version 3

Methods (`client.h:88-93`):

| Opcode | Name | Args | Source |
|---|---|---|---|
| 0 | AddListener | local only | |
| 1 | Error | `Struct{Int id, Int res, String error}` | `client_marshal_error` |
| 2 | UpdateProperties | `Struct{Dict props}` (the dict Struct nested inside the outer Struct) | `client_marshal_update_properties` (line 1660) |
| 3 | GetPermissions | `Struct{Int index, Int num}` | `client_marshal_get_permissions` |
| 4 | UpdatePermissions | `Struct{Int n, (Int id, Int permissions)*n}` | `client_marshal_update_permissions` |

Events (`client.h:57-59`):

| Opcode | Name | Args | Source |
|---|---|---|---|
| 0 | Info | `Struct{Int id, Long change_mask, Dict props}` | `client_marshal_info` |
| 1 | Permissions | `Struct{Int index, Struct{Int n, (Int id, Int permissions)*n}}` | `client_marshal_permissions` |

### 3.3 ClientNode (a proxy created by CreateObject). Interface `PipeWire:Interface:ClientNode` version 6

Source for all rows: `src/pipewire/extensions/client-node.h` (opcode numbers) and
`src/modules/module-client-node/protocol-native.c` (layouts).

Interface strings (type name = `PW_TYPE_INFO_BASE "Interface:" name`, `type.h:27-33`):
`PipeWire:Interface:Core`, `PipeWire:Interface:Client`, `PipeWire:Interface:ClientNode`,
`PipeWire:Interface:Node`, `PipeWire:Interface:Registry`.

CreateObject for a client node, exactly as `remote-node.c` `node_export` (line 1180) sends it:
factory name `client-node`, type `PipeWire:Interface:ClientNode` (the server compares the type string to the
factory's type and answers `-EPROTO "wrong resource type/version"` on mismatch, `impl-core.c`
`core_create_object`), version `6` (`PW_VERSION_CLIENT_NODE`; a server whose factory is older only logs it),
props = the node's property dict (4.1), `new_id` = the new proxy id (2 for the first). The factory is
registered in `src/modules/module-client-node.c` (`pw_context_create_factory(context, "client-node", ...)`).
Version 0 selects a legacy path on the server (`create_object`: `if (version == 0)`); never send 0.

Methods, client to server (`client-node.h:226-233`):

| Opcode | Name | Args |
|---|---|---|
| 0 | AddListener | local only |
| 1 | GetNode | `Struct{Int version, Int new_id}` (stream.c does not call it) |
| 2 | Update | `Struct{Int change_mask, Int n_params, Pod param * n_params, NodeInfo | None}`; `change_mask` bit 0 = params, bit 1 = info |
| 3 | PortUpdate | `Struct{Int direction, Int port_id, Int change_mask, Int n_params, Pod param * n_params, PortInfo | None}`; bit 0 = params, bit 1 = info |
| 4 | SetActive | `Struct{Bool active}` |
| 5 | Event | `Struct{Pod event}` |
| 6 | PortBuffers | `Struct{Int direction, Int port_id, Int mix_id, Int n_buffers, per buffer: Int n_datas, per data: Id type, Fd fd_index, Int flags, Int mapoffset, Int maxsize}`; only when the port flag CAN_ALLOC_BUFFERS is set and the server asked for allocation, so not used for a video input stream |

`NodeInfo` (a Struct pod, `client_node_marshal_update` line 164 and `client_node_demarshal_update`):
`Struct{Int max_input_ports, Int max_output_ports, Long change_mask, Long flags, Int n_items, (String key, String value)*n_items, Int n_params, (Id param_id, Int param_flags)*n_params}`.
The props are inline here, not a nested Struct. `change_mask` bits: FLAGS `1<<0`, PROPS `1<<1`, PARAMS `1<<2`
(`spa/node/node.h:44-46`). Node flags: RT `1<<0`, ASYNC `1<<6` (`node.h:49,58`).

`PortInfo` (`client_node_marshal_port_update` line 225):
`Struct{Long change_mask, Long flags, Int rate_num, Int rate_denom, Int n_items, (String key, String value)*n_items, Int n_params, (Id param_id, Int param_flags)*n_params}`.
Port change_mask bits: FLAGS `1<<0`, RATE `1<<1`, PROPS `1<<2`, PARAMS `1<<3`
(`node.h:76-79`). Port flags: REMOVABLE `1<<0`, OPTIONAL `1<<1`, CAN_ALLOC_BUFFERS `1<<2`, IN_PLACE `1<<3`,
NO_REF `1<<4`, LIVE `1<<5`, PHYSICAL `1<<6`, TERMINAL `1<<7`, DYNAMIC_DATA `1<<8`.
Param info flags (`spa/param/param.h`): SERIAL `1<<0`, READ `1<<1`, WRITE `1<<2`. The server enumerates
only the param ids it sees with READ.

A PortUpdate with `change_mask` 0 (and `n_params 0`, info `None`) removes the port
(`remote-node.c` `node_port_removed`; `client_node_port_update` treats `change_mask == 0` as remove).

Events, server to client (`client-node.h:43-55`):

| Opcode | Name | Args |
|---|---|---|
| 0 | Transport | `Struct{Fd read_fd, Fd write_fd, Int mem_id, Int offset, Int size}` |
| 1 | SetParam | `Struct{Id param_id, Int flags, Pod param}` (node level) |
| 2 | SetIO | `Struct{Id io_id, Int mem_id, Int offset, Int size}`; `mem_id == 0xffffffff` with offset 0 size 0 clears the area |
| 3 | Event | `Struct{Pod event}` |
| 4 | Command | `Struct{Pod command}` |
| 5 | AddPort | `Struct{Int direction, Int port_id, Dict props}`; stream.c answers `-ENOTSUP` (`remote-node.c` `client_node_add_port`) |
| 6 | RemovePort | `Struct{Int direction, Int port_id}`; also `-ENOTSUP` in `remote-node.c` |
| 7 | PortSetParam | `Struct{Int direction, Int port_id, Id param_id, Int flags, Pod param}`; `param` is None to clear |
| 8 | PortUseBuffers | `Struct{Int direction, Int port_id, Int mix_id, Int flags, Int n_buffers, per buffer: Int mem_id, Int offset, Int size, Int n_metas, (Id meta_type, Int meta_size)*n_metas, Int n_datas, (Id data_type, Int data_id, Int data_flags, Int mapoffset, Int maxsize)*n_datas}`; `n_buffers` may be 0 to clear |
| 9 | PortSetIO | `Struct{Int direction, Int port_id, Int mix_id, Id io_id, Int mem_id, Int offset, Int size}` |
| 10 | SetActivation | `Struct{Int node_id, Fd signal_fd, Int mem_id, Int offset, Int size}`; `mem_id == 0xffffffff` removes that peer |
| 11 | PortSetMixInfo | `Struct{Int direction, Int port_id, Int mix_id, Int peer_id, Dict props}`; `peer_id == 0xffffffff` removes the mix |

Notes on mix ids: a port starts with an implicit mix whose id is `0xffffffff`
(`remote-node.c` `do_node_init`: `create_mix(data, port, SPA_ID_INVALID, SPA_ID_INVALID)`). Each link to
the port adds a mix with a small integer id announced by PortSetMixInfo; PortUseBuffers and PortSetIO then
carry that mix id (`remote-node.c` `client_node_port_set_mix_info`, `find_mix`). Key client state by
(direction, port_id, mix_id), not by port alone.

## 4. What `pw_stream` does for an input video stream

Files: `src/pipewire/stream.c`, `src/modules/module-client-node/remote-node.c`,
`src/modules/module-client-node/client-node.c` (server side of the same node),
`src/pipewire/impl-node.c`, `src/pipewire/impl-port.c`, `src/pipewire/impl-link.c`,
`src/pipewire/private.h`, `src/examples/video-play.c`.

Important structural fact: `pw_stream_connect` (stream.c:1858) builds a local `pw_impl_node` whose
implementation is the stream, then calls `pw_core_export(core, PW_TYPE_INTERFACE_Node, ...)`
(`stream.c:2118`). That goes to `node_export` in `remote-node.c`, which sends `CreateObject` and
then replays the node's info and params as `Update` and `PortUpdate`. So everything on the wire is a
translation of the local node's info. A Go client does not need that machinery; it only needs to send the
same messages.

### 4.1 Properties that end up in CreateObject and Update

The dict is the stream's property dict (`remote-node.c` `node_export`: `&node->properties->dict`;
`add_node_update`: `ni.props = node->info.props`). `pw_stream_connect` adds these before export:

| Property | When | Source (stream.c) |
|---|---|---|
| `media.type` = `Video` | the application passes it (video-play.c:470 uses `PW_KEY_MEDIA_TYPE, "Video"`) | app |
| `media.category` = `Capture` | app (video-play.c:471) | app |
| `media.role` = `Screen` (video-play uses `Camera`) | app | app |
| `media.class` = `Stream/Input/Video` | if the app did not set it: `"Stream/%s/%s"` with `Input` for direction input and `media.type` | line 1993 and the block around it (`get_media_class` for the fallback) |
| `node.target` = decimal node id (deprecated key, still what the portal uses) | `target_id != PW_ID_ANY` and `node.target` unset | line 1967, "XXX this is deprecated but still used by the portal" comment |
| `target.object` | alternative, newer key (`keys.h:374`) | app |
| `node.autoconnect` = `true` | flag AUTOCONNECT | line 1970 |
| `node.dont-reconnect` = `true` | flag DONT_RECONNECT | |
| `node.loop.class` = `main` and `node.async` = `true` | unless flag RT_PROCESS | line 1981 |
| `port.group` = `stream.0` | always, also in the port props | lines 2015 and 2078 |
| `node.name` | app or default | `keys.h:142` |

The `node.async=true` property makes the server treat the node as asynchronous
(`impl-node.c:1228` reads `PW_KEY_NODE_ASYNC`), which changes scheduling in 4.5.

### 4.2 Message order sent by the client

1. `Core.Hello(4)` and `Client.UpdateProperties(props)` (2.7).
2. `Core.CreateObject("client-node", "PipeWire:Interface:ClientNode", 6, props, 2)`.
3. `ClientNode.Update` (`do_node_init`, `remote-node.c:939` calls `add_node_update(PARAMS|INFO, FLAGS|PROPS|PARAMS)`).
4. `ClientNode.PortUpdate` for the one input port (`add_port_update(PARAMS|INFO)`).
5. `ClientNode.SetActive(true)` after the Transport event arrives and the activation is mapped
   (`client_node_transport`, `remote-node.c:181`, ends with `if (node->active) pw_client_node_set_active(true)`).
   Later changes of the active flag send SetActive again (`node_active_changed`). Without
   `PW_STREAM_FLAG_INACTIVE` the node is active from the start (`stream.c`: `pw_impl_node_set_active(stream->node, !INACTIVE)`).

`Update` content (`add_node_update`, `stream.c` node info):

| Field | Value |
|---|---|
| outer `change_mask` | 3 (PARAMS 1 + INFO 2) |
| params | every pod enumerated for each node param id: the app's `EnumFormat` objects (the same list serves node and port, `stream.c` `get_param_index`, `add_param`), plus `Props`/`PropInfo` if any. With only EnumFormat supplied: the EnumFormat objects |
| info `max_input_ports` / `max_output_ports` | 1 / 0 (input stream) (`stream.c` `pw_stream_connect`) |
| info `change_mask` | 7 (FLAGS, PROPS, PARAMS) |
| info `flags` | `RT` (1); plus `ASYNC` (64) when `node.async` is true, so 65 |
| info props | the dict of 4.1 |
| info params | exactly 4 entries in this order: `(Id 1 PropInfo, 0)`, `(Id 2 Props, WRITE=4)`, `(Id 3 EnumFormat, READ=2 if the app supplied EnumFormat else 0)`, `(Id 4 Format, WRITE=4)`. The SERIAL bit may be toggled in a later update |

`PortUpdate` content (`add_port_update`; port 0, direction input = 0):

| Field | Value |
|---|---|
| direction, port_id | 0, 0 |
| outer `change_mask` | 3 (PARAMS 1 + INFO 2) |
| params | every pod enumerated for each id in the port's param list, in list order (below). Each PortUpdate with the PARAMS bit replaces the server's whole param list for that port (`client-node.c` `update_params`), so later updates must resend all of them |
| info `change_mask` | 15 (FLAGS, RATE, PROPS, PARAMS) (`add_port_update`) |
| info `flags` | 0 (`port_info.flags = 0`; CAN_ALLOC_BUFFERS only with flag ALLOC_BUFFERS; DYNAMIC_DATA cleared) |
| info rate | `0` / `1` |
| info props | the port properties; `port.group = stream.0` is the only one set by stream.c, `impl-port.c` may add a few (unverified list) |
| info params | 7 entries in this order (`stream.c` `PORT_*` indexes, lines 100-107): `(3 EnumFormat, 2 if supplied)`, `(6 Meta, 2)`, `(7 IO, 2)`, `(4 Format, 4)`, `(5 Buffers, 2 once supplied else 0)`, `(15 Latency, 4)`, `(17 Tag, 4)` |

The params, per id, in list order:

| Id | Pods sent | Source |
|---|---|---|
| 3 EnumFormat | the app's EnumFormat objects, each an Object type `0x40003` id `3` (see 5.1) | `stream.c` `enum_params` |
| 6 Meta | the locked Busy meta object (`SPA_PARAM_META_type = Id 7 Busy`, `SPA_PARAM_META_size = Int 8`) added by `add_params` (stream.c:1787), then the app's Meta objects | `add_params` |
| 7 IO | two objects from the port mixer, `mix_port_enum_params` (`impl-port.c:130-182`): `{id = Id 1 (Buffers), size = Int 8}` then `{id = Id 10 (AsyncBuffers), size = Int 8}`. `ParamIO` object type `0x40006`, object id `7` | `impl-port.c` |
| 4 Format | only after a format was set | |
| 5 Buffers | the app's Buffers object, sent after the Format arrives (video-play.c builds it in `on_stream_param_changed` and calls `pw_stream_update_params`) | `video-play.c:371-378` |

So the real flow for Buffers: first PortUpdate has EnumFormat, Meta, IO only. After the server's
`PortSetParam(Format)` arrives, the application builds Buffers (and extra Meta) and `pw_stream_update_params`
triggers a second PortUpdate (`stream.c:2189`, `emit_port_info`) that resends the full param list including
Format and Buffers.

### 4.3 Server events and what the client must do

Order the server produces them (link negotiation in `impl-link.c` `do_negotiate`, `do_allocation`, then
`link activate`): the order below is what the source gives; a client must still dispatch by opcode.

| Step | Event | Client action |
|---|---|---|
| 1 | `Core.BoundProps(id = 2, global_id, props)` (`pw_resource_set_bound_id`, `resource.c:192`) | record the node global id. `pw_stream` goes to state PAUSED here (`stream.c:1144` `proxy_bound_props`) |
| 2 | `ClientNode.Transport` (`client-node.c` `pw_impl_client_node_registered`, line 1322): `read_fd` = server's `node->source.fd` (the eventfd the client waits on), `write_fd` = the server's data-source eventfd, `mem_id`/`offset`/`size` = the activation block of this node, `size = sizeof(struct pw_node_activation) = 2312` | map the activation memory read/write; write `activation.client_version = 1` (`remote-node.c:218`); keep `read_fd` to wait on and `write_fd` to signal (`rtwritefd`, only written when the profiler flag is set, `node_rt_complete`); then SetActive(true) (4.2) |
| 3 | `Core.AddMem` events | map or record each memfd by id |
| 4 | `ClientNode.PortSetMixInfo(dir, port, mix_id, peer_id, props)` | create the mix |
| 5 | `ClientNode.PortSetParam(dir 0, port 0, Id 4 Format, flags, Format object)` | parse the Format (5.1). Respond with the second PortUpdate (4.2). The server then sends `Core.Ping` for the node's `sync` (`client-node.c:485` `impl_node_sync` calls `pw_resource_ping(resource, seq)`): answer with `Core.Pong` echoing id and seq or the link never moves on |
| 6 | `ClientNode.PortSetParam(..., Id 15 Latency, ...)` and Tag (17) | stream.c stores them; a Go client may ignore them (and may choose to omit Latency and Tag from the info params) |
| 7 | `ClientNode.PortUseBuffers(dir 0, port 0, mix_id, flags, n, ...)` | map the buffer memory (4.4) |
| 8 | `ClientNode.PortSetIO(dir 0, port 0, mix_id, io_id, mem_id, offset, size)` with `io_id = 1` (Buffers, 8 bytes) or `10` (AsyncBuffers, 16 bytes) | map the area; `impl-link.c` `link_activate` (line ~627) chooses AsyncBuffers when `impl->async`, which needs both nodes async-capable and both ports flagged ASYNC (`impl-link.c:1326`) |
| 9 | `ClientNode.SetIO(io_id, mem_id, offset, size)` | io_id 3 Clock (the node's own clock inside its activation) and 7 Position (the driver's position, inside the driver's activation block) (`impl-node.c:799-835` `pw_impl_node_set_io`; `remote-node.c` `client_node_set_io`). Not needed for frame ingestion; ignore unknown ids but do not fail |
| 10 | `ClientNode.SetActivation(node_id, signal_fd, mem_id, offset, size)` for each peer (driver and others) and for this node itself (`client-node.c` `node_peer_added`, line ~1271; `remote-node.c:797`) | map each peer's activation. Needed only to trigger peers (4.5). `mem_id = 0xffffffff` removes the peer |
| 11 | `ClientNode.Command(Object 0x30002 id 2)` = Start (`SPA_NODE_COMMAND_Start`) | in stream.c: if the stream is PAUSED, `io->status = SPA_STATUS_NEED_DATA` for an input stream (`impl_send_command`, `stream.c:645`); the node goes RUNNING (`remote-node.c` `client_node_command` to `pw_impl_node_set_state(RUNNING)`) and the stream is STREAMING (`stream.c` `node_state_changed`) |
| later | `Command` Pause (id 1) / Suspend (id 0) | stop processing; stream goes to PAUSED. `remote-node.c` maps Pause to IDLE, Suspend to SUSPENDED, RequestProcess (10) is forwarded |
| later | `PortSetParam(Format, None)` and `PortUseBuffers(n_buffers 0)` and `PortSetIO(mem_id 0xffffffff)` and `SetActivation(mem_id 0xffffffff)` | teardown: unmap everything |

Errors the client reports go as `Core.Error(proxy_id, recv_seq, -errno, message)` (2.7).

### 4.4 PortUseBuffers memory layout

Wire-to-memory translation is `remote-node.c` `client_node_port_use_buffers` (line 585) on the client and
`client-node.c` `do_port_use_buffers` on the server.

Per buffer the message gives `(mem_id, offset, size)`, a list of metas `(type, size)` and a list of datas
`(type, data_id, flags, mapoffset, maxsize)`.

1. Map the memory block `mem_id` (it was announced by AddMem; its fd is a memfd) for `size` bytes starting at
   `offset`. mmap offsets must be page aligned: map from `offset` rounded down to the page size and add the
   remainder (`stream.c` `map_data` uses `pw_map_range_init` for the same reason). Call the mapped start `base`.
2. Metas start at `base + 0`, in message order. Meta `j` is at `base + sum_{i<j} roundup8(size_i)`.
   `meta.data` points there and `meta.size = size_j` (`remote-node.c` loop `m->data = ptr + offset; offset += ROUND_UP_N(m->size, 8)`).
3. Chunks follow all metas: chunk `j` is at `base + roundup8-sum-of-meta-sizes + 16 * j`
   (`d->chunk = ptr + offset + sizeof(struct spa_chunk) * j`). `struct spa_chunk` is 16 bytes:
   `offset u32`, `size u32`, `stride i32`, `flags i32` (`spa/buffer/buffer.h`).
4. Data `j`:
   - `data_type == 4 (MemId)`: `data_id` is a pool mem id (an AddMem block, a memfd or a dmabuf). Its real
     type is the block's type from AddMem. Map `maxsize` bytes at file offset `mapoffset` (page aligned).
     `chunk.offset` and `chunk.size` are relative to that mapping.
   - `data_type == 1 (MemPtr)`: `data_id` is a byte offset inside the buffer block, relative to `base`;
     the pixels are at `base + data_id`, `maxsize` bytes (`d->data = ptr + offs`). The server verifies the
     pointer lies in the same block (`client-node.c` `do_port_use_buffers`).
   - `data_type` MemFd (2) or DmaBuf (3) appear only in the `PortBuffers` client method; the server converts
     them to MemId before sending.
5. `data_flags`: READABLE `1<<0`, WRITABLE `1<<1`, DYNAMIC `1<<2`, MAPPABLE `1<<3` (`buffer.h`).
6. Buffer id = index in the list (`stream.c` `impl_port_use_buffers`: `b->id = i`). `io.buffer_id` refers to it.
7. Validation the real server applies: `mem_id` known, `offset + size` inside the block. A client must
   reject a buffer whose metas, chunks or MemPtr data run past `size`, and a MemId whose `mapoffset + maxsize`
   runs past the file size (use `fstat`), because a hostile or buggy peer controls these numbers.
8. A new PortUseBuffers replaces all buffers of that mix; PortSetParam(Format) also invalidates them
   (`remote-node.c` `client_node_port_set_param` clears buffers on Format).

### 4.5 Activation protocol

`struct pw_node_activation` (`src/pipewire/private.h:582`), x86-64 layout checked with gcc. Size 2312.
Everything is naturally aligned; `unsigned int` bitfields share the u32 at offset 4.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `status` | one of the status values below; accessed atomically (CAS) |
| 4 | 4 | bitfields `version`, `pending_sync`, `pending_new_pos` | |
| 8 | 12 | `state[0]` = `{int status, int32 required, int32 pending}` | `status` at 8, `required` at 12, `pending` at 16 |
| 20 | 12 | `state[1]` | second state, unused here |
| 32 | 8 | `signal_time` | ns, `CLOCK_MONOTONIC`, written by the signaller |
| 40 | 8 | `awake_time` | written by the node when it starts |
| 48 | 8 | `finish_time` | written when it finishes |
| 56 | 8 | `prev_signal_time` | |
| 64 | 184 | `reposition` (`struct spa_io_segment`) | |
| 248 | 184 | `segment` | |
| 432 | 64 | `segment_owner[16]` | |
| 496 | 8 | `prev_awake_time` | |
| 504 | 8 | `prev_finish_time` | |
| 512 | 28 | `padding[7]` (must be 0) | |
| 540 | 4 | `client_version` | the client writes `1` at transport time (`remote-node.c:218`, `PW_VERSION_NODE_ACTIVATION = 1`, `private.h:564`) |
| 544 | 4 | `server_version` | written by the server, `1` in 1.2.7 (`impl-node.c:1705`) |
| 548 | 4 | `active_driver_id` | |
| 552 | 4 | `driver_id` | |
| 556 | 4 | `flags` | bit 0 = profiler running |
| 560 | 1688 | `position` (`struct spa_io_position`) | `position.clock` at 560 (size 160): `nsec` at 632, `position` at 648, `duration` at 656, `cycle` at 708; `position.state` at 768 |
| 2248 | 8 | `sync_timeout` | |
| 2256 | 8 | `sync_left` | |
| 2264 | 12 | `cpu_load[3]` | |
| 2276 | 4 | `xrun_count` | |
| 2280 | 8 | `xrun_time` | |
| 2288 | 8 | `xrun_delay` | |
| 2296 | 8 | `max_delay` | |
| 2304 | 4 | `command` | 0 none, 1 start, 2 stop; read by the driver side |
| 2308 | 4 | `reposition_owner` | |

Activation status values (`private.h:583-587`): NOT_TRIGGERED 0, TRIGGERED 1, AWAKE 2, FINISHED 3, INACTIVE 4.
Documented transitions (`private.h` comment above the struct):

- INACTIVE to FINISHED: the node is added to the loop and can be scheduled.
- any to INACTIVE: the node cannot be scheduled any more.
- not INACTIVE to NOT_TRIGGERED: the driver prepares the node for a cycle.
- NOT_TRIGGERED to TRIGGERED: the eventfd is written.
- TRIGGERED to AWAKE: the eventfd is read, the node starts processing.
- AWAKE to FINISHED: the node finished and triggered its peers.

Status values for `spa_io_buffers.status` and for the node's process result (`spa/node/io.h`): OK 0,
NEED_DATA `1<<0`, HAVE_DATA `1<<1`, STOPPED `1<<2`, DRAINED `1<<3`; negative errno values are errors.

`struct spa_io_buffers` is 8 bytes: `int32 status` at 0, `uint32 buffer_id` at 4 (`0xffffffff` = none).
`struct spa_io_async_buffers` is two of them (16 bytes).

Setup the client performs when the node becomes active (`impl-node.c` `do_node_prepare`, line 174, runs
on the client for a locally created node): it drains the eventfd of stale counts and, because the node is
not `remote` on the client, stores status FINISHED (`SPA_ATOMIC_STORE(activation->status, FINISHED)`).
A Go client must do the same: after mapping the activation write `client_version = 1`, read and discard
whatever is in `read_fd`, and set `status = 3` (FINISHED) when it sends SetActive(true). The server leaves the
status alone because `client_version >= 1` (`do_node_prepare`: `if (!remote || client_version < 1) store FINISHED`).
On deactivate the client exchanges INACTIVE (4) into the status (`do_node_unprepare`, line ~229); if the old
value was NOT_TRIGGERED, TRIGGERED or AWAKE (`PW_NODE_ACTIVATION_PENDING_TRIGGER`, status <= AWAKE) it also
triggers its targets, so the driver's cycle can finish. The Go client does the same for a synchronous node.

Wake up and process cycle, as run by `node_on_fd_events` (`impl-node.c:1544`) and `process_node`
(`impl-node.c:1464`):

1. Wait until `read_fd` is readable (`poll`/`epoll`). It is an eventfd: a `read(2)` returns an 8-byte native
   u64 counter and resets it. A counter above 1 means missed wake-ups (logged as xrun stats only). The
   fd was created non-blocking by the server and SCM_RIGHTS shares the open file description, so a read
   with nothing pending returns `EAGAIN`.
2. `CAS(activation.status, TRIGGERED -> AWAKE)`. If the CAS fails, do nothing this cycle.
3. Write `awake_time` (monotonic ns). Statistics only.
4. Process (stream.c `impl_node_process_input`, line 991): look at the `spa_io_buffers` area:
   - if `status == HAVE_DATA` and `buffer_id < n_buffers`: that buffer holds a new frame;
   - hand the frame to the application;
   - recycle: stream.c sets the local io to `buffer_id = <returned id or 0xffffffff>`, `status = NEED_DATA`.
5. Store the result in `activation.state[0].status` (offset 8). stream.c returns
   `NEED_DATA | HAVE_DATA` = 3 for an input stream.
6. `CAS(activation.status, AWAKE -> FINISHED)`; write `finish_time`.
7. If the node is not async (or `server_version < 1`) and the CAS in step 6 succeeded (`was_awake`; when the
   server changed the status during the cycle nobody is triggered): trigger each peer target (`trigger_targets`):
   for each activation mapped from SetActivation, atomically decrement `state[0].pending` (offset 16 in that
   activation); if the result is 0 and `CAS(peer.status, NOT_TRIGGERED -> TRIGGERED)` succeeds, write
   `signal_time` and `write(signal_fd, 1 as u64)` (`private.h:656` `trigger_target_v1`).
   If the node is async and `server_version >= 1` do nothing: the driver resumes async nodes itself
   (`impl-node.c:1521`: `if ((!this->async || a->server_version < 1) && was_awake) trigger_targets`;
   `activate_target` does not count async nodes in `required`/`pending`, `impl-node.c:114-128`). Never trigger
   peers from an async node: that would corrupt the driver's pending counter.

How the buffer is handed back, in detail. The shared io area (`PortSetIO`) is read by the stream through a
copy: for an input port the mixer `schedule_mix_input` (`impl-port.c:300`) copies the shared
`spa_io_buffers` into the port's local io and then writes `shared.status = NEED_DATA` immediately, leaving
`shared.buffer_id` as it was (`*io = *mix->io[cycle]; mix->io[cycle]->status = SPA_STATUS_NEED_DATA`). The
stream's own writes go to the local copy and are not copied back for an input port. So on the wire the
consumer returns a buffer by setting the shared `status` to `NEED_DATA` (value 1) after it has finished
reading it, and the producer, which still sees its own `buffer_id`, recycles that buffer when it next
runs and sees `NEED_DATA` (`spa/node/io.h` doc: "If status is HAVE_DATA, the host should consume the buffer in
buffer_id and set the state to NEED_DATA when new data is requested"). A Go client that reads the shared
area directly should: read `status`; if `HAVE_DATA`, copy the frame out, then store `status = NEED_DATA`.
Copy before storing NEED_DATA, because the producer may reuse the buffer right after.
With AsyncBuffers the area holds two `spa_io_buffers` and the reader uses index `position.clock.cycle & 1`
(`impl-port.c:300` uses `this->node->rt.position->clock.cycle & 1`; `io.h` `spa_io_async_buffers` doc), where
`position` is the driver's position from SetIO(7).

Busy meta: if a buffer has a `Busy` meta (type 7, `struct spa_meta_busy {u32 flags; u32 count}`, 8 bytes),
stream.c increments `count` atomically when a buffer is dequeued and decrements it on `pw_stream_queue_buffer`
for input streams (`stream.c:991` push path, `pw_stream_queue_buffer` line 2442). Do the same around the copy.

Start: `Command Start` sets `io.status = NEED_DATA` on the stream's io when the stream is PAUSED
(`impl_send_command`, stream.c:645-672). For a client that reads the shared area, writing `status = NEED_DATA`
into the Buffers io area on Start matches that.

How the stream stops (`stream.c:1619` `stream_disconnect`): `SetActive(false)` (activation status goes to
INACTIVE), `Core.Destroy(Int proxy_id)` (opcode 7) for the ClientNode proxy, then close the socket
(`pw_core_disconnect`). The server then removes the node and sends `RemoveId`. On a server-initiated stop the
client sees Command Pause/Suspend and the teardown events in 4.3, or `Core.Error` on id 0 with `res = -EPIPE`
(`stream.c:1404` `on_core_error` treats that as unconnected) or just a closed socket.

## 5. Video format negotiation, buffers and metadata

Files: `spa/include/spa/param/{param,format,buffers}.h`, `spa/param/video/{raw,format-utils}.h`,
`spa/buffer/{buffer,meta}.h`, `spa/node/io.h`, `src/examples/video-play.c`, `src/examples/sdl.h`.

### 5.1 Ids

`SPA_PARAM_*` (`param.h` `enum spa_param_type`): Invalid 0, PropInfo 1, Props 2, EnumFormat 3, Format 4,
Buffers 5, Meta 6, IO 7, EnumProfile 8, Profile 9, EnumPortConfig 10, PortConfig 11, EnumRoute 12, Route 13,
Control 14, Latency 15, ProcessLatency 16, Tag 17.

Format object keys (`format.h` `enum spa_format`; the object type is `0x40003`):

| Key | Id | Value type |
|---|---|---|
| mediaType | 1 | Id: `SPA_MEDIA_TYPE_video` = 2 (unknown 0, audio 1, video 2, image 3, binary 4, stream 5, application 6) |
| mediaSubtype | 2 | Id: `SPA_MEDIA_SUBTYPE_raw` = 1 (unknown 0, raw 1, dsp 2, iec958 3, dsd 4) |
| VIDEO_format | `0x20001` | Id, `enum spa_video_format` |
| VIDEO_modifier | `0x20002` | Long; DMA-BUF only, omit for memfd |
| VIDEO_size | `0x20003` | Rectangle |
| VIDEO_framerate | `0x20004` | Fraction (0/1 = variable) |
| VIDEO_maxFramerate | `0x20005` | Fraction |
| VIDEO_views | `0x20006` | Int |
| VIDEO_interlaceMode | `0x20007` | Id (progressive 0) |
| VIDEO_pixelAspectRatio | `0x20008` | Rectangle |
| VIDEO_multiviewMode | `0x20009` | Id |
| VIDEO_multiviewFlags | `0x2000a` | Id |
| VIDEO_chromaSite | `0x2000b` | Id |
| VIDEO_colorRange | `0x2000c` | Id |
| VIDEO_colorMatrix | `0x2000d` | Id |
| VIDEO_transferFunction | `0x2000e` | Id |
| VIDEO_colorPrimaries | `0x2000f` | Id |

Video formats we care about (`video/raw.h` `enum spa_video_format`, counted from `UNKNOWN = 0`):

| Id | Name | Byte order in memory (little endian 32-bit pixel) |
|---|---|---|
| 7 | RGBx | R, G, B, x |
| 8 | BGRx | B, G, R, x |
| 11 | RGBA | R, G, B, A |
| 12 | BGRA | B, G, R, A |

(Neighbours for reference: 2 I420, 3 YV12, 4 YUY2, 5 UYVY, 6 AYUV, 9 xRGB, 10 xBGR, 13 ARGB, 14 ABGR, 15 RGB,
16 BGR, 23 NV12.) The names list components in big-endian order in the GStreamer manner (`raw.h` comment),
so `BGRx` means the byte at the lowest address is B. This is consistent with the byte order the table gives; it
matches how `video-play.c` maps formats to SDL pixel formats, but the byte order column is derived from the
naming convention comment, not from a captured frame (see section 7).

EnumFormat as an application builds it for a raw video input (pattern from `sdl.h` `sdl_build_formats`,
lines 129-175): `Object(0x40003, id 3)` with props in this order: mediaType = Id 2, mediaSubtype = Id 1,
VIDEO_format = `Choice Enum Id {default, default, alt...}`, VIDEO_size = `Choice Range Rectangle {default, min, max}`,
VIDEO_framerate = `Choice Range Fraction {default, min, max}`. The enum repeats its default as the first
alternative (sdl.h writes the first id twice).

Fixation: the server takes the default of every Choice when it builds the Format it sends back
(`impl-link.c` `do_negotiate`, `spa_pod_fixate`). So the first value of each Choice is what you will get if
the producer accepts it. The producer's own EnumFormat decides what survives the intersection, so give wide
ranges (size min `1x1`, max `16384x16384`, framerate min `0/1`).

The Format sent to the client in PortSetParam is `Object(0x40003, id 4)` with plain values (no Choices) for
VIDEO_format, VIDEO_size, VIDEO_framerate (and possibly others such as modifier for DMA-BUF, which
we avoid by never offering DmaBuf). Parse by key, ignore unknown keys, and treat each value as a possible
Choice (1.4).

### 5.2 Buffers param (object type `0x40004`, object id 5), keys from `param/buffers.h`

| Key | Id | Type | Notes |
|---|---|---|---|
| buffers | 1 | Int, usually Choice Range `{default, min, max}` | video-play: `{8, 2, MAX_BUFFERS}` |
| blocks | 2 | Int | data blocks per buffer, 1 for packed RGB |
| size | 3 | Int | bytes per block |
| stride | 4 | Int | bytes per row |
| align | 5 | Int | |
| dataType | 6 | Int, `Choice Flags` mask of `1 << spa_data_type` | |
| metaType | 7 | Int mask of `1 << spa_meta_type` | |

Data type ids (`buffer.h` `enum spa_data_type`): Invalid 0, MemPtr 1, MemFd 2, DmaBuf 3, MemId 4, SyncObj 5.
As bitmask values in `dataType` (`1 << id`): **MemPtr = 2, MemFd = 4, DmaBuf = 8**. A client that accepts
shared memory only offers `MemFd | MemPtr = 6` (`Choice Flags Int {6}`) and never bit 8.
`stream.c` `fix_datatype` (line 196) adds the MemFd bit when MemPtr is set and the stream has the
`MAP_BUFFERS` flag, because the server shares remote buffers through memfds (`impl-link.c:537-541`:
`PW_BUFFERS_FLAG_SHARED_MEM` when either node is remote).

Meta param (object type `0x40005`, id 6): `SPA_PARAM_META_type` key 1 = Id (`spa_meta_type`), `SPA_PARAM_META_size`
key 2 = Int, optionally a Choice Range (`video-play.c:382-396`). IO param (object type `0x40006`, id 7):
`SPA_PARAM_IO_id` key 1 = Id (`spa_io_type`), `SPA_PARAM_IO_size` key 2 = Int.

IO type ids (`io.h` `enum spa_io_type`): Invalid 0, Buffers 1, Range 2, Clock 3, Latency 4, Control 5, Notify 6,
Position 7, RateMatch 8, Memory 9, AsyncBuffers 10.

### 5.3 Chunk fields

`struct spa_chunk` (`buffer.h`): `offset u32` "offset of valid data, taken modulo the data maxsize", `size u32`
"size of valid data, clamped to maxsize", `stride i32` "stride of valid data", `flags i32`
(CORRUPTED `1<<0`, EMPTY `1<<1`). Reading a frame (consistent with `video-play.c:196-221`):

```text
start  = chunk.offset % maxsize
stride = chunk.stride; if stride == 0 { stride = chunk.size / height }
row y  starts at data + start + y * stride, holds width * 4 bytes of pixels for the four formats above
reject if chunk.size > maxsize, or start + (height-1)*stride + width*4 > maxsize
```

If `chunk.flags & CORRUPTED` skip the frame. If `EMPTY` the content is neutral (black).

### 5.4 Meta types and layouts (`buffer/meta.h` `enum spa_meta_type`)

| Id | Name | Layout |
|---|---|---|
| 1 | Header | `struct spa_meta_header` 32 bytes: `flags u32`, `offset u32`, `pts i64`, `dts_offset i64`, `seq u64`; flags DISCONT `1<<0`, CORRUPTED `1<<1`, MARKER `1<<2`, HEADER `1<<3`, GAP `1<<4`, DELTA_UNIT `1<<5` |
| 2 | VideoCrop | one `struct spa_meta_region`: `x i32`, `y i32`, `width u32`, `height u32` (16 bytes; `defs.h` `spa_region` = `spa_point` then `spa_rectangle`). Valid when `width != 0 && height != 0` (`spa_meta_region_is_valid`). It is the visible rectangle inside the buffer. The meta `size` requested by video-play is `sizeof(struct spa_meta_region)` = 16 |
| 3 | VideoDamage | an array of `spa_meta_region` (16 bytes each). The list ends at the first entry that is not valid (zero width or height) or at the end of the meta (`meta.h` comment, `spa_meta_for_each`). Regions are in buffer coordinates |
| 4 | Bitmap | `struct spa_meta_bitmap`: `format u32`, `size {u32,u32}`, `stride i32`, `offset u32` (offset of pixel data from the start of this struct; 0 means none) |
| 5 | Cursor | `struct spa_meta_cursor`: `id u32`, `flags u32`, `position {i32,i32}`, `hotspot {i32,i32}`, `bitmap_offset u32` (28 bytes) |
| 6 | Control | pod sequence |
| 7 | Busy | `struct spa_meta_busy`: `flags u32`, `count u32` |
| 8 | VideoTransform | `transform u32`: None 0, 90 1, 180 2, 270 3, Flipped 4, Flipped90 5, Flipped180 6, Flipped270 7 |
| 9 | SyncTimeline | `flags u32, padding u32, acquire_point u64, release_point u64` |

The data-size of a meta in PortUseBuffers is the `meta_size` field; check `meta_size >= sizeof(layout)`
before reading (`spa_buffer_find_meta_data` does this check, `buffer.h`). With the loose-ends scope the
client asks for VideoCrop and Busy; VideoDamage is not requested because the frame copy does not use it; cursor
metadata is out of scope. A chunk size above the data block's maxsize is clamped, as `spa_chunk` says.

## 6. Checklist of easy-to-miss points

1. Answer every `Core.Ping` with `Core.Pong` carrying the same id and seq. The server uses Ping as the
   completion of `PortSetParam`/`PortUseBuffers` (`client-node.c:485`).
2. Keep one fd queue per connection; pair fds to messages by `n_fds` only after the whole message arrived.
3. A message payload can be longer than its Struct (footer). Parse the first pod, ignore the rest.
4. AddMem block ids come from the server's pool; use the id in the event, map lazily.
5. Each PortUpdate with the PARAMS bit replaces all of the port's params on the server.
6. Send Buffers only after the Format arrived (second PortUpdate), as `pw_stream` does through `param_changed`.
7. Write `client_version = 1` and status FINISHED (3) into the activation before SetActive(true).
8. Declare `node.async=true` and the ASYNC node flag if you intend never to trigger peers. If you do not,
   you must run the trigger step of 4.5.
9. Handle both `PortSetIO` ids 1 and 10; with 10 index by `clock.cycle & 1`.
10. Do not rely on the order of server events; dispatch by (proxy id, opcode).
11. Bound every count and size from the wire with the limits in 2.7 before allocating.

## 7. Not found, unverified, or derived

- No byte vectors in PipeWire's tests (see section 0). All byte examples were produced by a separate
  encoder written from the builder source; nothing was compared with bytes captured from a real daemon.
- Exact set of port properties that `impl-port.c` adds to the PortUpdate props: only `port.group` is
  certain. The server accepted a client that sends just that in the source reading, but this was not run.
- Exact `param_flags` the real stream sends in the node and port info lists at the moment of the first
  messages (the SERIAL bit toggles when `user` counters change, `stream.c` `emit_node_info`). The READ and
  WRITE bits given in 4.2 are from the `SPA_PARAM_INFO(...)` initialisers at `pw_stream_connect`.
- The order of the first server messages after Hello (Core.Info, Client.Info, BoundId/BoundProps for id 1)
  is read from `core_hello` and `global_bind`, not observed.
- Whether the portal's restricted PipeWire connection (an fd from `OpenPipeWireRemote`) accepts a
  `CreateObject("client-node")` and links the new node to the portal node. `module-protocol-native/portal-screencast.c`
  and `security-context.c` exist in the tree and were not read. The link is created by the session manager
  (WirePlumber policy) from `node.target`/`target.object` and `node.autoconnect`; that policy code is outside
  the PipeWire files read here. This is the biggest open risk.
- Whether a server will pick `AsyncBuffers` for this node. `impl-link.c:1326` requires both ports flagged ASYNC
  (derived from IO params the port advertises, `impl-port.c` `check_param_io`). Handle both ids.
- Meaning of `SetIO` for Clock and Position for a pure consumer. Source shows they only feed timing. Not needed
  for frame ingestion, and not exercised.
- Pixel byte order for BGRx and friends is from the naming convention comment in `video/raw.h`, not from a
  captured frame.
- Real producers' choice of `data_type` (MemFd versus MemPtr) and `mapoffset` alignment was not checked
  against a compositor. Reject any buffer whose mapping parameters do not validate (4.4 item 7).
- `PW_MEMBLOCK_FLAG_*` values in AddMem `flags` (`mem.h`: READABLE 1, WRITABLE 2, SEAL 4, MAP 8,
  DONT_CLOSE 16, DONT_NOTIFY 32, UNMAPPABLE 64) were read from `mem.h` but how the exporter fills them in
  AddMem was not traced beyond `block->flags`.
- Registry methods, Node/Port/Device/Link/Module/Factory interfaces were not documented: the client does
  not use them.
