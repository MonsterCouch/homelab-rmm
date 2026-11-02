# Loose ends after Phase 4 (design, 2026-10-25)

Two items left open by the roadmap phases, built together.

## 1. The update source reaches the console

`internal/server/update.go` discards the `agent.update` reply (`s.hub.Request(..., nil)` for a single device, and the fleet batches only count answers). The agent already knows where the bytes came from (`selfUpdateSource`: `origin`, `cache <leader> over h3|https`, or `origin (the cache failed: ...)`).

- The agent's reply to `agent.update` becomes `protocol.AgentUpdateResult{source, bytes, resumed_chunks, version}` (today it is whatever the dispatcher sends; keep it backward compatible: an old agent's empty reply is treated as `source: ""`).
- The server stores the reply on the `agent_events` row it writes for the update (kind `update`), and on the fleet update batch result per device (the structure the console's fleet-update summary already reads). The audit row for the update gets `source` in its details.
- Console: the device page's update result (where the operator started the update) shows "Downloaded from the subnet cache (leader X over HTTP/3)" or "Downloaded from the server" and, when the cache failed, the reason; the fleet update summary counts devices by source. `GET /api/agents/{id}` is unchanged.
- Tests: server (reply recorded, old agent without a reply still works, fleet batch per-device source), console typecheck.

## 2. PipeWire frame ingestion without CGO

`capture_pipewire_linux.go` negotiates the ScreenCast portal and gets a PipeWire node id and a connected fd, then fails with `errPipeWireNoIngest`. This builds the missing client as pure Go, so Wayland sessions stream real frames.

### Packages

- `internal/agent/desktop/pipewire/pod`: the SPA POD binary format (Bool, Id, Int, Long, Float, Double, String, Bytes, Rectangle, Fraction, Bitmap, Array, Struct, Object with property keys/flags, Sequence, Pointer, Fd, Choice with None/Range/Step/Enum/Flags). Encoder and decoder with 8-byte alignment exactly as `spa/pod/*.h` lays it out. No build tag: it is bytes only and its tests run everywhere, including the vectors taken from PipeWire's own test files.
- `internal/agent/desktop/pipewire/proto`: the native protocol (`module-protocol-native`): the 16-byte message header (`id`, `opcode<<24|size`, `seq`, `n_fds`), footers as the current version sends them, the proxy id space (core 0, client 1, then `BoundId`), and typed messages for the objects this client needs: Core (Hello, Sync, Pong, Error, GetRegistry, CreateObject, Destroy; Info, Done, Ping, Error, RemoveId, BoundId, AddMem, RemoveMem, BoundProps), Client (UpdateProperties; Info, Permissions) and ClientNode (GetNode, Update, PortUpdate, SetActive, Event, PortBuffers; Transport, SetParam, SetIO, Event, Command, AddPort, RemovePort, PortSetParam, PortUseBuffers, PortSetIO, SetActivation, PortSetMixInfo). Opcodes, interface names and versions are taken from `src/pipewire/core.h`, `client.h`, `src/pipewire/extensions/client-node.h` and `protocol-native.c` of the PipeWire release on the development machine's target distributions (PipeWire 1.0 and later; the protocol version is 3).
  - The transport is an interface: `send(header, payload, fds)` / `recv() (header, payload, fds)`. The Linux implementation is a Unix socket with `SCM_RIGHTS`; the test implementation is an in-memory pair that carries fds as integers. Shared memory and eventfds sit behind the same kind of seam (`mem` for memfd mappings, `signal` for eventfd), so the whole state machine is tested on Windows against a fake server.
- `internal/agent/desktop/pipewire/stream`: a video input stream as the client-node object: Hello and Sync with the core, `UpdateProperties` with `media.type=Video`, `media.category=Capture`, `media.role=Screen`, `node.name`, then `CreateObject("client-node")` with `node.target`/`target.object` set to the portal's node id, `Update` (node info: one input port, no output), `PortUpdate` with `EnumFormat` (video/raw; BGRx, BGRA, RGBx, RGBA; any size and framerate) and `Buffers` params (data type MemFd or MemPtr only, never DmaBuf, so compositors fall back to shared memory), `SetActive(true)`. Then it serves the server's events: `AddMem` (memfd by fd → mapping), `Transport` (activation area and the two eventfds), `PortSetParam(Format)` (records the chosen format, size and stride), `PortUseBuffers` (buffer metadata and data chunks inside mapped memory), `PortSetIO(io.Buffers)`, `SetIO`, `Command(Start|Pause|Suspend)`. The process loop waits on the activation eventfd, reads `io.Buffers.buffer_id` and status, copies the frame out of the buffer's chunk honouring `chunk.offset`, `chunk.stride` and the `VideoCrop`/`VideoDamage` metadata when present, sets status `NEED_DATA`, returns the buffer, and signals the driver as `pw_stream` does for a client-node (the activation protocol from `src/pipewire/impl-node.c` and `module-client-node/client-node.c`). Frames come out as `*image.RGBA` in the stream's size.
  - Errors: a Core Error event, a closed socket, a format the client did not offer, or a buffer referencing an unknown mem id end the stream with a sentence; the capturer then falls back exactly as today. Nothing synthetic is ever returned.
- `capture_pipewire_linux.go`: `pipewireIngestImplemented = true`; `capture(m)` reads the latest frame from the stream for the monitor's node (one stream per node, started lazily on first capture, stopped on `Close`); `newWaylandCapturer` starts the portal session by default (the restore token makes the second start silent) unless `RMM_WAYLAND_PORTAL=0`, and falls back to the screenshot path when the portal or the stream fails. The file comment is rewritten to say what is implemented and what is not verified.

### What cannot be verified here

The development machine is Windows without WSL or Docker, so no PipeWire daemon or compositor can run. The client is verified three ways: byte vectors from PipeWire's own tests for the POD codec, a fake server that speaks the protocol as the source describes it for the stream state machine, and a review that reads PipeWire's source (the files named above, fetched from gitlab.freedesktop.org at a 1.x tag) and checks every opcode, type id, struct layout and the activation sequence against the implementation. The first run against a real compositor (GNOME or KDE on Wayland, `RMM_DEBUG=1`) is the actual check, and the docs say so. The fallback keeps today's behaviour when anything fails.

### Out of scope

DMA-BUF buffers, cursor metadata as a separate layer (the cursor is composited by the compositor when `cursor_mode=1`, which the portal negotiation already asks for), audio, and the X11 path, which is unchanged.

## Status (implemented 2026-10-25)

Both items are built. The update source was not rendered in a browser. The PipeWire client has now run against a real compositor: on 2026-10-31 it streamed frames, with mouse and keyboard input, from GNOME 50 on Wayland (mutter) with PipeWire 1.6.2 and xdg-desktop-portal-gnome 50, on Ubuntu 26.04.1 in a Hyper-V VM, and the console showed the live desktop. The sections below were written before that run; the lists at the end say what it settled.

### 1. Update source

Built as designed: `protocol.AgentUpdateResult`, `selfUpdateResult` (with `selfUpdateSource` kept as a wrapper), the `agent.update` handler always replying with the result, server recording on the `update` event and audit rows, `results` and `by_source` on `update-batch`, and the console sentence and fleet toast.

Deviations:
- **Late replies are recorded.** The single-device and batch handlers still stop waiting after `fleetUpdateReplyWindow` (20 seconds) and answer "installing", but the request stays open for `lateUpdateWindow` and the event is written when the device answers. The fleet summary's `by_source` still counts only answers that came inside the window. Event inserts are serialised by one mutex.
- **No single-device update button.** `api.dispatchAgentUpdate` exists in the console but nothing calls it, so there is no device-page result to change. The source is shown under each update event on the device's activity tab instead. A device-page "Update agent" button is a separate change.
  - Done 2026-11-01: the device page has an "Update agent" button (confirm, forced reinstall, signed flow), and the update event is broadcast live.
- **`update-all` is not waited on.** Waiting would add up to 20 seconds to the call. Its goroutine keeps the request open for `lateUpdateWindow` (15 minutes) and records the source as a device event when the reply arrives, but the call's reply has no sources, and the fleet summary counts only devices updated through signed groups and `update-batch`.
- **Event wording.** An answer with no source (an older agent, or a device that already runs the build and skipped the download) is worded "Agent update accepted by ...; no download source reported", not "staged". A reply that arrives after the handler stopped waiting is still recorded for up to 15 minutes.
- **Test scope.** The agent test covers `selfUpdateResult`, which the handler passes straight through, not the dispatcher.
- Not verified: the new sentence and the toast were never rendered in a browser.

### 2. PipeWire frame ingestion

Built as three packages (`pod`, `proto`, `stream`) plus the wiring in `capture_pipewire_linux.go` and the OS-neutral choices in `capture_pipewire_select.go`. `pipewireIngestImplemented` is true and `errPipeWireNoIngest` is gone. Tests run on Windows against a fake server; the Linux build and vet pass.

Deviations:
- **Nesting test.** Choice and Array bodies hold headerless fixed-size values, so they cannot contain a Struct or Object; the nesting test is Object in Struct in Struct, with Choices as property values.
- **No byte vectors from PipeWire's tests.** It has none. Every vector is derived by hand from the headers and the protocol notes (`docs/plans/2026-10-25-pipewire-protocol-notes.md`).
- **POD strictness.** Padding must fit in the buffer; scalar bodies may be larger than the minimum; Array and Choice children are limited to the fixed-size types; unknown type ids are errors. The `SPA_PROP_*` values are from memory and marked unverified (the video path does not use them). Dict helpers live in `proto`'s `Dict`, not in `pod`.
- **Transport and sockets.** `Transport` takes a `Header` struct, not bytes. The Linux transport uses the standard library's `syscall` and `net.UnixConn`, not `golang.org/x/sys/unix`, so `go.mod` is unchanged. `NewSocketTransport(fd)` takes ownership of the fd. A real `Conn` over it must set `Config.CloseFd` to `proto.CloseFd` or received fds leak.
- **Core Error is per proxy.** Changed after review: the `Conn` hands a Core Error to the handler of the proxy it names (the stream ends itself with a sentence and the shared connection stays up), and ends the connection only for `-EPIPE` on id 0. A message that does not decode is dropped, as the C client does, and reported through `Config.OnSkip`.
- **Param serial.** The Format and Buffers param infos in `PortUpdate` flip their SERIAL bit on every format negotiation, so a second negotiation is not ignored by the server.
- **Stream options.** `Options` gained `Mem`, `Signal`, `SkipHello` and `Async`. `Async` is false by default, so the stream wakes the driver itself. Only `node.target` is set, not `target.object`. AsyncBuffers is not offered and ends the stream if chosen. Per-link state (Buffers I/O area and buffer set) is keyed by mix id, and the process loop reads from the newest mix that has both; only the first data block of a buffer is used. Latency and Tag are not advertised.
- **Frames.** A corrupted or empty chunk is skipped, not returned as black. A cropped frame comes out at the crop size. `VideoDamage` is not requested and not used (the design said it would be honoured); only `VideoCrop`, `chunk.offset`, `chunk.stride` and `chunk.size` (clamped to the block) are. The process loop triggers peers only when its AWAKE to FINISHED exchange succeeded, and Close wakes them when the node was still pending.
- **Selection.** `RMM_WAYLAND_PORTAL=0` turns the portal off; any other value leaves it on. A first frame that is slow to arrive is not a failure (an idle screen sends none). A stream error, `Session.Closed` from the portal, or a running stream silent for 2 minutes switches to the screenshot path, and a background probe with backoff (30 seconds doubling to 10 minutes, only while a restore token exists) switches back; an idle screen therefore costs one switch every couple of minutes. The capturer corrects each monitor's `Bounds` to the stream's frame size after the first frame, so a HiDPI or cropped output no longer makes `session.go` re-enumerate forever; `session.go` still re-enumerates on the mismatch, and monitor positions are not rescaled. `streamFor` holds a mutex while a stream opens, so `Close` can wait up to 10 seconds. Returned images are shared between calls and must not be modified; whether `session.go` obeys that was not checked. None of the retry, stall or session-closed paths has run against a real portal.
- The existing Linux test that asserted `errPipeWireNoIngest` was renamed `TestPipeWireCaptureWithoutSessionFailsWithoutFrames` and now expects any error and no image.

### Verified on 2026-10-31

Run on Ubuntu 26.04.1 (Hyper-V VM), GNOME 50 on Wayland, PipeWire 1.6.2, xdg-desktop-portal-gnome 50.

- The portal's restricted fd accepts `CreateObject("client-node")`.
- WirePlumber links the node from `node.target` alone.
- A synchronous node is fine. `Async` is not needed (the driver, mutter, is the async node).
- MemFd buffers: the server offered 8 of them. Format BGRx 1024x768, framerate 0/1, maxFramerate about 60.
- BGRx byte order renders correctly.
- The `epoll`, `eventfd`, `mmap` and `SCM_RIGHTS` code works.
- Order of the first server messages as observed: `PortSetParam(Format)` and `PortUseBuffers` before `Command Start`; `SetActivation` for the node itself before `Transport`, removed later with mem id `0xffffffff`. ClientNode interface version 6. Details in `docs/plans/2026-10-25-pipewire-protocol-notes.md`, section 8.

### Found by the real run

Four bugs, all fixed in the working tree:

- **Linux service unit template** (`internal/svc/svc.go`): the systemd unit template used `text/template` syntax the service library no longer accepts, so the service could not be installed.
- **Supervisor handed the worker the Windows pipe name** (`internal/supervisor/supervisor.go`, `internal/agent/agent.go`): the supervisor exported the Windows named-pipe name to the Linux worker and the worker dialled it, so its watchdog killed the worker every 30 seconds.
- **Misspelled portal method** (`internal/agent/desktop/capture_pipewire_linux.go`): the call was `OpenPipeRemote`; the portal method is `OpenPipeWireRemote`.
- **`active_driver_id` never written** (`internal/agent/desktop/pipewire/stream/stream.go` `onSetIO` and `publishActiveDriver`, `activation.go`): the stream did not copy `clock.id` from the Position I/O area (offset 4 of `struct spa_io_position`) into its activation at offset 548, so the driver skipped the node every cycle and it never ran. Debug-level traces (`trace`, `traceWake`, `traceActivation`) were added to the stream.

### Verified later on 2026-10-31

- The first session on a machine with no restore token: the helper now dials the bridge before it probes the capturer, the console shows "Waiting for the person at rmm-wayland to allow screen sharing" while GNOME's Share Screen prompt is up, the server's 30-second helper wait no longer fires, and frames arrive once the prompt is accepted (tested with the token deleted and the prompt left open for over 30 seconds).
- `rmm-agent install` writes the uinput udev rule; after `uninstall` and `install` on the VM the rule was present and `/dev/uinput` carried the session user's ACL without a re-login.

Two more, found while re-testing and fixed the same day:

- **Reinstall kept the old slot binary** (`cmd/rmm-agent/main.go`, `internal/supervisor/slots.go`): `rmm-agent install` seeded the A/B slot only when it was empty, so an install from a newer binary left the supervisor running the previous build. Install now refreshes the active slot when the SHA-256 differs (verified on the VM) and refuses while an update is pending.
- **Fast-start log spam** (`internal/agent/desktop/session.go`): "fast-start video encode failed; tiles only" was logged every 100 ms on Linux, which has no hardware encoder; it is logged once per session now.

### Verified later (2026-11-01, same VM)

- KDE Plasma 6.6 (KWin Wayland, xdg-desktop-portal-kde 6.6.6): the "Share screen with" dialog once, then frames, mouse and keyboard; the restore token made the second session silent (portal session ready 0.7 s after the helper started). KWin re-announced the driver node once mid-session (`active driver published` twice), which the client followed.
- HiDPI at 200% on GNOME and KDE: the portal reports the logical 960×540, the first frame is 1920×1080, the `Bounds` correction logged "PipeWire frame size differs from the portal's monitor size; using the frame size" and the console showed 1920×1080; clicks at (0.5,0.5), (0.8,0.3) and (0.7,0.4) of the canvas landed at those fractions of the screen.
- An unanswered KDE ScreenCast prompt times out after 2 minutes (`ScreenCast.Start: no response from the portal within 2m0s`) and the helper falls back to the Screenshot portal for that session, which then shows KDE's own "Allow Apps to Take Screenshots?" prompt.

### Still unverified

- Compositors that offer DMA-BUF only (the client offers MemFd and MemPtr, never DmaBuf).
- Multi-monitor sessions.
- The retry, stall and session-closed paths against a real portal.
- The portal code beyond the GNOME 50 happy path.

First check on another machine: a Wayland session with `RMM_DEBUG=1`; see `docs/OPERATIONS.md`, "Wayland screen capture". Anything that fails falls back to the Screenshot portal as before.
