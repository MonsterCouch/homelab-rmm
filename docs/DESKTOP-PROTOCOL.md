# Remote desktop wire protocol

Three parties: the **viewer** (browser), the **server** (a dumb bridge, `internal/server/relay.go`)
and the **helper** (`rmm-agent desktop-helper`, package `internal/agent/desktop`). The server
bridges the two WebSockets frame for frame and never decodes video.

Connection sequence:

1. Viewer opens `wss://server/ws/desktop/{agentId}?quality=60` (session cookie).
2. Server sends the agent `desktop.start {token, quality}`. The agent service launches the helper
   in the interactive session; the helper opens `wss://server/ws/desktop-agent?token=<token>`.
3. Server sends the viewer `{"t":"connected"}` and bridges. It may also send
   `{"t":"note","message":...}` (from the agent, e.g. "no user logged in, showing logon screen")
   and `{"t":"error","message":...}` before closing.

All multi-byte integers in binary frames are **little-endian**.

## Helper → viewer

Text frames (JSON):

| message | meaning |
|---|---|
| `{"t":"screen","w":1920,"h":1080,"monitor":0,"monitors":[{"index":0,"x":0,"y":0,"w":1920,"h":1080,"primary":true},...]}` | sent first, after a monitor switch and whenever the resolution changes. `w`/`h` are the current monitor's size; every tile that follows is in that monitor's pixel space. |
| `{"t":"cursor","x":10,"y":20,"shape":"arrow"}` | optional cursor position. **No helper sends this yet on any platform**, and the Windows GDI capture excludes the cursor from the pixels, so the remote pointer is currently invisible in the stream. |
| `{"t":"clipboard","text":"..."}` | optional: remote clipboard changed (text only). **No helper sends this yet on any platform**, so the viewer's "Remote clipboard" control never becomes available. The viewer-to-helper direction (pasting *into* the session) does work. |
| `{"t":"error","message":"..."}` | fatal; the helper closes afterwards. |

Binary frames: first byte is the kind.

| kind | layout | meaning |
|---|---|---|
| `0x01` tile | `u8 kind, u16 x, u16 y, u16 w, u16 h, u8 codec, bytes...` | a rectangle to draw at (x,y) of size (w,h). `codec` 0 = JPEG, 1 = PNG. |
| `0x02` frame end | `u8 kind, u32 frameId` | all tiles of one capture pass have been sent. The viewer replies `{"t":"ack","frame":frameId}`. The helper keeps at most **2 frames unacknowledged** (flow control) and pauses capture until an ack arrives. |

The first frame after `screen` covers the entire monitor. Later frames contain only tiles whose
pixels changed (the helper diffs 64×64 tiles against its previous capture and merges runs of
changed tiles into wider rectangles).

## Viewer → helper

Text frames (JSON). Coordinates are integers in the current monitor's pixel space (the viewer
scales from its canvas size to `screen.w`/`screen.h`).

| message | meaning |
|---|---|
| `{"t":"mousemove","x":..,"y":..}` | absolute move |
| `{"t":"mousedown","button":0,"x":..,"y":..}` / `{"t":"mouseup",...}` | button 0 left, 1 middle, 2 right |
| `{"t":"wheel","dx":0,"dy":120,"x":..,"y":..}` | `dy` > 0 scrolls down; units are browser `deltaY` pixels. 100 units = one notch, and the helper rounds any single event between 40 and 200 units (either sign, each axis on its own) to exactly one notch — browsers disagree about a notch (Chrome on Windows sends 120, Chrome on Linux 100 or 53), and rounding is what stops every fifth 120 px notch from scrolling twice. Smaller deltas are trackpad scrolling and accumulate until they reach 100; a rounded notch discards whatever remainder was pending. For `deltaMode` 1 (line) and 2 (page) the viewer converts to whole notches × 100 before sending. |
| `{"t":"keydown","code":"KeyA","key":"a","ctrl":false,"alt":false,"shift":false,"meta":false}` / `{"t":"keyup",...}` | `code` is the W3C physical key code (`KeyA`, `Digit1`, `Enter`, `ControlLeft`, `F5`, `ArrowUp`, `Numpad1`, ...). The helper maps `code` to a virtual key / X keysym; when the code is unknown it falls back to `key` for printable characters. |
| `{"t":"paste","text":"..."}` | type the text into the remote session (used for clipboard paste). |
| `{"t":"monitor","index":1}` | switch to another monitor; the helper answers with a new `screen` message and a full frame. |
| `{"t":"quality","q":40}` | JPEG quality 1–100 for subsequent tiles. |
| `{"t":"refresh"}` | resend a full frame. |
| `{"t":"ack","frame":123}` | flow control acknowledgement. |
| `{"t":"ctrlaltdel"}` | best effort Secure Attention Sequence (Windows: `SendSAS`, needs the *SoftwareSASGeneration* policy; otherwise ignored). |

## Connection query parameters

The viewer opens `wss://server/ws/desktop/{agentId}` with:

| param | meaning |
|---|---|
| `quality` | JPEG quality 1–100 for the tile stream (default 60). |
| `webrtc=1` | the viewer supports WebRTC; the server replies with `webrtc_config` and the helper negotiates a peer connection (see below). Omitted = tiles only, exactly as before. |
| `mode=backstage` | attach to the isolated administrative desktop instead of the console (Windows only; see Backstage mode). Default `console`. |

## WebRTC transport (optional, with automatic fallback)

When the viewer asks for it (`?webrtc=1`), video and input can travel peer-to-peer over WebRTC
(UDP/SRTP) instead of through the server relay, cutting latency and server bandwidth. The JPEG
tile stream stays up as both the **fast-start** (the first picture shows in <100 ms over the
WebSocket while ICE negotiates) and the **firewall fallback** (if UDP is blocked). The server only
relays the signaling text frames verbatim and delivers STUN/TURN config; it never decodes media.

Signaling messages (JSON text frames, bridged viewer ⇄ helper; the browser is the **offerer**):

| message | direction | meaning |
|---|---|---|
| `{"t":"webrtc_config","ice_servers":[{"urls":[...],"username":"","credential":""}]}` | server → viewer | STUN/TURN servers for `RTCConfiguration` (configure with `RMM_ICE_SERVERS`; defaults to a public STUN server). Sent once, before the helper connects. |
| `{"t":"webrtc_offer","sdp":"..."}` | viewer → helper | SDP offer: a recvonly H.264 video transceiver plus two data channels. |
| `{"t":"webrtc_answer","sdp":"..."}` | helper → viewer | SDP answer with the sendonly H.264 track. |
| `{"t":"webrtc_candidate","candidate":{...}}` | both ways | trickle ICE candidate (`RTCIceCandidateInit`). |
| `{"t":"webrtc_active"}` | viewer → helper | the `<video>` is decoding WebRTC frames (`onplaying`): the helper stops sending JPEG tiles. |
| `{"t":"fallback_tiles"}` | viewer → helper | WebRTC failed to connect within the viewer's 4 s watchdog, or dropped after connecting: the helper resumes the JPEG tile stream. |

Video: the helper encodes H.264 (Windows Media Foundation MFT, hardware when available) and writes
Annex-B access units to a Pion `TrackLocalStaticSample`. A background RTCP reader on the sender
forces an IDR keyframe on `PictureLossIndication`/`FullIntraRequest`, so a dropped UDP packet
recovers instead of freezing the browser's decoder.

Input over WebRTC uses two SCTP data channels, created by the viewer:

| channel | reliability | carries |
|---|---|---|
| `input-unreliable` | unordered, `maxRetransmits: 0` | `mousemove` (a later move supersedes a lost one) |
| `input-reliable` | ordered, reliable | `mousedown`/`mouseup`, `wheel`, `keydown`/`keyup`, `paste`, `ctrlaltdel` |

Data-channel messages use the **same JSON schema** as the viewer→helper table above, so one code
path injects input whichever transport delivered it.

## Backstage mode (Windows)

`?mode=backstage` streams an isolated virtual desktop (`winsta0\HomelabRMM_Backstage`, created with
`CreateDesktopW` and a DACL admitting only SYSTEM and Administrators) that the logged-in user never
sees, for administrative work that must not disturb them. The helper launches admin tools
(`cmd.exe`, `taskmgr.exe`) onto that desktop; any PowerShell is started `-WindowStyle Hidden`.

Capture and input never touch the physical screen: the compositor enumerates the backstage
desktop's windows (`EnumDesktopWindows`) and draws each with `PrintWindow(…, PW_RENDERFULLCONTENT)`
into an off-screen DIB — **never** `GetDC(NULL)` — and input is hit-tested against the backstage
window tree and delivered with `PostMessageW` — **never** `SendInput`. The physical cursor does not
move and the user's screen is never captured. A static test (`TestBackstageNoForbiddenAPIs`)
enforces that the forbidden APIs appear nowhere in the backstage source.

## Helper launch

- **Windows**: the agent runs as a service in session 0, which cannot see the user's desktop. It
  finds the console session (`WTSGetActiveConsoleSessionId`), duplicates its own SYSTEM token and
  sets `TokenSessionId` to that session, then `CreateProcessAsUser` with
  `lpDesktop = "winsta0\default"` runs `rmm-agent.exe desktop-helper --server ... --fingerprint ...`.
  The helper captures with GDI (`BitBlt` via `kbinani/screenshot`) and injects input with
  `SendInput`. It runs as SYSTEM on purpose: UAC prompts, the lock screen and Ctrl+Alt+Del live on
  the secure desktop (`winlogon`), whose DACL admits LocalSystem alone, and `WTSQueryUserToken`
  hands back an administrator's UAC-*filtered* token, which UIPI stops from clicking anything
  elevated. When the agent itself is not LocalSystem there is no SYSTEM token to move, and the
  helper falls back to the console user's token — the linked, elevated one when UAC filtered it —
  with a `note` saying the lock screen will not be visible. A helper that cannot follow the input
  desktop ends the session with `{"t":"error"}` rather than streaming a frozen picture of the old
  one.
- **Linux**: the agent finds the active graphical session with `loginctl` (Type=x11), takes its
  `DISPLAY`, `XAUTHORITY` and user, and runs the helper as that user (`SysProcAttr.Credential`).
  Capture uses XShm/XGetImage through `kbinani/screenshot`; input uses the XTEST extension via
  `jezek/xgb`. An active X11 session owned by a user wins; the display manager's greeter
  (`Class=greeter`) is used only when there is nothing else, and the `note` then says no user is
  logged in. A Wayland session is captured through the ScreenCast portal and PipeWire (unverified against a real compositor; see docs/OPERATIONS.md, "Wayland screen capture"), with the Screenshot portal as the fallback — a Wayland *greeter* is
  reported as "no user is logged in" instead, because that is the more useful half of the truth.
- **Linux without logind** (no systemd, a hand-started X server, a kiosk box, Xvfb) — three
  optional keys in the agent config, `agent.json` in `$RMM_AGENT_DIR` or `/etc/homelab-rmm`, are
  consulted **before** `loginctl` and skip it entirely when any of them is set:

  | key | meaning |
  |---|---|
  | `desktop_display` | the X display to attach to, e.g. `":0"`. Defaults to the display of a running process owned by `desktop_user`, else `":0"`. |
  | `desktop_user` | the account to run the helper as: a name or a numeric uid. Defaults to the account the agent itself runs as, which is what a root-started X server needs. |
  | `desktop_xauthority` | path to the X cookie file. Must exist when set; defaults to `$HOME/.Xauthority`, then `/run/user/<uid>/gdm/Xauthority`. |

  ```json
  { "server_url": "https://rmm.example:8443", "desktop_display": ":0", "desktop_user": "alice" }
  ```

  Keys that name an account or a cookie file that does not exist are logged at WARN and `loginctl`
  is tried after all. With neither the keys nor a usable `loginctl` the start fails with
  `cannot find the graphical session (<loginctl error>); set desktop_display and desktop_user in
  agent.json (<path>)` instead of a raw `loginctl` error.
- When the agent is already running interactively (developer mode, `rmm-agent run` from a
  terminal with a display), the helper runs in-process instead of spawning.
- **The one-time bridge token is passed in the environment**, as `RMM_DESKTOP_TOKEN`, on both
  platforms: `/proc/<pid>/cmdline` is world-readable on Linux and any local account can read a
  command line on Windows, so an argument would hand a live session token to every local user.
  `--token` is still accepted and takes precedence, as a developer override for running
  `rmm-agent desktop-helper` by hand; the helper drops the variable from its own environment as
  soon as it has read it, so nothing it starts inherits the token.

## Privacy banner overlay & multi-monitor support

- **Session privacy banner (Windows)**:
  To prevent covert surveillance and inform the local user that remote management is active, the
  desktop helper displays a topmost overlay banner (`HomelabRMM - Remote Support Active`) across
  the active monitor. The banner is created using Win32 layered click-through window styles
  (`WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_NOACTIVATE`). This ensures:
  - Clicks and touches pass directly through to the underlying applications without interference.
  - The banner never steals keyboard input focus or activates over fullscreen games/apps.
  - When the remote session ends or disconnects, the window and its GDI resources are destroyed
    immediately (`DestroyWindow`).

- **Multi-monitor display switching**:
  The helper queries display bounds across all attached monitors via GDI (`EnumDisplayMonitors` /
  `GetSystemMetrics`) or X11/XRandR.
  - The initial `screen` text frame enumerates all monitors (`monitors: [...]`) along with resolutions
    and offsets.
  - The web viewer provides a display selector dropdown. Sending `{"t":"monitor","index":<n>}` switches
    active capture to the selected display index (e.g. index 0 for primary, 1 for secondary).
  - The helper responds with an updated `screen` frame and an immediate full-frame refresh in the
    new monitor's coordinate space.
