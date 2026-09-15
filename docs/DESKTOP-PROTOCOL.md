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
| `{"t":"cursor","x":10,"y":20,"shape":"arrow"}` | optional cursor position (helper may omit; the viewer draws its own cursor). |
| `{"t":"clipboard","text":"..."}` | optional: remote clipboard changed (text only). |
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
| `{"t":"wheel","dx":0,"dy":120,"x":..,"y":..}` | `dy` > 0 scrolls down; units are browser `deltaY` pixels (~100 per notch). The helper converts to one wheel notch per 100. |
| `{"t":"keydown","code":"KeyA","key":"a","ctrl":false,"alt":false,"shift":false,"meta":false}` / `{"t":"keyup",...}` | `code` is the W3C physical key code (`KeyA`, `Digit1`, `Enter`, `ControlLeft`, `F5`, `ArrowUp`, `Numpad1`, ...). The helper maps `code` to a virtual key / X keysym; when the code is unknown it falls back to `key` for printable characters. |
| `{"t":"paste","text":"..."}` | type the text into the remote session (used for clipboard paste). |
| `{"t":"monitor","index":1}` | switch to another monitor; the helper answers with a new `screen` message and a full frame. |
| `{"t":"quality","q":40}` | JPEG quality 1–100 for subsequent tiles. |
| `{"t":"refresh"}` | resend a full frame. |
| `{"t":"ack","frame":123}` | flow control acknowledgement. |
| `{"t":"ctrlaltdel"}` | best effort Secure Attention Sequence (Windows: `SendSAS`, needs the *SoftwareSASGeneration* policy; otherwise ignored). |

## Helper launch

- **Windows**: the agent runs as a service in session 0, which cannot see the user's desktop. It
  finds the console session (`WTSGetActiveConsoleSessionId`), gets that session's user token
  (`WTSQueryUserToken`) — or, when nobody is logged in, duplicates its own SYSTEM token and sets
  `TokenSessionId` so the logon screen can be captured — then `CreateProcessAsUser` with
  `lpDesktop = "winsta0\default"` runs `rmm-agent.exe desktop-helper --server ... --token ...`.
  The helper captures with GDI (`BitBlt` via `kbinani/screenshot`) and injects input with
  `SendInput`. UAC prompts and the lock screen live on the secure desktop (`winlogon`) and are
  only visible when the helper runs as SYSTEM; that is why the SYSTEM-token path is used when
  no user token is available.
- **Linux**: the agent finds the active graphical session with `loginctl` (Type=x11), takes its
  `DISPLAY`, `XAUTHORITY` and user, and runs the helper as that user (`SysProcAttr.Credential`).
  Capture uses XShm/XGetImage through `kbinani/screenshot`; input uses the XTEST extension via
  `jezek/xgb`. Wayland sessions are reported as unsupported in the `note`.
- When the agent is already running interactively (developer mode, `rmm-agent run` from a
  terminal with a display), the helper runs in-process instead of spawning.
