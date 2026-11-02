# Terminal protocol

The remote terminal moves its bytes over a WebRTC data channel when it can and
over the server's WebSocket relay when it cannot. The relay is always there: it
carries the session lifecycle and the WebRTC signaling, and it is the fallback.

```
browser  <--WebSocket /ws/shell/{agent}[?webrtc=1]-->  server  <--agent socket (WS or QUIC)-->  agent
browser  <=========== WebRTC data channel "term" (direct, UDP) ==========================>  agent
```

## Browser <-> server (WebSocket, JSON text frames)

Browser to server:

| Frame | Meaning |
| --- | --- |
| `{t:"open", shell, cols, rows}` | Open a shell. Gated: under enforcement it needs a live `shell.open` grant. |
| `{t:"in", data}` | Keystrokes (relay path). |
| `{t:"resize", cols, rows}` | Resize (relay path). |
| `{t:"close"}` | End the session. |
| `{t:"rtc_offer", sdp}` | WebRTC offer. Only honoured after `opened`, only with `?webrtc=1`, SDP at most 64 KiB. |
| `{t:"rtc_candidate", candidate}` | Trickle ICE candidate (RTCIceCandidateInit). |
| `{t:"rtc_fallback"}` | The browser gave up on WebRTC. |

Server to browser:

| Frame | Meaning |
| --- | --- |
| `{t:"webrtc_config", ice_servers}` | Sent only with `?webrtc=1`, after the grant check and before the shell is requested. Same shape as the desktop viewer's. |
| `{t:"opened", session}` | The device confirmed a shell exists. |
| `{t:"out", data}` | Output (relay path; a string, so non-UTF-8 bytes are mangled here). |
| `{t:"closed"}` / `{t:"error", message}` | Session end / failure. |
| `{t:"rtc_answer", sdp}` | The agent's answer. |
| `{t:"rtc_candidate", candidate}` | The agent's ICE candidate. |
| `{t:"rtc_switch"}` | The agent now sends output on the data channel. |
| `{t:"rtc_unavailable", reason}` | The agent could not build a peer connection (or the server rejected the offer): stay on the relay. |

The ICE servers come from `RMM_ICE_SERVERS` (`url|user|credential`, default
`stun:stun.l.google.com:19302`) and are sent to the browser and, inside
`shell.open`, to the agent, so TURN works on both ends.

## Server <-> agent (protocol envelopes)

- `shell.open` payload `ShellOpen{shell, cols, rows, rtc, ice_servers}`. `rtc`
  and `ice_servers` are omitted unless the viewer asked for WebRTC.
- `shell.rtc` (new request, `ClassRead` in the action policy, fire and forget)
  payload `ShellRTC{session, kind, sdp, candidate}`, `kind` being `offer`,
  `candidate` or `fallback`.
- Agent output and signaling both ride the `shell.open` stream as `ShellChunk`.
  A chunk with `sig` set is signaling and carries no output:
  `ShellSignal{kind, sdp, candidate, reason}`, `kind` being `answer`,
  `candidate`, `switch` or `unavailable`.

## Data channel

The browser is the offerer and creates one ordered channel labelled `term`.
The agent accepts exactly one channel with that label and ignores any other
(including a second `term`).

- Binary message: raw pty bytes, both directions, at most 32 KiB each. No
  string conversion anywhere on this path.
- Text message: JSON control frame, `{t:"resize", cols, rows}` or `{t:"close"}`.

The agent writes with backpressure: it stops when the channel has more than
1 MiB buffered and resumes when the buffer drains to 256 KiB, so a fast pty
on a slow link does not grow memory. Waiting ends at once if the session
closes or the channel dies.

## The switch (ordering)

1. Browser gets `opened`, creates the peer connection, sends `rtc_offer`.
2. Agent answers; both sides trickle candidates over the relay.
3. When the channel opens the agent, holding its output lock, first streams
   `ShellSignal{kind:"switch"}` over the relay and only then routes pty output
   to the channel.
4. The browser holds channel output until it has seen `rtc_switch` on the
   WebSocket, then writes what it held and treats the channel as the route.
   Every byte the relay carried precedes the signal on the WebSocket and every
   later byte is on the channel, so order is preserved. The browser also sends
   its current size over the relay at that moment.
5. Input and resize go over the channel once it is open and switched; before
   that, over the relay.

On switch the server writes an audit row `shell.rtc` and a device event
"Terminal session upgraded to WebRTC by <user>".

## Fallback

- The browser starts a 4 s watchdog at the offer, cancelled when the channel
  opens. It sends `rtc_fallback`, closes its peer connection and keeps using
  the relay when the watchdog fires, when the connection goes `failed` or
  `closed`, after 4 s of `disconnected`, when the offer cannot be built, or
  when more than 4 MiB of channel output piles up before the switch.
- The agent reverts to the relay and closes its peer connection when the
  channel closes, the connection fails or closes, a `fallback` arrives, or a
  channel write fails. It also closes it when the shell ends or is closed.
- The agent sends `unavailable` if the peer connection cannot be created or
  the offer cannot be applied. The browser stays on the relay.
- The WebSocket stays open for the whole session whichever transport is
  active; closing it ends the shell.
- Bytes already queued on a channel that died are lost: the agent cannot know
  what the peer received. The unsent remainder of the read in flight is sent
  over the relay.

## Security notes

- One peer connection and one data channel per session. A second offer for a
  session is refused, as is a second channel.
- Signaling is accepted only for a session created by a gated `shell.open`:
  the server forwards `shell.rtc` only after the device confirmed the shell
  (`opened`), and the agent refuses signals for unknown ids and for sessions
  opened without `rtc`. Under enforcement a viewer without a grant never gets
  as far as a shell, so no offer is honoured.
- The offer is authenticated by the browser's console session and travels over
  the TLS relay; DTLS then binds the data channel to the keys in that offer,
  so a third party who learns the candidates cannot join the channel.
- Server-side SDP and candidates are capped at 64 KiB; the WebSocket frame
  limit still applies.
- The channel carries what the relay already carried (keystrokes and output)
  and nothing that creates sessions, so it adds no capability beyond the
  gated shell.
