# Phase 3E: QUIC agent transport (design, 2026-10-24)

Refines §3.10 of `2026-10-06-phase3-signed-actions.md`. Opt-in, agents only, WebSocket stays the default and the fallback.

## Goal

Remove head-of-line blocking between a shell session, a file transfer and telemetry on one agent connection, and survive address changes (roaming) without a reconnect. Each server-to-agent request gets its own QUIC stream; the rest of the protocol is unchanged, byte for byte, so every handler, test fixture and signed-action check keeps working.

## Library

`github.com/quic-go/quic-go` (pure Go, in go.mod). No HTTP/3 and no browser involvement: the console keeps its WebSocket relay. ALPN `homelab-rmm-agent/1`.

## Framing

On every QUIC stream, frames are `uint32 big-endian length` + the same JSON `protocol.Envelope` the WebSocket carries. Maximum frame size is `maxAgentFrame` on the server and the agent's existing 64 MiB read limit.

## Streams

- **Control stream**: the first bidirectional stream, opened by the agent right after the handshake. The agent sends `auth` then `hello`; the server answers `welcome` (or `error`). Afterwards it carries everything that is not tied to a request id: agent pushes (`inventory`, `metrics`, `event`, `baseline`), `ping`/`pong`, config pushes and any server frame with an empty id.
- **Request streams**: for every server frame with a non-empty id that is not a reply (`RequestA`, `StreamA`, `NotifyA`, the welcome-time pushes keep the control stream), the server opens a bidirectional stream, writes the request frame, and reads that request's `stream` and `reply` frames from it until the final `reply`, then closes it. The agent answers on the stream the request arrived on: `conn.reply`, `replyErr` and `stream` look the stream up by id; the final reply closes the agent's side. A request the agent cannot match (unknown id) is dropped. Agent-side timeouts and cancellation (`script.cancel`, shell close) keep working because they are ordinary requests on their own streams.
- `auth` is a new envelope type carried only on the control stream: `{"key": "<agent key>"}` or `{"token": "<enrollment token>"}`, never logged, never stored. It replaces the HTTP headers the WebSocket path uses. The hub refactors `handleAgentWS` into an authentication step and a transport-neutral `serve(ac)` that both paths share.

## Transport abstraction

Server: `agentConn` gains a `transport` with `writeControl(env)`, `openRequest(env) (requestStream, error)` and `close()`; the WebSocket transport implements `openRequest` by writing on the single socket (replies are demuxed by id exactly as today). The read side becomes `handleFrame(env)` (the body of today's `readLoop` switch) fed by one pump per stream. `withLogProof` runs on every send regardless of stream. Keepalive stays the application-level ping on the control stream; `quic.Config` has `MaxIdleTimeout` 90 s and `KeepAlivePeriod` 20 s besides.

Agent: `conn` gains the same shape: one writer per stream, `send` routes by id (a reply/stream frame goes to its request's stream, everything else to control). `dispatch` is unchanged; the read side is one goroutine per accepted request stream plus one for control, all calling `a.dispatch`.

## Opt-in, discovery and fallback

- Server: `--quic` (or `RMM_QUIC=1`) listens on UDP at the HTTPS port, `--quic-port` to choose another. Refused with a clear sentence under `--insecure` (no TLS, no QUIC). The same certificate and hook as the HTTPS listener, so `--tailscale-cert` rotation applies.
- The server advertises `quic_port` (and `quic: true`) in `AgentConfig`; agents remember it in their config file (`QUICPort`, `QUICFailedAt`).
- Agent: `RMM_TRANSPORT=websocket|quic|auto` (default auto; also a config field). In auto, when a port is known and the last QUIC failure is older than 10 minutes, the agent dials QUIC with a 4 s handshake deadline; any failure (no UDP, handshake, auth refused for transport reasons) falls back to WebSocket at once and records the failure time. A QUIC session that drops after being established reconnects through the same choice. An agent key refusal (401) is never a transport failure and keeps today's re-enrollment behaviour.
- The server records the transport per connection; `GET /api/agents` and `GET /api/agents/{id}` expose `transport: "websocket" | "quic"` for online devices, and the device page shows it next to the connection state.

## Tests

- `internal/server`: a QUIC listener on 127.0.0.1:0 with the test certificate; a test client (shared helper, reusable by the agent tests) that speaks the framing; connect, auth, hello, welcome; `RequestA` round trip on its own stream; a `StreamA` whose sink receives chunks while a concurrent `RequestA` completes in under 100 ms although the stream is deliberately stalled (the head-of-line test, which fails on the WebSocket transport by construction and is asserted only for QUIC); a request stream the agent never answers times out through the context; a signed action over QUIC carries `L` and the log proof chain works the same (reuse the fake agent from log_server_test.go through the new transport helper); keepalive drops a silent agent.
- `internal/agent`: the real agent session over QUIC against the server test fixture (as signed_e2e_test does over WebSocket); fallback to WebSocket when the UDP port is closed and the 10-minute memory; `RMM_TRANSPORT=websocket` never dials UDP.
- `cmd/rmm-server`: flag parsing and the `--insecure` refusal.

## Status

Implemented 2026-10-24: server (`transport.go`, `hub_quic.go`, `--quic`/`--quic-port`) and agent (`conn_quic.go`, `transport`/`quic_port`/`quic_failed_at` in `agent.json`, `RMM_TRANSPORT`). Tests: `hub_quic_test.go` and `quic_test.go`.

Deviations from the design above:
- The refusal strings and ALPN are protocol constants (`QUICALPN`, `Err*`), and `CheckQUICConfig` is exported for `main.go`.
- The agent's `MaxIncomingStreams` is 256; the server's is 8, since the agent opens only the control stream.
- The server opens request streams with `OpenStream`, never blocking under `writeMu`; the agent reads each stream's request frame in the accept loop, in stream order, before spawning a handler.
- Signed requests on different streams can still be reordered by packet loss. The agent's log-proof check then fails closed and a retry works.
- A Notify such as `shell.input` travels on the control stream, so it may in theory overtake its `shell.open`; the agent ignores input for unknown sessions.
- A WebSocket welcome that advertises QUIC only stores the port; the agent switches at the next session. A welcome without QUIC clears the stored port and failure time.
- QUIC peers are not behind trusted proxies (the device IP is the UDP peer), and unauthenticated handshakes are bounded only by 15 s per-step deadlines.

## Out of scope

HTTP/3 for the console, QUIC through reverse proxies (documented: terminate TLS at the server or stay on WebSocket), 0-RTT, connection migration beyond what quic-go does on its own.
