# Phase 4B: local subnet cache (design, 2026-10-24)

Roadmap item "Local subnet P2P mesh caching". Devices on one subnet download a server artifact once across the WAN and share it over the LAN, verified end to end by the SHA-256 the server (and, in a signing organization, the operator's signature) already names.

## What it caches

Artifacts the server itself serves by URL and hash: today the agent binary (`agent.update` payload `{url, sha256}`, 2000 devices per signed batch), and anything a later feature fetches through `cache.Fetch(url, sha256)`. Windows updates are not cached here: they come from Microsoft's CDN through the Windows Update Agent, which already peers on the LAN through Delivery Optimization. Software catalog installs run `winget`, which downloads on its own. Both are documented as out of scope.

## Roles, assigned by the server

The server knows every device's LAN addresses (inventory interfaces, with prefix) and which are online, so it assigns roles instead of electing them over multicast:

- Devices of one organization sharing an IPv4 prefix (the interface's own prefix, /24 when it is wider than /22) form a subnet group. The leader is the group's longest-online device whose agent reports `cache_capable` (it has a cache directory and could bind the port). A leader that goes offline is replaced on the next assignment pass (every 60 s, and on every online/offline event).
- `AgentConfig.Cache`: for every member `{leader_addr: "192.168.1.5:7443", leader_id, fingerprint, token}`; for the leader also `{serve: true, port: 7443, max_bytes}`. The token is an HMAC the server derives per organization and day from a secret in `settings`; the leader checks it on every request; a member sends it as a bearer. Fingerprint is the SHA-256 of the leader's self-signed certificate, which the agent generates on first start, keeps in its config directory and reports in `Hello.CacheFingerprint`. Enabled per organization in Settings (`mesh_cache: {enabled, port, max_bytes}`), default off.

No multicast or mDNS: the server already holds the membership, and a multicast election would add a discovery protocol, a second trust problem and a failure mode on networks that block multicast. The roadmap bullet is amended accordingly.

## Content-addressable store on the leader

`<config dir>/cache/<sha256>` holds the whole artifact; `<sha256>.idx` holds the SHA-256 of each 2 MiB chunk. The leader serves, over HTTPS on TCP and HTTP/3 on UDP (same port, `quic-go/http3`, the same self-signed certificate):

- `GET /cas/{sha256}` the whole file (supports `Range`), `GET /cas/{sha256}/index` the chunk list, `GET /cas/{sha256}/chunk/{i}` one chunk.
- A miss is filled on demand: the request carries `X-Origin: <url>`; the leader fetches it only when the URL is under its own configured server URL (never anywhere else, so a peer cannot turn the leader into a proxy), streams it to disk while hashing, keeps it only when the hash equals `{sha256}`, and answers 502 with the mismatch otherwise. Concurrent requests for the same hash wait for the one fill.
- Eviction is least-recently-used by file mtime down to `max_bytes` (default 2 GiB); an artifact in use is not evicted mid-stream.

## Member fetch

`cache.Fetch(ctx, url, sha256, dst)`: with a leader assigned, try HTTP/3 then HTTPS to the leader with the pinned fingerprint and the token, chunk by chunk (verify each chunk against the index, resume by chunk after an interruption), then verify the whole file against `sha256`; on any failure after one retry fall back to the origin URL directly, as today. The update path (`selfUpdate`) uses it; the operator sees in the device's update result whether the binary came from the cache or the origin. The agent reports `cache: {role, hits, misses, bytes_served, bytes_stored}` in inventory, and the device page shows it.

## Security notes

- Integrity never depends on the leader: the member verifies the SHA-256 the server named, which in a signing organization is inside the signed manifest.
- Confidentiality: artifacts are things the server serves unauthenticated anyway (agent binaries); the token and certificate pin stop devices outside the organization from using or impersonating the leader.
- The leader binds the port on every interface; the firewall rule is documented (TCP and UDP 7443 inbound from the subnet), and the Windows agent adds a firewall rule for itself when it becomes leader and removes it when it stops.

## Tests

`internal/agent/cache`: CAS fill, hash mismatch refused, chunk index, range and chunk serving, LRU eviction, origin URL restriction, token check, concurrent fills; a member fetching from a leader in-process over HTTPS and over HTTP/3, resume after a cut chunk, fallback to origin. `internal/server`: grouping by prefix and organization, leader choice and replacement, config push contents, the daily token. `selfUpdate` through the cache with a fake leader.

## Status (implemented 2026-10-24)

Built as designed: `internal/agent/cache` (certificate, CAS, leader server, member client), `internal/agent/mesh*.go` (leader lifecycle, token ring, firewall rule), `internal/server/cache_assign.go` (grouping, leader choice, tokens, the 60 s pass), and the `selfUpdate` path through `Client.Fetch`. Verified in-process over HTTPS and HTTP/3 with fake leaders; not yet run across real subnets with real firewalls.

Deviations from the design above:
- **Settings are global.** Settings in this product are global, so `mesh_cache: {enabled, port, max_bytes}` is one switch for the server, not per organization. Grouping still never crosses organizations. A PUT that omits it keeps the current value; a port under 1024 or a budget under 64 MiB is a 400.
- **Grouping detail.** Virtual adapters (docker, veth, WSL, the Hyper-V Default Switch, tunnels) are ignored, because Docker bridges repeat across unrelated hosts. A device on two subnets joins its largest group, and a group of fewer than two devices gets no cache.
- **Token.** `HMAC-SHA256(secret, "mesh-cache/v1|org|UTC-date")`, with the secret created lazily in the `mesh_cache_secret` setting. The leader accepts today's and yesterday's token so a midnight rollover does not break a transfer in flight.
- **Origin rule.** The leader fills a miss only from a URL with the same scheme and host as its own `server_url`, and refuses redirects off that host.
- **Client shape.** `Fetch` is a method on `*Client`, and `selfUpdate` reaches it through a package variable (`updateCache`) so its signature, used by the dispatcher, the auto-update loop and tests, did not change.
- **Stats.** `Hits` and `Misses` mean different things by role: a leader reports served and filled counts, a member reports fetches served by the leader and fallbacks to the origin. `Serving` and `ServeFailed` say whether an assigned leader actually bound its port.
- **A leader that cannot serve.** An assigned leader that cannot open its store or bind the port reports `serve_failed` at once and fetches its own updates from the origin; the server remembers the failure and skips that device at the next passes until it reports `serving`, goes offline, or 6 hours pass. Firewall calls (`netsh`) run on one background goroutine, never under the mesh mutex or on the session reader.
- **Store limits.** The leader admits an artifact only when it fits the budget and the free disk plus what is evictable (Content-Length checked first, copy capped at the budget, 507 when too large); orphaned `.idx` files are swept on open.
- **Source in the console.** The agent's `agent.update` reply says where the bytes came from (`cache <id> over h3`, `origin`, or `origin (the cache failed: ...)`), but `internal/server/update.go` discards that reply, so today the source shows in the agent log only. Passing the reply through is a small open follow-up.
- **Firewall.** On Windows the leader adds TCP and UDP rules through a hidden `netsh` call with `remoteip=LocalSubnet`, best effort, and removes them when it stops or the agent exits.
- **No multicast or mDNS**, as the design says; the roadmap bullet is amended.
