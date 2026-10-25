# Phase 3 Implementation Plan: Signed Actions & Tamper-Evident Audit

**Document:** `docs/plans/2026-10-06-phase3-signed-actions.md`
**Status:** 3A, 3B and 3C implemented (2026-10-24); 3D, 3E open. See §8.
**Supersedes:** the Phase 3 sections of `docs/ROADMAP.md` (as of 2026-10-05) and `docs/MASTER_TRANSFORMATION_HANDOFF.md`
**Goal:** An agent never runs a destructive action, opens a shell or desktop, or installs an update unless an operator's hardware key signed that exact action for that exact device. A stolen session, a tampered database or a compromised server process can no longer turn the RMM into a fleet-wide ransomware launcher (the Kaseya VSA 2021 failure model).

### Decisions recorded (2026-10-06)

| Question | Decision |
| :--- | :--- |
| Where are approvals signed? | **Browser WebAuthn first (3A/3B); an out-of-band signer later (3D).** |
| Immutable audit log | **Local Merkle transparency log** (pure Go). No Sigstore Rekor. |
| QUIC / HTTP/3 | **Deferred** until 3A–3C are done (3E). |

---

## 1. Threat model

| # | Adversary | Outcome with this plan |
| :--- | :--- | :--- |
| T1 | Stolen operator session: cookie theft, phished password + TOTP | **Defeated.** Every protected action needs a fresh touch of the operator's key. |
| T2 | Database compromise: SQL injection, stolen backup, insider with DB write access, edited scripts or schedules | **Defeated.** The agent runs only content whose hash an operator signed. |
| T3 | Full server compromise (RCE, replaced binary) | **Partly mitigated.** The attacker cannot act on their own, but the console's JavaScript comes from the server, so a modified console can show one action and have the key sign another. Security keys do not display what they sign. This closes in **3D** (a signer the server does not serve). The attacker can still deny service and read telemetry. |
| T4 | Replay of a captured signed action | **Defeated.** Nonce, expiry, and binding to a target agent and organisation. |
| T5 | Local administrator on the endpoint | Out of scope (they already own the machine). |

Also out of scope:
- confidentiality of shell and desktop streams;
- keystrokes injected into a session that is **already open**. Signing covers the session open, not each keystroke.

Both are listed under risks in §7.

---

## 2. Findings in the current code

- **Agent chokepoint.** Every server request passes through `Agent.dispatch` (`internal/agent/agent.go:366`). Several are handled in its fast path **before** `Agent.handle` (`:411`), including `agent.config` (`:375`) and shell input. The check therefore goes in `dispatch`, ahead of the fast path.
- **Baseline specs are code (the largest hole).** `agent.config` (`protocol.AgentConfig.Baselines`) delivers baseline specs whose `command` checks carry arbitrary check and fix scripts (`internal/agent/baseline_kinds.go:520/546`). The agent runs them on its own interval, offline too. A database or server attacker could push a baseline and get SYSTEM code running fleet-wide without ever sending `script.run`. `baseline.preview` runs an unsaved spec's check scripts immediately.
- **Server chokepoints.** Every outgoing action goes through `Hub.Request` / `Hub.Stream` / `Hub.Notify` (`internal/server/hub.go:487/528/556`).
- **Wire format.** `protocol.Envelope` (`internal/protocol/protocol.go:17`) is `{t, id, d, err}`, with no authorization field. Nothing cryptographic exists between "the handler allowed it" and "the agent ran it". Agent self-update only checks a SHA-256 that the server itself supplies (`internal/agent/update.go`).
- **Operator authentication.** Roles (`auth.go:21-31`), bcrypt, optional TOTP, a CSRF header and `requireWrite` / `requireAdmin`. There are no API tokens: the browser console is the only API client.
- **Audit.** The `audit` table (`db.go:264`, writer `DB.Audit` at `db.go:720`) and `agent_events` (`db.go:275`) are plain mutable rows.
- **Frontend.** Every API call goes through one function, `request()` in `web/src/api/client.ts:90`.
- **Actions that run with nobody present.** A per-action key touch would break all of these:

  | Originator | Location | What it does |
  | :--- | :--- | :--- |
  | Scheduled script task | `scheduler.go:154` | `script.run` |
  | Scheduled reboot | `scheduler.go:170` | `power` |
  | Alert automation | `scheduler.go:294` | `script.run` |
  | Patch policy | `patches.go:303` | `updates.install` |
  | Post-patch reboot | `patches.go:372` | `power` |
  | Software catalog | `software_catalog.go:247/320` | `script.run` (generated winget bodies) |
  | Client self-service portal | `portal.go:313` | `script.run`, started by a client contact who never signs |

- **Indirect code.** `baseline.remediate` (`api_baselines.go:624`) only names a baseline and its check IDs. The remediation steps live in baseline definitions the agent received unsigned. Any server-supplied data that later decides what runs must be bound by hash.

### Corrections to the earlier blueprint

| Earlier proposal | Problem | This plan |
| :--- | :--- | :--- |
| "Admin signs with a YubiKey via WebAuthn in the console" stops a compromised server | Blind signing (T3) | Browser signing for T1/T2; out-of-band signer in 3D |
| Ed25519 keys | Windows Hello, Touch ID and most passkeys sign **ES256**; Windows Hello TPM keys may sign **RS256** | Agent verifies ES256, EdDSA and RS256 |
| Targets chosen by tag filter (`"tags": ["production-servers"]`) | An agent cannot check a server-side tag | An explicit list of agent IDs plus the organisation pinned at enrollment |
| Public key carried inside the signature | Invites trusting the message's own key | Keys are looked up only in the agent's pinned trust bundle |
| `signatures` inside the signed JSON | Circular definition | Detached signatures over the exact manifest bytes |
| Failed check: "endpoint isolates its network interface" | Lets anyone who can send a bad manifest, a bug or clock skew cut machines off, including the channel needed to fix them | **Reject, log, raise a security event. Never isolate.** |
| Anti-replay "in TPM NVRAM / SQLite" | Unnecessary; the agent has no SQLite | Nonce + expiry + binding, with consumed nonces kept in a file in the locked-down config directory |
| Agent checks a Sigstore Rekor inclusion proof before executing | Publishes admin-activity metadata; needs internet egress; self-hosting needs Trillian and a database | Local Merkle log with signed tree heads (3C) |
| No answer for unattended actions | Scheduler, patching, catalog and portal stop working | Signed standing approvals (3B) |
| No trust root or recovery story | The server could hand agents its own keys; losing the only key locks you out | Pinned bundle, quorum rotation, offline recovery key (§3.4) |

---

## 3. Design

### 3.1 The manifest

A manifest is a small JSON document. The **exact bytes** are signed, transmitted and stored. Nobody re-serializes it: the agent verifies the received bytes and only then parses them. Bytes are still emitted in RFC 8785 (JCS) form so that independent tools produce identical bytes for identical content. Manifests contain **no floating-point numbers**, which reduces JCS number formatting to integers.

```json
{
  "v": 1,
  "kind": "action",
  "id": "01J9Z0X8K6Q3M8T2V5W7Y9A1BC",
  "org": "org_7f3a",
  "targets": ["agent_1c2d", "agent_9e8f"],
  "op": "script.run",
  "payload": { "language": "powershell", "body": "Restart-Service Spooler", "args": [], "timeout_sec": 300 },
  "nonce": "kq3V1oZ8yN2bX7cR4tL0mA",
  "iat": 1791234567,
  "exp": 1791235167,
  "issuer": "alice"
}
```

- **`kind`** is one of:
  - `action`: one-shot; the nonce is consumed.
  - `grant`: a time-boxed capability on one agent (§3.3).
  - `standing`: a reusable approval for unattended runs (§3.7).
  - `bundle`: a trust-bundle update (§3.4).
- **The agent runs what was signed.** For protected operations it takes the payload from the verified manifest and ignores `Envelope.D`. The server cannot swap the content after signing.
- **`targets`** must include the agent's own ID, and **`org`** must equal the organisation pinned in its bundle.

### 3.2 Signatures

Signatures are detached and travel next to the manifest. Each one is a WebAuthn assertion: `{cred, ad, cd, sig}` (credential ID, authenticatorData, clientDataJSON, signature), all base64url.

The agent checks each assertion as follows:
1. `cred` exists in the pinned bundle. This yields the public key, the algorithm and the owner.
2. `clientDataJSON` contains:
   - `type == "webauthn.get"`;
   - `challenge == base64url(SHA-256(manifest bytes))`;
   - an `origin` from `bundle.origins`;
   - no `crossOrigin: true`.
3. In `authenticatorData`:
   - the RP ID hash equals `SHA-256(bundle.rp_id)`;
   - the **UP** flag is set;
   - the **UV** flag is set when the policy requires it.
4. The signature over `authenticatorData ‖ SHA-256(clientDataJSON)` verifies with ES256 (DER ECDSA P-256), EdDSA (Ed25519) or RS256.
5. Valid signatures are counted per **distinct owner** (one person with two keys counts once), against the threshold for the manifest's class.

The signature counter is ignored: passkeys report 0, and clone detection buys nothing here.

### 3.3 Action classes

The agent derives the class from its **built-in table**, never from the server. A signed bundle may raise thresholds; it cannot move an operation into a less protected class.

| Class | Operations | Requirement |
| :--- | :--- | :--- |
| **read** | `ping`, `inventory.refresh`, `proc.list`, `svc.list`, `eventlog.query`, `updates.scan`, `script.cancel`, `wol`, `network.scan`, `snmp.poll`, `baseline.evaluate` (approved specs only, see below), and `shell.input` / `shell.resize` / `shell.close` (they only act on a session that a signed `shell.open` created) | none |
| **config** | `agent.config` | intervals and monitored services are unsigned; **each baseline spec must carry a `standing` approval binding its SHA-256**. In `enforce`, unapproved specs are dropped and reported. |
| **grant** | `shell.open`, `desktop.start`, `fs.list`, `fs.read` | one signature opens a capability for one agent; TTL 15 min by default, 60 max |
| **action** | `script.run`, `proc.kill`, `svc.action`, `fs.write`, `fs.delete`, `fs.rename`, `fs.mkdir`, `power`, `updates.install`, `baseline.remediate`, `baseline.preview` (it runs the unsaved spec's check scripts), `device.isolate` | one signature, one use |
| **high-risk** | `agent.update`; trust-bundle changes; any manifest whose `targets` exceed `policy.bulk_limit` (default 10) | `policy.high_threshold` distinct owners (default 1, so single-admin homelabs still work) |

**Payload binding for the indirect cases:**
- `agent.update`: the signed payload carries the binary's SHA-256, which `update.go` already checks after download. This closes the "push a backdoored agent" hole.
- Baselines: the agent keeps only specs whose SHA-256 a `standing` approval covers, so `baseline.evaluate` and `baseline.remediate` can only ever run approved check and fix scripts. `baseline.remediate` is still an `action`, because it changes state.

### 3.4 Trust bundle

The trust bundle is the agent's root of trust, stored as `trust.json` in the agent's locked-down config directory:

```json
{
  "v": 1, "epoch": 3, "prev": "<sha256 of epoch 2 bundle>",
  "org": "org_7f3a", "rp_id": "rmm.lan", "origins": ["https://rmm.lan:8443"],
  "signers": [
    { "owner": "alice", "creds": [
      { "id": "<b64url credential id>", "alg": -7, "pub": "<b64 SPKI DER>" },
      { "id": "...", "alg": -8, "pub": "..." } ] }
  ],
  "recovery": [ { "id": "recovery-1", "alg": "ed25519", "pub": "<b64 raw 32 bytes>" } ],
  "log_key": "<b64 Ed25519 public key of the server's transparency log (3C)>",
  "policy": { "mode": "audit", "require_uv": false, "high_threshold": 1, "bundle_threshold": 1, "bulk_limit": 10 }
}
```

**First bundle, trust on first use.** A new agent receives the bundle in the enrollment `welcome` frame. An existing agent accepts the first bundle that arrives over its authenticated socket. Both are logged as security events. Optionally, the install one-liner can pin the bundle hash out of band (`--trust-pin`).

**Updating the bundle** (new request `trust.update`). The agent accepts a new bundle only if all of these hold:
- `epoch` is greater than the current one;
- `prev` equals the hash of the current bundle;
- it is signed by `bundle_threshold` distinct owners **from the current bundle**, or by a recovery key from the current bundle.

The server therefore cannot introduce its own key.

**Recovery key.** Generated in the browser with WebCrypto Ed25519 and shown once as a printable code. Only the public key leaves the page. Recovery signing (rare: all keys lost) is done offline with `rmm-server trust sign-bundle --recovery-key FILE`. **The server refuses to set `mode: enforce` until the bundle contains a recovery key.**

### 3.5 Rollout modes

The mode lives in the signed bundle, so changing it is itself a signed action.

| Mode | Agent behaviour |
| :--- | :--- |
| *(no bundle)* | today's behaviour; nothing is checked |
| `audit` | verifies everything; on failure it **still executes** but sends a `security` event, and the server raises an alert. This shows which paths are still unsigned before anything breaks. |
| `enforce` | rejects with an explicit reason (`signature required: …`) and sends a `security` event. **Never isolates.** |

### 3.6 Anti-replay

- **Nonce:** 128 bits.
- **`iat` / `exp`:** maximum lifetime 10 min for an `action`, 60 min for a `grant`, 365 days for a `standing` approval. Up to 5 min of clock skew is tolerated.
- **Binding:** to the target list and the organisation.
- **Consumed nonces:** kept in `nonces.json`, append-only and pruned after expiry, so a restart cannot reopen the window. (Example: a replayed `reboot` manifest would otherwise work again after the reboot it caused.)
- **Clock errors:** an agent whose clock is out of range reports that, rather than a generic failure.
- **Standing approvals** are reusable by design. Their safety comes from content-hash binding, scope and expiry (§3.7).

### 3.7 Standing approvals (3B)

An operator signs a `standing` manifest once, when creating or editing the scheduled task, automation, policy or catalog item. The server stores it next to that object and sends it with every run, together with the concrete payload.

The agent checks:
- the standing manifest's signatures, expiry, `org` and `targets`;
- that the concrete payload satisfies its `constraints`.

| Originator | Constraint the agent checks |
| :--- | :--- |
| Scheduled task / automation (`script.run`) | `sha256(body) == body_sha256`, same language, same args |
| Scheduled reboot / post-patch reboot (`power`) | `action == "reboot"` |
| Patch policy (`updates.install`) | allowed; the agent installs only through the OS update service, so update IDs cannot carry code |
| Software catalog / portal (`script.run`) | `body_sha256` of the **final generated** body, per catalog item and action (install / uninstall) |
| Baseline spec (`agent.config`) | `spec_sha256` of the spec as delivered; approved when the baseline is created or edited |

Once a bundle exists, a **Review & sign** page lists every unsigned task, automation, policy and catalog item. In audit mode these keep running, with warnings, until they are signed.

### 3.8 Transparency log (3C)

**Server log.** An RFC 6962-style Merkle log built on `golang.org/x/mod/sumdb/tlog` (pure Go; the same code behind Go's checksum database). It records:
- every manifest and signature set the server relays;
- every bundle;
- every `DB.Audit` row.

Signed tree heads use a server log key (Ed25519, kept in the data directory). Its public half is pinned in the bundle, so the key cannot be swapped silently. Endpoints serve the head, inclusion proofs and consistency proofs.

**Agent side:**
- When `policy.require_log_proof` is set, a protected action arrives with an inclusion proof and a tree head. The agent verifies both, plus consistency with the last head it accepted. The server cannot run something without logging it, and cannot rewrite history without agents noticing.
- Each agent keeps its own hash-chained `executed.log` of the manifests it ran and reports the head in inventory. The server cannot quietly drop an entry.

### 3.9 Out-of-band signer (3D, design deferred)

A signer whose code the server does not serve. It renders the manifest itself, so you can see what you sign (closes T3). Candidates:
1. A Windows desktop signer using the native WebAuthn API (`webauthn.dll`, pure-Go syscalls, works with Windows Hello and security keys).
2. A native approval screen in the Android app (Credential Manager). The app is currently a WebView of the console.
3. A CLI.

3D also adds the M-of-N approval queue.

### 3.10 QUIC / HTTP/3 (3E, deferred)

Notes for when this is picked up:
- The real benefit is removing head-of-line blocking between shell, file transfer and telemetry. That requires mapping requests to separate QUIC streams, not just swapping the transport under `Envelope`.
- A WebSocket fallback is mandatory: UDP/443 is often blocked, and `--insecure` deployments behind a reverse proxy cannot carry QUIC through to the server.
- Tailscale users already get roaming from WireGuard.

---

## 4. Wire changes

- **`protocol.Envelope`** gains `A *ActionAuth \`json:"a,omitempty"\``, holding the manifest bytes, the signatures, an optional standing manifest and (3C) an optional log proof.
  - Old agents ignore the field.
  - Old servers never send it. An agent in `enforce` then rejects protected operations; that is intended.
- **`trust.update`** (server → agent): a new request carrying a bundle and its signatures (high-risk class).
- **`welcome`** carries the bundle at enrollment.
- **Security events** reuse `TypeEvent` with `kind: "security"`, and the server raises an alert.
- **HTTP flow.** A protected handler without a valid signature answers **`428 Precondition Required`** with `{manifest_id, manifest}`.
  - `request()` in the console catches it, shows what will be signed, calls `navigator.credentials.get` with `challenge = SHA-256(manifest)`, and retries with `{manifest_id, assertion}`.
  - The server dispatches the **stored** manifest, not the retried request body.
  - No individual console page needs to change.

- **Bundle sync.** `hello` carries `trust_epoch` and `trust_hash`.
  - Agent holds no bundle: after the welcome the server sends the current bundle (trust on first use).
  - Agent holds epoch *k*: the server sends epochs *k+1 … n* in order, each signed by its predecessor's signers. A hash mismatch at *k* raises an alert.
- **Baseline approvals.** `agent.config` carries `baseline_auth`, a map from baseline ID to the standing approval of that spec.
- **Correlation fields.** One signed `script.run` manifest serves every target, and each agent takes only `run_id` from its own envelope (`actionauth.correlationFields`).

### 4.1 HTTP API (server ⇄ console)

All binary values are unpadded base64url. All routes are under the existing session/CSRF middleware. "Admin" means `requireAdmin`.

**Security keys** (any operator, for their own account):

| Route | Body → Response |
| :--- | :--- |
| `POST /api/webauthn/register/begin` | → `PublicKeyCredentialCreationOptions` JSON (challenge, `rp{id,name}`, `user{id,name,displayName}`, `pubKeyCredParams` ES256/EdDSA/RS256, `attestation:"none"`, `excludeCredentials`). The server keeps the challenge for 5 min. Refused with a clear message when the console is reached by IP address. |
| `POST /api/webauthn/register/finish` | `{name, id, clientDataJSON, authenticatorData, publicKey, publicKeyAlgorithm}`. `publicKey` is the SPKI from `response.getPublicKey()`, so no CBOR is needed. The server checks `type webauthn.create`, the challenge, the origin, the RP ID hash and UP, then stores the key. → the credential. |
| `GET /api/webauthn/credentials` | → `[{id, name, alg, owner, created_at, last_used_at, in_bundle}]` (all of them for admins) |
| `DELETE /api/webauthn/credentials/{id}` | Removing a key that is in the bundle needs a bundle update. |

**Trust bundle** (admin):

| Route | Body → Response |
| :--- | :--- |
| `GET /api/organizations/{id}/trust` | → `{current: {epoch, hash, mode, policy, signers, recovery_ids, rp_id, origins} \| null, proposals: [...], agents: {at_current, behind, mismatched, none}}` |
| `POST /api/organizations/{id}/trust/proposals` | `{mode, require_uv, high_threshold, bundle_threshold, bulk_limit, signers: [{owner, credential_ids}], recovery: [{id, pub}]}` → `{id, epoch, bundle, need, have}`. The server builds epoch+1 with `prev`, `rp_id` and `origins`. It refuses `enforce` without a recovery key. |
| `POST /api/trust/proposals/{pid}/sign` | `{assertion}` (challenge = SHA-256 of the bundle bytes; signer from the **current** bundle, or for the first bundle one of its own signers) → `{have, need, active}` |
| `POST /api/trust/proposals/{pid}/recovery` | `{id, sig}` produced offline by `rmm-server trust sign-bundle` → `{active}` |
| `GET /api/trust/proposals/{pid}` | → `{bundle, ...}`, for offline recovery signing |

When a proposal becomes active, the server stores it as the org's new epoch and pushes `trust.update` to the org's online agents.

**Signing an action** (the 428 flow, in `request()`):
1. A protected request in an org whose bundle mode is not `off`, with no `X-Action-Auth` header, is answered `428 {error, manifest_id, manifest, summary, required}`. `required` is true in `enforce`. In `audit` the operator may decline with `X-Action-Auth: skip`; the action then runs unsigned and the agent reports it.
2. The console decodes and shows the manifest, calls `navigator.credentials.get({publicKey: {challenge: SHA-256(manifest), rpId, allowCredentials, userVerification}})`, and repeats the **same** request with `X-Action-Auth: base64url(JSON{manifest_id, assertion})`.
3. The server loads the stored manifest (bound to that user and not expired), checks the assertion against the bundle, and dispatches the **stored** manifest. The original handler's response is returned.
4. If more signers are needed (`high_threshold` > 1 for high-risk or bulk operations), the response is `202 {pending: true, manifest_id, have, need}`. Other operators see the request in `GET /api/approvals` and add theirs with `POST /api/approvals/{manifest_id}/sign {assertion}`. The last signature dispatches it.

**Details fixed while building the console:**
- `manifest` (in a 428) and `bundle` (in a proposal) are unpadded base64url strings of the exact bytes.
- The 428 body may also carry `rp_id`, `allow_credentials` (base64url credential IDs) and `user_verification`. The defaults are `location.hostname`, any credential and `"preferred"`. A missing `required` means required.
- `expires_at` values are unix seconds.
- In a proposal, `recovery` lists keys to **add**, and every recovery key of the current bundle is carried forward. Retiring one takes an explicit `remove_recovery_ids` (the console only ever sees `recovery_ids`, never the public keys).

**Grants for streaming features.** Shell and remote desktop are WebSockets, which cannot answer 428, and the file browser issues many requests.
- Before opening a feature, the console calls `POST /api/agents/{id}/grant {ops}`, using the 428 flow; for example `["shell.open"]`, `["desktop.start"]` or `["fs.list","fs.read"]`.
- The server keeps the grant per user and agent until it expires and attaches it to the matching requests.
- The response is `{expires_at}`, or `{required: false}` when no bundle applies.

**Standing approvals** (3B):

| Route | Body → Response |
| :--- | :--- |
| `GET /api/approvals/unsigned?org=` | → objects that run unattended without a valid approval: `[{type, id, name, reason: "missing" \| "expired" \| "content changed"}]`. Types: `task`, `automation`, `patch_policy`, `catalog_item`, `baseline`. |
| `POST /api/approvals/objects/{type}/{id}/sign` | Uses the 428 flow with a `standing` manifest built from the object's current content → `{expires_at}` |

Saving such an object never blocks on a signature. An edit changes the content hash, so the object becomes unsigned; the console offers to sign it straight after saving, and it is listed in Review & sign. Until it is signed, `audit` runs it unsigned and reports it, and `enforce` refuses it on the agents.

---

## 5. Tasks

### 3A — Signed actions (foundation)
1. **`internal/actionauth`** (new, pure Go, shared by server and agent): manifest types and a restricted JCS encoder; the WebAuthn assertion verifier (ES256 / EdDSA / RS256); bundle types and update rules; the class table; the nonce store. Exhaustive tests use software-generated assertions, including every negative case in §3.2, plus replay, expiry, wrong target or org, unknown credential, threshold not met, and one owner with two keys counted once.
2. **Agent:** enforcement in `Agent.dispatch`, ahead of its fast path; executing the payload from the manifest; filtering unapproved baseline specs out of `agent.config`; grant sessions; the `trust.update` handler; storing the bundle and nonces; security events.
3. **Server:**
   - WebAuthn registration and credential storage (evaluate `go-webauthn/webauthn`, which must be confirmed CGO-free, or a minimal own parser);
   - bundle management (first bundle, add or remove signer, recovery public key, mode with the enforce guard);
   - the manifest builder and pending-manifest store;
   - the 428 flow on protected handlers;
   - attaching `A` in the hub;
   - alerts on security events.
4. **Console:**
   - a Security keys page (register, list, remove);
   - recovery-key generation (shown once);
   - the 428 interception in `request()` with a dialog showing what will be signed;
   - the bundle / mode page.
5. **End-to-end tests that import the production packages** (unlike the Phase 2 specification suite), using an in-process server and agent with a software authenticator. They cover:
   - a signed run succeeds;
   - an unsigned run is rejected in enforce and logged in audit;
   - a replay is rejected;
   - bundle rotation;
   - recovery;
   - the enforce guard.

### 3B — Standing approvals
Constraint checking on the agent. Signing on create or edit for the scheduler, automations, patch policies and the software catalog. The Review & sign page. Portal runs carry the catalog item's standing approval.

### 3C — Transparency log
The `tlog`-backed log, tree heads, proof endpoints, agent proof verification and consistency tracking, `executed.log`, and the audit-row leaves.

### 3D — Out-of-band signer and M-of-N (design first)
### 3E — QUIC (deferred)

---

## 6. Invariants and verification

- `CGO_ENABLED=0`. Every new dependency is checked for cgo before adoption.
- Fail closed in `enforce`; **never** isolate or disable networking because of a signature failure.
- Private keys never reach the server: credential private keys stay in the authenticators, and the recovery private key is shown once in the browser.
- Tests for this phase import the production packages.
- Existing invariants are unchanged (hidden PowerShell windows, no `GetDC(NULL)` / `SendInput` in backstage).

---

## 7. Risks and open questions

| Risk | Handling |
| :--- | :--- |
| **WebAuthn needs a hostname.** An IP address is not a valid RP ID, so a console opened at `https://192.168.1.10:8443` cannot register or use keys | The Security keys page detects this and explains it; use a DNS / MagicDNS name (e.g. with `tailscale cert`) |
| **WebAuthn needs a trusted certificate.** Chromium refuses WebAuthn on pages with certificate errors, which includes the default self-signed certificate until it is trusted (to be confirmed in 3A.4) | Detected and explained in the console (`isSecureContext`, availability probe); trust the server certificate on operator machines, or use an operator-supplied or Tailscale certificate |
| Trust-on-first-use windows at enrollment and the first bundle | Documented; optional `--trust-pin`; security event logged |
| Blind signing until 3D | Documented in the console's signing dialog and in `docs/SECURITY.md` |
| Lockout | Enforce requires a recovery key; the console nags until each signer has two credentials |
| Agent clock skew | 5 min tolerance; explicit error; the skew is visible in inventory |
| Keystrokes injected into an already-open shell or desktop | Grants are short and per-agent; end-to-end session encryption is a later item |
| Android app approvals | WebView WebAuthn needs `WebSettingsCompat.setWebAuthenticationSupport` (androidx.webkit) |
| Existing fleets and automations break on upgrade | No bundle means no change; `audit` comes before `enforce`, plus the Review & sign page |

---

## 8. Status and follow-ups (2026-10-23)

**Implemented (3A and 3B):**
- `internal/actionauth`: canonical JSON, WebAuthn assertion verification, trust bundle, class table, standing approvals and replay store.
- Agent enforcement: `internal/agent/trust.go`, with the check in `dispatch` ahead of the fast path, fail-closed handling of a damaged `trust.json`, and baseline approval re-checked before every pass.
- Server: security keys, trust bundles and bundle sync, the 428 signing flow, the approvals queue, grants, standing approvals for every unattended originator, and alerts on security events.
- Console: Security keys card, Trust & signing, the signing dialog, Approvals, and grants before shell, desktop and files.
- `rmm-server trust sign-bundle` for offline recovery.

**Verified with:** unit tests in every package and `internal/server/signed_e2e_test.go`. The latter runs the real server and the real agent with a software authenticator. It checks that:
- the agent refuses an unsigned script sent around the console;
- the 428 → sign → retry flow runs the script on the device;
- a replayed manifest is refused by the agent;
- a fleet update in an org that signs: the agent refuses an unsigned `agent.update` sent around the console, `POST /api/agents/update-batch` runs the 428 → sign → retry flow, the device accepts the signature (and fails only to install, because the test agent has no supervisor), and the consumed manifest is refused as a replay.

`TestTransparencyLogEndToEnd` runs the same pair in `enforce` with `require_log_proof` and the server's `log_key` pinned. It checks that:
- two signed script runs execute, and after each one `log_head.json` verifies against the pinned key, matches its own fields, grows strictly and is a prefix of the server's current head (consistency proof checked with `translog.CheckConsistency`);
- `executed.log` has exactly two lines, the second's `prev` is the SHA-256 of the first, and each `log_index` resolves through `/api/log/entries/{i}` to a `manifest` leaf equal to the manifest that run was signed with;
- after `inventory.refresh` the server's `agents.executed_head` equals the hash of the last line (`GET /api/agents/{id}` shows it as `inventory.executed_head`);
- a validly signed manifest sent without `L`, and one sent with another manifest's leaf index, are both refused with a `log proof` reason, raise a security alert, add no `executed.log` line and leave the device head where it was;
- the `script.run` audit rows carry a `log_index` whose leaf is an `audit` entry for the same action, target and id.

**Not verified:** a real browser with a real security key or passkey, and the certificate and hostname prerequisites in §7.

**Decisions made while implementing:**
- **Device environment.** A signed `script.run` takes only `RMM_*` variables from the envelope, and never overrides a signed one. A standing approval refuses any non-`RMM_*` variable, because it does not bind the environment.
- **Grant lifetime.** Grants last 15 minutes. Action manifests last 5 minutes, or 10 when more than one signer is needed. Standing approvals last 180 days.
- **Unattended agent updates.** The agent's own update check (every 5 minutes, `GET /api/agent/update-check`) used to install whatever URL and hash the server advertised, with no signature behind it. The agent now treats it as an unsigned `agent.update`: in `audit` it still installs and raises a security event once for each advertised binary, and in `enforce` it refuses and reports that once, so in an enforcing org devices update only through a signed push. For devices of orgs in `enforce` mode the server answers `update_available: false, signed_update_required: true` instead of advertising, so a fleet does not alert every five minutes; the device still decides for itself, so a server that advertises anyway gains nothing.

**Follow-ups:**
1. ~~**Uploads (`fs.write`) are limited to 1 MiB in signed orgs.**~~ **Fixed.** In an org with a bundle, uploads go out as unsigned `fs.stage` chunks into a staging area inside the agent's config directory, which the file browser cannot reach. The operator signs `fs.commit {upload_id, path, size, sha256}`. The agent copies the staged bytes beside the destination while hashing them, and renames them into place only on a match. A server that stages anything else, or names a digest it invented, gets a refusal and no file (`internal/agent/files_stage.go`, `internal/server/uploads.go`).
2. ~~**"Update all agents" skips signed orgs.**~~ **Fixed.** `POST /api/agents/update-all` now updates only the orgs that do not sign actions (no bundle, or mode `off`) at once and returns the others as `signed_groups`, one per org and agent build (cut into groups of at most 2000 devices, the most `update-batch` takes), because a manifest names one org and carries one binary; `POST /api/agents/update-batch` sends one group as a single high-risk `agent.update` manifest whose payload `{url, sha256, version}` the device checks against the downloaded binary. The console (Devices → Update Agents, and Server & Fleet Updates) walks the groups and asks for one signature per group, and cancelling a signature stops the loop (`internal/server/update.go`, `web/src/lib/fleetUpdate.ts`). Review findings fixed afterwards: groups are cut at the batch limit; a device is grouped by the architecture in its hello for both handlers (an inventory that disagreed made its whole group unsignable); the build is only looked up by a known OS and architecture name and only a regular file counts, so a device cannot steer the lookup to another file; the batch reply says whether it was signed, the console counts unsigned continuations in `audit` mode as unsigned, shows each failure with the device and reason, keeps offline devices apart from failures, reports online devices that have no build, and disables Update Agents while a run is going; the audit entry names the operator who asked (not whoever completed the signatures) and the first failures; a device that already runs the pushed build answers as done without downloading or restarting (the signature is still spent, since it is asked for before any device is); and the unattended poll gate is tested through `checkAutoUpdate` itself (`internal/agent/autoupdate_test.go`). Also fixed: the audit entry of every signed action, not only a fleet update, names the address the operator asked from (`withIssuer` carries it to the closure that runs the action); `update-all` leaves a `fleet.update_all` entry; a mixed-build `update-batch` names the odd device out; the security alert for the unattended poll says it was the poll; and the signing dialog shows an `agent.update` payload whole when it carries more than `url`, `sha256` and `version`. Both open points are fixed afterwards: `POST /api/agents/{id}/update` now waits as long as the batch does (`fleetUpdateReplyWindow`, on a context of its own) and answers 200 `installing: true` for a device that is still staging the binary, 409 for an offline one and 400 with the device's reason for any other error; and `handleAgentUpdateCheck` records the lower-cased digest each device reports (`agents.binary_sha256`, `binary_sha256_at`, migration 16, only when it is 64 hex characters, and ignored once it is older than 24 h), so `update-all` leaves devices already on the build out (counted in `up_to_date`, never put in `signed_groups`), `update-batch` drops them before the manifest is built so the signature names only the stale devices (a batch of current devices answers 200 with `up_to_date` and no 428), and the single-device update answers `up_to_date: true` before any signature unless `?force=1` (`DB.recordBinaryDigest`, `DB.runsBuild`; `fleetUpdate.ts` says "N devices already run this build"). The console has no single-device update button, and `api.dispatchAgentUpdate` still has no callers.
3. ~~**Runs queued for an offline device** are released after their 5-minute manifest has expired.~~ **Fixed.** A signed run is never queued: in an org with a bundle, `planRuns` and `startOneRun` answer a library script for an offline device with `ErrSignedRunOffline` (409 from the single-device handler, `error: ...` in the per-device outcomes) before any signature is asked for, and ad hoc bodies keep `ErrAgentOffline`. `runTracker.Start` repeats the check when `req.Auth` is set, because the device can drop between the challenge and the last signature. Unattended runs still queue, and now keep their standing reference: migration 15 adds `script_runs.standing` (`<type>:<id>`), and `releaseQueued` re-derives the approval from it, falling back to `task_id` for older rows. That fallback never worked before, because `releaseQueued` scanned `task_id` into a throwaway variable (`internal/server/runs.go`, `internal/server/api_scripts.go`). Fleet updates deliberately include online devices only, so this concerned runs, not updates.
4. ~~**Review & sign signs one approval per click.**~~ **Fixed.** A patch policy that reboots, or a catalog item, holds several approvals. `GET /api/approvals/unsigned` rows now carry `org` and `purpose`, and the row button signs exactly its own unit (`signObject(type, id, {org, purpose})`); signing a unit that is already approved answers `already_approved` without asking for a signature. **Sign all** walks the listed rows one dialog at a time, stops when a dialog is cancelled, and reports signed, pending and failed in one toast (`web/src/lib/signAll.ts`, `web/src/pages/Approvals.tsx`). `remaining` used to count only units of the asked purpose, so it was always 0 when a purpose was given; it now counts every other unit of the object that still needs a signature (`internal/server/standing.go`).
5. ~~**3C transparency log**~~ **Built.** `internal/translog` (a `tlog` Merkle log with Ed25519 signed heads, SQLite tables `tlog_leaves` and `tlog_hashes`, migration 17) records every released manifest, every activated bundle and every audit row. The hub completes an inclusion proof and a consistency proof per send; the agent verifies them in `authorize`, pins the head in `log_head.json` and keeps the hash-chained `executed.log` (`internal/agent/translog.go`, `trust.go`), whose head rides in hello and inventory. `policy.require_log_proof` and the bundle's `log_key` are validated by the server (`checkLogBinding`). `GET /api/log/head|proof|consistency` need no session, `GET /api/log/entries/{index}` needs an admin. `rmm-server log head|verify` checks from outside (`cmd/rmm-server/log.go`), and the console has the log card, the **Require log proofs** switch, the device log heads and the audit **Log #** column. Design and status: `docs/plans/2026-10-24-phase3c-transparency-log.md`.
6. **3D out-of-band signer and M-of-N UX, 3E QUIC**, as planned.
