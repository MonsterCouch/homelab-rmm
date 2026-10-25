# Phase 3C: transparency log (design, 2026-10-24)

Refines §3.8 of `2026-10-06-phase3-signed-actions.md`. Decisions here win over that sketch where they differ.

## Goal

The server cannot run a signed action on a device without leaving a record that it cannot later remove or rewrite, and a device can prove what it ran. Concretely:

- every manifest the server relays (action, grant, standing), every trust bundle it activates and every audit row is a leaf of an append-only Merkle log on the server, with signed tree heads;
- a device that holds a bundle with `log_key` verifies, for every protected request it receives, that the manifest is in the log (inclusion proof against a signed head) and that the log only grew since the last head it accepted (consistency proof). A bad proof is refused in `enforce` and reported in `audit`; a missing proof is refused only when the bundle policy sets `require_log_proof`;
- each device keeps a hash-chained `executed.log` of the manifests it ran and reports its head, so the server cannot quietly drop one;
- an operator can check from outside (`rmm-server log verify`) that the log only grew.

## Library

`golang.org/x/mod/sumdb/tlog` (hashing, proofs: `StoredHashes`, `TreeHash`, `ProveRecord`, `CheckRecord`, `ProveTree`, `CheckTree`, `FormatTree`, `ParseTree`) and `golang.org/x/mod/sumdb/note` (signed tree heads, Ed25519). Both are pure Go. Leaf hash is `SHA-256(0x00 || data)`, node hash `SHA-256(0x01 || left || right)` (RFC 6962 as tlog does it).

## Package `internal/translog`

```go
// Storage is append-only. AppendLeaf stores the leaf and the hashes tlog.StoredHashes
// returned for it in one transaction; indexes are dense from 0.
type Storage interface {
    Size() (int64, error)
    AppendLeaf(kind string, data []byte, hashes []tlog.Hash) (index int64, err error)
    ReadHashes(indexes []int64) ([]tlog.Hash, error) // tlog.HashReader
    ReadLeaf(index int64) (kind string, data []byte, ts int64, err error)
}
// SQLStorage implements Storage over *sql.DB with tables tlog_leaves(idx, kind, data, ts)
// and tlog_hashes(idx, hash). Schema is the DDL (the server's migration runs it).
// MemStorage is for tests.

type Log struct { /* mu, storage, note.Signer, verifier key */ }
func Open(st Storage, keyFile string) (*Log, error) // loads or generates the key file (0600): line 1 signer key, line 2 verifier key, name "homelab-rmm-log"
func (l *Log) VerifierKey() string                  // the note verifier key, e.g. "homelab-rmm-log+9f3c1a2b+AAAA..."; this is what bundles pin as log_key
func (l *Log) Append(kind string, data []byte) (int64, error)
func (l *Log) Head() (tlog.Tree, []byte, error)     // tree and the signed note; cached per size, invalidated by Append
func (l *Log) ProveInclusion(index, size int64) (tlog.RecordProof, error)
func (l *Log) ProveConsistency(from, to int64) (tlog.TreeProof, error)
func (l *Log) Leaf(index int64) (kind string, data []byte, ts int64, err error)

// Verification, shared by the agent and the CLI (no Log needed):
func ParseHead(verifierKey string, signed []byte) (tlog.Tree, error)
func CheckInclusion(t tlog.Tree, index int64, leaf []byte, proof tlog.RecordProof) error
func CheckConsistency(old, new tlog.Tree, proof tlog.TreeProof) error
func EncodeProof(p []tlog.Hash) []string / DecodeProof([]string) ([]tlog.Hash, error) // base64 std
```

Tree size 0 has no head to sign: `Head()` on an empty log returns a tree with N=0 and an empty hash, signed like any other.

## Leaves

Leaf data is canonical JSON (`actionauth.CanonicalizeJSON`), so both sides can rebuild it byte for byte.

| kind | data |
|---|---|
| `manifest` | `{"kind":"manifest","manifest":"<b64 exact manifest bytes>","sigs":[<protocol.Assertion as sent in ActionAuth.S>]}` built by `actionauth.ManifestLeaf(auth *protocol.ActionAuth) ([]byte, error)`, which the agent uses to rebuild the leaf from the ActionAuth it received. The signature set is the final one at release. |
| `bundle` | `{"kind":"bundle","org":...,"epoch":...,"bundle":"<b64>","sigs":[...],"recovery_sigs":[...]}` at activation |
| `audit` | `{"kind":"audit","id":...,"ts":...,"user":...,"ip":...,"action":...,"target":...,"details":...}` for every `DB.Audit` row, appended right after the insert; `audit.log_index` stores the index |

An action manifest is logged once, when it is released (the last signature arrives), in both dispatch sites of `signing.go` (`p.run(w, withIssuer(r, p), p.auth())`): `p.logIndex` is set before `p.auth()` builds the ActionAuth. A standing approval is logged once in `putApproval` (`approvals.log_index`), and `approvalAuth` carries that index. Grants go through the same pending path.

## Wire

```go
// protocol
type LogProof struct {
    Head        string   `json:"head"`                  // base64 of the signed tree head note
    Index       int64    `json:"index"`                 // the manifest's leaf
    Proof       []string `json:"proof"`                 // inclusion proof, base64 hashes
    From        int64    `json:"from,omitempty"`        // size of the head the consistency proof starts from (the device's last head), 0 = none
    Consistency []string `json:"consistency,omitempty"`
}
ActionAuth.L *LogProof `json:"l,omitempty"`
Hello.LogSize int64 `json:"log_size,omitempty"`          // size of the last head the device accepted
Hello.ExecutedHead string `json:"executed_head,omitempty"`
Inventory.ExecutedHead string `json:"executed_head,omitempty"`
Envelope.Log int64 `json:"log,omitempty"`                // on an agent's reply to a protected request: the size the device holds now
// actionauth
Policy.RequireLogProof bool `json:"require_log_proof,omitempty"`
Bundle.LogKey (exists): the note verifier key string of the server's log
```

The handler sets only `L: &LogProof{Index: i}`. The hub completes the proof **per send** (`agentConn.send`, under `writeMu`, on a copy of the struct, never on the shared pointer): current head and inclusion proof at that head, and a consistency proof from `ac.logSize` when `0 < ac.logSize < N`. This keeps heads monotone per connection even when two manifests are dispatched concurrently to thousands of devices. `ac.logSize` comes from the hello and is updated from `Envelope.Log` on every reply. The hub must not hold `h.mu` while computing proofs. When the server has no log (tests, or the log failed to open: the server refuses to start in that case, so only tests) `L` stays nil.

## Device

`internal/agent/trust.go`, after `Verifier.Check` allowed a request with a manifest (`env.A != nil`):

1. `bundle.LogKey == ""`: if `policy.require_log_proof`, refuse "the trust bundle requires log proofs but pins no log key"; else ignore `L`.
2. `L == nil`: refuse "log proof required" if `require_log_proof`, else allow.
3. Otherwise: parse the head with `LogKey` (bad signature: refuse); rebuild the leaf with `ManifestLeaf`; `CheckInclusion`. Let S be the stored size (`ConfigDir()/log_head.json`, `{size, hash, note}`): S == 0 → accept (first head; log it at info level); N == S → hashes must match; N > S → `L.From` must equal S and `CheckConsistency` must pass; N < S → refuse "the server presented a log head older than the last one this device accepted". On success persist the head when N > S.

Failure handling mirrors `Decision`: `enforce` refuses with `refused: log proof: <reason>` and a security event; `audit` allows and raises the event once per manifest id. The reply envelope (and the refusal) carries `Log: S`.

`executed.log` (`ConfigDir()/executed.log`): one JSON line per executed manifest `{"prev":"<b64 sha256 of the previous line, "" for the first>","ts":...,"manifest_id":...,"op":...,"log_index":<index or -1>}`, appended in `authorize` when `dec.ManifestID != ""` and the request is allowed. The head is the base64 SHA-256 of the last line, kept in memory and reported in hello and inventory; the server stores `agents.executed_head`.

## Server

- Migration (after the one the update items add): `tlog_leaves`, `tlog_hashes`, `audit.log_index INTEGER NOT NULL DEFAULT -1`, `approvals.log_index INTEGER NOT NULL DEFAULT -1`, `agents.executed_head TEXT NOT NULL DEFAULT ''`.
- `Server.tlog` opened at startup from `<data dir>/log.key`; a server that cannot open its log does not start. `DB.Audit` appends through a hook the server sets (`db.logAppend`), nil in DB-only tests.
- Bundle validation on activation and on proposal: `require_log_proof` without `log_key` is refused; a `log_key` other than this server's is refused with a message naming both. Every bundle the server composes (`trust.go` ~line 227 and every edit path) carries `log_key`.
- Endpoints, no session needed for heads and proofs (they hold only hashes and sizes), admin for leaf content:
  - `GET /api/log/head` → `{size, hash, key, note}` (`note` base64 of the signed head)
  - `GET /api/log/proof?index=` → `{size, hash, note, index, proof}` at the current head
  - `GET /api/log/consistency?from=&to=` → `{from, to, proof}` (`to` defaults to the current size)
  - `GET /api/log/entries/{index}` (admin) → `{index, kind, data, ts}` with `data` base64
  - audit listing rows carry `log_index`.
- CLI `rmm-server log verify --server URL --key VERIFIER_KEY [--state FILE]`: fetches the head, checks the signature, checks consistency with the head in the state file (first run pins it), prints size and hash, writes the state. Exit 1 on any failure with a plain sentence. `rmm-server log head --server URL` prints the head and key.

## Console

Trust & signing: a "Transparency log" card (size, head hash clipped, key, "copy key", the `rmm-server log verify` one-liner), a **Require log proofs** checkbox in the policy editor, and the executed-log head (clipped, with a title holding the full value) in the Devices table. Audit page rows show the leaf index.

## Out of scope

Serving tiles, mirroring to another host, and the console verifying proofs itself (the CLI does, in Go, with the same code as the agent).

## Status (2026-10-24)

Implemented as designed: `internal/translog` (package, `Schema`, `SQLStorage`, `MemStorage`), migration 17 (the two log tables, `audit.log_index`, `approvals.log_index`, `agents.executed_head`), the hub completing proofs per send, the agent check and `executed.log`, the four `/api/log` endpoints, `rmm-server log head|verify`, the console card, switch, device heads and audit column, and `TestTransparencyLogEndToEnd`. The update items shipped first and took migration 16.

Deviations and decisions made while building:
- **Wording and scope on the device.** The missing-proof refusal reads "the request carried no proof that the manifest is in the transparency log" rather than "log proof required". The check runs only when `Check` allowed the request, the manifest verified and the class is neither read nor config; `trust.update` is exempt so a bundle can still fix a bad `log_key`. In `audit` mode an unverified manifest is skipped. A damaged `log_head.json` refuses every protected request (reads still work) whenever the bundle pins a `log_key`, and deleting the file recovers.
- **A refused manifest burns its nonce.** `Check` spends the nonce before the proof is looked at, so a manifest refused for a bad proof cannot be retried; the server must obtain a fresh signature.
- **`log_key` rotation.** A bundle that changes `log_key` makes the stored head fail the consistency check, and the device refuses until `log_head.json` is deleted. Not designed for yet.
- **`executed.log` details.** `log_index` is -1 when there was no `log_key`, no `L`, or the proof failed in audit mode. A write failure is logged and does not block the request. Start-up reads only the last 64 KB and parses only the last line; a torn line or a missing file starts a new chain.
- **Fail closed on manifests.** If the log cannot take a manifest at release, the dispatch answers 500 and sends nothing, and `putApproval` stores nothing. A failed audit append keeps the row with `log_index` -1. A failed bundle-leaf append after activation is logged and not undone, because the bundle is already in force.
- **Bundles.** The server always pins its own key, so a bundle without `log_key` cannot come from the proposal endpoint; `checkLogBinding` runs when a bundle is built and when a stored proposal is loaded for signing, recovery or activation.
- **Server odds and ends.** An empty `executed_head` in a hello or inventory leaves the stored head alone, so older agents do not wipe it. Audits written by CLI tools through `OpenDatabase` have no log hook and keep -1. `ProveConsistency` is only called for `0 < from < N`.
- **Dependencies.** `golang.org/x/mod` is now a direct requirement; `go mod tidy` also moved `x/mod` to v0.42.0 and `x/tools` to v0.51.0 in `go.sum`.

Fixed after review (same day): `/api/agents` rows carry `executed_head` as a field; the signing dialog's bundle diff shows `require_log_proof` and `log_key`; `ParseBundle` itself refuses an unparsable `log_key` and `require_log_proof` without a key, so devices and the offline recovery signer refuse such a bundle too; each connection remembers the largest head it was sent and chains the next consistency proof from it, every frame from the device carries the size it holds, and a "log proof" refusal resets the chain to what the device reported, so back-to-back signed requests and long-running scripts no longer trip the strict `From` check (one request is lost only when a manifest fails signature verification after a newer head was sent; the next one goes through); standing approvals stored before the log are logged on first dispatch; `/api/log` endpoints answer a plain sentence on internal errors; a reported `executed_head` must be base64 of 32 bytes and a change of the stored head leaves a `device.executed_head` audit row; the leaf count is kept in memory.

Open:
- The console pages have not been opened in a browser.
- `log_key` rotation and a nonce spent on a manifest refused for a bad proof, as noted above.
