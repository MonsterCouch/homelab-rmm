# Phase 3D: out-of-band signer and M-of-N (design, 2026-10-24)

Refines §3.9 of `2026-10-06-phase3-signed-actions.md`. Of the three candidates there, this builds the first and third as one tool: `rmm-signer`, a Windows command-line program that signs with the native WebAuthn API (`webauthn.dll`, Windows Hello and security keys). The Android approval screen stays open.

## Why

Today the browser renders what you sign with code the server served (T3, blind signing): a server that is compromised can show one manifest and sign another. `rmm-signer` fetches the pending manifest bytes, decodes and prints them itself, and signs exactly those bytes with a credential the operator registered on the Security keys page. The server contributes nothing to what the operator sees except device names, which the tool labels as such. The same credentials work, because a WebAuthn credential is bound to the RP ID and the authenticator, not to the client program.

## The tool

`cmd/rmm-signer`, CGO_ENABLED=0, windows/amd64 and windows/arm64 (built by the Makefile next to the server; other platforms build but answer "signing needs Windows" for `sign`).

```
rmm-signer login   --server URL [--user NAME]          password (and TOTP code when asked) from the terminal; keeps the session cookie in %APPDATA%\homelab-rmm\signer.json (0600, expiry recorded)
rmm-signer list    --server URL                          what is waiting for this operator's signature
rmm-signer show    --server URL ID                       decode and print one manifest without signing
rmm-signer sign    --server URL ID [--yes]               print it, ask "Sign? [y/N]", sign with Windows Hello or a key, post the assertion
rmm-signer sign    --server URL --all                    the same for every entry, one at a time
rmm-signer selftest                                      report the WebAuthn API version and whether a platform authenticator is present; no UI
```

What `show` and `sign` print, from the manifest bytes: kind, id, organization, issuer, issued and expiry times, targets (ids, with the device names the server lists for them marked "names from the server"), and the payload in full: for `script.run` the language, timeout, every environment variable and the whole body; for `agent.update` url, sha256 and version; for a grant the ops; for a standing approval the constraints. Anything else is printed as indented JSON. The server's `summary` is printed last, marked as the server's words.

Signing: clientDataJSON is `{"type":"webauthn.get","challenge":"<b64url of SHA-256(manifest bytes)>","origin":"<origin of --server>","crossOrigin":false}`; the challenge is the digest of the exact manifest bytes (`actionauth.Challenge`), as the console does it. The origin must be one the bundle trusts, so the entry carries the bundle's origins and the tool refuses with a plain sentence when `--server`'s origin is not among them. The RP ID and the operator's credential ids come with the entry. User verification follows the entry's `user_verification`.

## Package `internal/winwebauthn`

Pure-Go syscalls into `webauthn.dll` (`windows.NewLazySystemDLL`, as the desktop package does for D3D), 64-bit only:

```go
type Options struct { RPID, Origin string; Challenge []byte; AllowCredentialIDs [][]byte; UserVerification string /* required|preferred|discouraged */; Timeout time.Duration }
type Assertion struct { CredentialID, AuthenticatorData, ClientDataJSON, Signature []byte }
func APIVersion() (uint32, error)                       // WebAuthNGetApiVersionNumber
func PlatformAuthenticatorAvailable() (bool, error)     // WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable
func GetAssertion(ctx context.Context, o Options) (*Assertion, error) // WebAuthNAuthenticatorGetAssertion with the foreground window as owner; cancellation through WebAuthNCancelCurrentOperation when ctx ends
func ClientDataJSON(challenge []byte, origin string) []byte
```

Structs follow `webauthn.h` from github.com/microsoft/webauthn at the lowest version that carries what is needed (client data v1, credential v1, get-assertion options v4 for `pAllowCredentialList`, or v1 with `CredentialList` when the allow list is the plain credential array). Every struct is laid out with explicit padding and checked by a test against `unsafe.Sizeof` expectations from the header. Errors come back through `WebAuthNGetErrorName`. On other platforms every function returns `ErrUnsupported`.

## Server

- `GET /api/approvals` also lists the caller's own entries that have no signature yet (`have: 0`), so a challenge the operator chose to sign out of band is reachable; everyone else's unsigned entries stay invisible. Every entry gains `rp_id`, `origins`, `allow_credentials` (the caller's credential ids in that organization's bundle), `user_verification`, `signers` (owner names so far) and `kind`, `op`, `ops`, `targets`, `target_names` (id to display name, for the ids the caller may see).
- `GET /api/approvals/{id}` returns one entry in the same shape (404 when the caller may not sign it).
- Signing stays `POST /api/approvals/{id}/sign {assertion}`; when the last signature lands, the action runs and its response is what the signer receives, as today.
- A challenge entry already lives until its expiry whether or not the dialog was cancelled, so "sign later" needs no new state; the console only has to tell the operator the id.

## Console

- The signing dialog gains **Sign with rmm-signer**: it closes the dialog with the manifest id and the command `rmm-signer sign --server <origin> <id>` in a toast that stays until dismissed, and the request fails with a `SigningParked` error that callers treat like a cancel (nothing was sent).
- Approvals shows the operator's own unsigned entries ("waiting for your signature, 0 of N"), the names of who has signed, and for every entry a copyable `rmm-signer sign` command.

## Security notes

- The tool trusts the server for nothing but device names and the list itself; what is signed is what is printed, byte for byte.
- The session cookie file has the same power as a logged-in browser; it is 0600 and `rmm-signer logout` deletes it.
- A compromised server can still ask for signatures on manifests it invents; the operator reads them before signing, which is the point.
- M-of-N: thresholds are unchanged. The tool is simply another signer client, so a second operator can approve from their own machine with their own key.

## Out of scope

The Android screen; registering credentials from the tool (use the Security keys page); passkey creation.

## Status (2026-10-24)

Implemented: `internal/winwebauthn`, `cmd/rmm-signer` (with a `signer` Makefile target, windows/amd64 and windows/arm64), the server's own-unsigned entries and `GET /api/approvals/{id}` (`internal/server/signing.go`, `approvals_oob_test.go`), and the console's "Sign with rmm-signer" button, parked-request toast and Approvals changes. Tests pass in `internal/winwebauthn`, `cmd/rmm-signer` and `internal/server` (`Approval|Sign`); the console typechecks and builds.

**Verified 2026-11-01:** `login` (password on stdin), `list` and `show` against a throwaway server decode and print a pending manifest exactly as the console shows it; `sign --yes` reaches `WebAuthNAuthenticatorGetAssertion` and Windows opens "Choose a passkey — Passkey for localhost" offering a phone (hybrid) and a security key, so the v3 options are accepted on API version 9; cancelling the prompt returns "signing was cancelled at the Windows prompt; nothing was sent". The console's "Sign with rmm-signer" button and the 428 dialog were exercised in Edge. **Not verified:** a completed assertion from a hardware key or phone (none is available on the development machine; `selftest` prints `api_version=9 platform_authenticator=false`). Cancelling a prompt relies on the DLL accepting v3 options on API version 3 or higher; if it does not, the call returns only when the prompt does.

**Deviations from the design above:**
- **The challenge is the SHA-256 of the manifest bytes, not the bytes.** The verifier (`actionauth.Challenge`) and the console (`web/src/lib/webauthn.ts`) use the digest, and the server would reject the other form. clientDataJSON therefore carries base64url of that digest. The "Signing" paragraph above is wrong on this point.
- **`ops` is also listed** on every entry, as the server section names it.
- **The tool checks more than designed:** it refuses an entry whose manifest bytes carry another id than the one listed, never sends a session saved for another server, never follows redirects, and prints every server or manifest string with control and bidi characters escaped. A `script.run` or `agent.update` payload with unknown fields is printed as full JSON.
- **Commands:** flags may come before or after the id; `--server` falls back to `RMM_SERVER`, then to the server of the last login; `logout` also calls the server's logout endpoint; exit codes are 0, 1 (failure) and 2 (usage). `sign --all` skips a declined entry and stops with exit 1 on a server or signer failure.
- **Toast:** the console's toast gained sticky and copy support for the parked-request message.

**Left open:** an `http://` server is allowed for development (loopback only for `login`) but its origin never matches a bundle's `https://` origins, so signing against it is refused; the 64-bit assumption is enforced by the layout tests, not a build constraint; the MSI does not carry rmm-signer (the archives and `SHA256SUMS` do, and `rmm-signer version` prints the stamped version). A software-key test (`cmd/rmm-signer/clientdata_verify_test.go`) proves the clientDataJSON the tool builds is what the verifier accepts, binds the manifest bytes and refuses another origin; the native call itself is still unexercised.
