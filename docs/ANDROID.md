# Homelab RMM for Android

A pinned Kotlin WebView shell around the existing React console. One Gradle project at `android/`, one WebView per server loaded top-level from the real server origin, SHA-256 leaf-certificate pinning as the only trust authority, a biometric gate, native bottom navigation, and a mobile-responsive pass on the console itself.

Scope: v1 requires **zero server changes**. Realistic effort **18–22 days**, of which the console pass is ~40%. The 6-day and 25-day figures from earlier drafts are both wrong and must not be planned against.

---

## 1. Overview

**Goal.** Manage the homelab fleet from a phone over Tailscale: triage an alert, restart a service, run a script, glance at a device. Four 30-second jobs.

**Approach.** The console is already same-origin, relative and cookie-authenticated; it needs no server-side adaptation to run in a WebView. The native layer owns exactly what the web cannot do on a phone:

- identity (certificate pin + biometric lock),
- navigation chrome (bottom bar + one-tap server switcher replacing the console's off-canvas drawer *inside the shell only*),
- hardware (file chooser, downloads, clipboard, fullscreen, IME insets, keep-awake),
- failure (unreachable screen, pin-mismatch dead end, Connection test).

Everything else stays in the console, where the mobile pass also benefits tablets and desktop touch.

**Gating unknown.** No device has confirmed that a `wss://` handshake to a pinned self-signed host reaches `WebViewClient.onReceivedSslError`. The Chromium path is traced end to end (`services/network/websocket.cc OnSSLCertificateError` → `URLLoaderNetworkServiceObserver` → `content/browser/storage_partition_impl.cc:2537` → `content/browser/ssl/ssl_manager.cc:108/368` → `android_webview/browser/aw_content_browser_client.cc:548`, which **ignores `is_primary_main_frame_request`** → `AwContentsClientBridge.java:170`), but source reading is not a test. **All other Android work is gated on task A2 (the half-day spike).** If it fails, Terminal and Remote Desktop are dead inside the app and the fallback is operator-side (`tailscale cert`), not an in-app relay.

**Repo layout.** `android/` is its own Gradle build with its own `settings.gradle.kts`, so `go build ./...` and `npm run build` are untouched. The Makefile gains an optional `apk:` target that does **not** hang off `all` (the Go/web build must stay usable on a machine with no Android SDK).

**Application id:** `io.github.monstercouch.homelabrmm` — reverse-DNS from the Go module path, a namespace the owner controls. **Permanent**: the AndroidKeyStore key that seals the server list is bound to the app UID and signing identity, so changing it later destroys every stored pin.

---

## 2. Security model

### 2.1 The rule, stated once

The SHA-256 fingerprint of the server's **leaf certificate DER**, supplied out of band and confirmed by a human, is the only thing that grants trust. Not the hostname, not the issuer, not the expiry, not the system CA store, not TOFU.

The stored pin is lower-case hex, no colons — byte-identical to `Fingerprint()` at `internal/server/tls.go:45-49` (`hex(sha256(der))`) and to what every agent already compares at `internal/agent/conn.go:36`. Chromium hands Java the same bytes (`aw_contents_client_bridge.cc:143` takes them from `cert->cert_buffer()`). So the 64-char string the console prints, the string every agent pins, and the string the phone stores are literally the same string.

### 2.2 Non-negotiable rules

1. **`error.primaryError` is never consulted.** `localHostnames()` (`internal/server/tls.go:111-124`, verified) returns only `localhost`, `127.0.0.1`, `os.Hostname()` (short name) and non-loopback addresses where `ipn.IP.To4() != nil` — IPv6 is filtered out entirely, and a MagicDNS name appears only if it was the host of `--public-url` on **first run** (`server.go:143-152` seeds the setting before the cert block). **`SSL_IDMISMATCH` on top of `SSL_UNTRUSTED` is the NORMAL case.** Any handler that checks `primaryError` or `hasError()` rejects every legitimate connection. `SSL_EXPIRED` is likewise accepted when the pin matches and surfaced as a banner, matching the agent's `InsecureSkipVerify: true` + pin-only `VerifyPeerCertificate`. This justification must be carried into `docs/SECURITY.md` next to the existing "verify a fingerprint out of band" guidance, or the next reader files it as a bug.
2. **Host-scoped.** The pin is looked up by the URL's host. A redirect can never inherit a pin. Unknown host ⇒ `cancel()`.
3. **Empty pin (`trustMode = SYSTEM`) ⇒ Rejected.** A publicly-trusted leaf raises no SSL error at all, so if `onReceivedSslError` fires for an entry stored with `fp == ""`, that is a genuine failure. Fail-closed by construction, not by remembering a branch.
4. **No bypass exists, in any build variant.** The mismatch screen is a dead end: Switch server / Forget server / Re-pair. No "proceed anyway", no long-press escape, no `BuildConfig.DEBUG` branch in the pin path. A source-scan unit test asserts `handler.proceed()` occurs **exactly once** in the whole tree.
5. **`SslErrorHandler` contract.** `proceed()` or `cancel()` must be called **exactly once per handler, on the UI thread**. A path that returns without calling either hangs that load forever with no error. The callback is **not** once-per-session: `AwSslHostStateDelegate` keeps allow decisions in an in-memory `std::map<SHA256HashValue, net::Error>` and `CertPolicy::Check` requires no *additional* errors versus when allowed, so it re-fires after every process start and can re-fire per host. The handler must therefore be an **idempotent, side-effect-free pure function of (URL host, stored pin, leaf DER)**.
6. **Never build pinning on `shouldInterceptRequest`** — it never sees WebSocket traffic.
7. **Never add a service worker to the console.** `ssl_manager.cc:132` denies with no client callback when there is no WebContents, and the comment names service workers. Verified: zero `serviceWorker`/`manifest`/`workbox` references in `web/src`, `web/index.html`, `web/public`, `web/vite.config.ts`. This is a standing constraint, recorded in the console README.

### 2.3 Storage integrity

The server list is not secret (the console publishes the fingerprint). Its **integrity** is the whole model: a silently mutated pin is a silently accepted MITM.

- AES-256-GCM under AndroidKeyStore alias `rmm_trust_v1`: `setBlockModes(GCM)`, `setEncryptionPaddings(NONE)`, `setKeySize(256)`, `setRandomizedEncryptionRequired(true)`.
- **Deliberately NOT `setUserAuthenticationRequired`** — the picker must render before the biometric prompt.
- **Deliberately NOT `setUnlockedDeviceRequired`** — it silently breaks the moment the v1.1 alert poller needs to read the server list while the device is locked. (If it is ever wanted, split into an unlocked-device-required key for pins and a plain key for what a worker needs.)
- Blob layout `[12-byte IV][ciphertext || 16-byte tag]`, stored in a single `byteArrayPreferencesKey("servers.v1")` in DataStore Preferences.
- **`AEADBadTagException` on read ⇒ storage tampered**: wipe the blob, wipe every WebView profile, force re-pairing. Never fall back to a plaintext read, never degrade to "use whatever bytes are there".
- **Escape hatch:** an explicit "Export server list" (plain text, url + fp + label) in App settings. The keystore key dies with an uninstall or a signing-identity change; re-pairing must not be a scavenger hunt through the console.

### 2.4 Native attack surface

- `INTERNET`, `ACCESS_NETWORK_STATE`, `USE_BIOMETRIC` at install. `CAMERA` declared with `<uses-feature android:required="false"/>` and requested only at the instant of scanning; denying it forever leaves the app fully usable via manual entry.
- `<queries><package android:name="com.tailscale.ipn"/></queries>` — **mandatory**. Without it, at minSdk 30 Android 11 package-visibility filtering makes `getLaunchIntentForPackage("com.tailscale.ipn")` and `resolveActivity` return **null**, and the "Open Tailscale" button silently does nothing.
- `android:allowBackup="false"` plus `android:dataExtractionRules="@xml/data_extraction_rules"` with an **empty ruleset file that must actually exist** — a missing referenced resource fails resource linking in `assembleRelease`. Do **not** also set `android:fullBackupContent="false"`; it is redundant alongside `allowBackup="false"`.
- `android:usesCleartextTraffic="false"` + `@xml/network_security_config` with `<base-config cleartextTrafficPermitted="false">` and **no trust-anchor overrides** (the server list is a runtime value; compiled-in XML cannot express it — that is precisely why pinning lives in code).
- `<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false"/>` — deliberate: Safe Browsing sends URL hashes to Google, the hostnames here are a private tailnet, and there is no user-navigable web to protect.
- `FLAG_SECURE` on the window (default on, toggleable) so the recents thumbnail and screenshots cannot leak a device list or a live terminal.
- No services, no receivers, no content providers in v1.
- `ClipDescription.EXTRA_IS_SENSITIVE` on **every** clipboard write at API 33+, so Android 13's clipboard preview toast does not render a certificate fingerprint or a line of terminal output on screen.

### 2.5 Sign-out is a real logout

A pinned `POST /api/auth/logout` carrying the WebView's cookie and `X-Requested-With`, **with no body** — the absent `Content-Type` is exactly what satisfies `authGuard`'s 415 check (`internal/server/api.go:272-277`, verified). Then clear cookies.

- **Not** `CookieManager.removeSessionCookies()` alone: that leaves the server-side session row alive for the full 14 days (`sessionTTL = 14*24h`, `auth.go:22`; `userBySession` never extends `expires_at`).
- **Not** an `evaluateJavascript` click on the console's own Sign-out button (`Layout.tsx:154-158`) — brittle DOM coupling to markup the mobile pass is about to change.

### 2.6 Named prohibitions (record the reason; do not let anyone "simplify" these back in)

| Prohibited | Why |
|---|---|
| `android.app.DownloadManager` for any download | Runs in a system process against the **system trust store** (never reaches `onReceivedSslError`, fails on the self-signed leaf) with a **separate cookie jar** (401s without a copied header). |
| `androidx.security:security-crypto` | All APIs deprecated in 1.1.0 in favour of direct AndroidKeyStore use; drags in `tink-android`. |
| Static `network_security_config` trust anchor | Compiled-in XML cannot express a runtime server list. |
| User CA install | Not trusted on API 24+ without an NSC entry anyway. |
| `WebSettingsCompat.setRequestedWithHeaderOriginAllowList` | The console already sets `X-Requested-With: fetch` itself (`web/src/api/client.ts:79-83`, verified), which is all `requireUser` checks (`auth.go:340`: `== ""`). Re-enabling the legacy header widens what the server sees for zero benefit. |
| Injecting JS to repoint `wss://` at a loopback port | `connect-src 'self'` blocks it in the renderer before it leaves the device (CSP verified live at `api.go:158`). |
| `pauseTimers()`, ever, including while backgrounded | Stops the console's SSE reconnect backoff while `Hub.broadcast`'s 64-slot per-listener buffer drops events (`hub.go:86-107`); the stream emits no `id:` or `retry:` so there is no resume. `webView.onPause()` alone is correct; the console's synthetic `{kind:'hello'}` on reopen (`useEvents.tsx:76`) is the intended resync. |
| `onRenderProcessGone` returning `false` | Crashes the whole app. Must return `true`, destroy, rebuild, reload `lastPath`. A multi-hour desktop tile stream is the canonical renderer-OOM workload. |
| An unauthenticated `/api/fingerprint` endpoint | Security theatre: an on-path attacker serves their own value over the very connection being verified. |

---

## 3. Architecture

### 3.1 Module layout

```
android/
  settings.gradle.kts          include(":app", ":trust"); pluginManagement + dependencyResolutionManagement
  build.gradle.kts             plugin aliases only, no buildscript block
  gradle.properties            android.useAndroidX=true; org.gradle.jvmargs=-Xmx2g; android.nonTransitiveRClass=true
  gradle/libs.versions.toml    the single version catalogue, with DO-NOT-BUMP comments
  gradle/wrapper/…             gradle-wrapper.properties (+ distributionSha256Sum) and the generated jar
  gradlew / gradlew.bat
  local.properties             GITIGNORED — sdk.dir=C\:\\Android\\Sdk
  keystore.properties          GITIGNORED — release signing, or env vars
  trust/                       ← kotlin("jvm"), NOT com.android.library
    build.gradle.kts
    src/main/kotlin/…/trust/   Fingerprint.kt  ServerEntry.kt  TrustStore.kt  PairUri.kt  SealedCodec.kt
    src/test/kotlin/…          plain JUnit — ./gradlew :trust:test needs no device
  app/
    build.gradle.kts  proguard-rules.pro  src/main/AndroidManifest.xml
    src/main/res/xml/network_security_config.xml
    src/main/res/xml/network_security_config_debug.xml   (debug source set)
    src/main/res/xml/data_extraction_rules.xml           (empty ruleset — must exist)
    src/main/res/xml/shortcuts.xml
    src/main/res/{layout,values,drawable,mipmap-*}/
    src/main/java/io/github/monstercouch/homelabrmm/
      App.kt                   ProcessLifecycleOwner observer → LockState
      MainActivity.kt          the only long-lived Activity: toolbar, WebView host, bottom bar, lock overlay
      ServersActivity.kt       server list / add / forget / export
      AddServerActivity.kt     manual entry, scan result, homelabrmm:// deep-link target
      TrustReviewActivity.kt   the human confirmation gate + pinned probe
      ConnTestActivity.kt      the five-row Connection test
      ScanActivity.kt          ZXing embedded host (exported=false)
      web/WebViewSetup.kt      every WebSettings flag in one auditable function
      web/RmmWebViewClient.kt  onReceivedSslError · shouldOverrideUrlLoading · onReceivedError · onRenderProcessGone
      web/RmmChromeClient.kt   onShowFileChooser · onShowCustomView/onHideCustomView · onConsoleMessage · onCreateWindow=false
      web/HostBridge.kt        WebMessageListener "RmmHost", origin-scoped; JS shim ships in the console
      web/Downloads.kt         DownloadListener → pinned stream → MediaStore.Downloads
      net/PinnedHttp.kt        HttpsURLConnection + pinning X509TrustManager (probe, download, logout, raw Upgrade probe)
      lock/BiometricGate.kt  lock/LockState.kt
      store/ServerStore.kt   store/Keystore.kt   store/Prefs.kt
      ui/…                     bottom sheets, error views, pin-mismatch view
```

**Views + XML, not Compose.** Removes the compose-compiler/Kotlin coupling entirely for what is four screens plus a WebView, and keeps the dependency set inside the physically verified compileSdk-35 ceiling. `MaterialToolbar` + `BottomNavigationView` + `BottomSheetDialogFragment` from Material 1.14.0 give the whole native UI.

**`:trust` is a `kotlin("jvm")` module, not `com.android.library`.** If it were an Android library and `PairUri` used `android.net.Uri`, `./gradlew :trust:test` would throw *"Method parse in android.net.Uri not mocked"*. Parse with `java.net.URI`. There is no emulator on this machine, so `:trust:test` is the only automated verification gate that exists and it must genuinely need no device.

### 3.2 Transport decision

Load `https://<server>:8443` as the **top-level document** from the real origin. Not an iframe (`X-Frame-Options: DENY` + `frame-ancestors 'none'`), not a local asset origin (`connect-src 'self'` leaves no CORS fallback, and `sameOrigin` at `relay.go:30-39` compares `strings.EqualFold(u.Host, r.Host)` literally, so an opaque/`null` origin parses to `""` and is refused with 403).

Loading from the server origin makes cookies, `X-Requested-With`, Origin, `ws`/`wss` scheme selection (`Terminal.tsx:18-20`, `Desktop.tsx:39-41`) and SSE all correct with zero configuration. Deep links need nothing either: `staticHandler` returns `index.html` with **HTTP 200** for any unknown path.

### 3.3 Data flow

**Cold start.** `MainActivity.onCreate` sets `FLAG_SECURE`, inflates the shell **without** creating a WebView, then runs `BiometricGate.require()`. Nothing is read from disk until it succeeds. On success the sealed list is opened, `Prefs.lastServerId` is selected, the WebView is built and `loadUrl(entry.url + lastPath)`. Empty list ⇒ `ServersActivity`.

**Steady state.** One WebView per server, LRU of 2 so A↔B switching is instant. Each gets its own `Profile` via `ProfileStore.getOrCreateProfile(serverId)` when `WebViewFeature.MULTI_PROFILE` is supported (hardening; cookies are host-scoped anyway). `CookieManager.setAcceptCookie(true)` once; `flush()` in `onStop` — `rmm_session` is `Max-Age=1209600` (verified live), so without the flush the 14-day persistent cookie is lost on process death and the operator re-logs in constantly.

**Native HTTP.** `PinnedHttp` = `HttpsURLConnection` + a plain pinning `X509TrustManager` + `hostnameVerifier { _, _ -> true }`. No OkHttp: two call sites do not justify the dependency. Every non-GET adds `X-Requested-With: rmm-android`; it sends **no** Origin (`sameOrigin` treats absent as allowed).

### 3.4 Navigation model

The console's off-canvas drawer is the wrong shape on a phone (the audits say so independently). Inside the shell it is suppressed and replaced by a native 5-item `BottomNavigationView`: **Home `/` · Alerts `/alerts` (badge) · Devices `/devices` · Runs `/runs` · More**.

- Suppression is feature-detected and **default-off**: the console only sets `document.documentElement.dataset.rmmShell = 'android'` after the bridge says `hello`. A plain mobile browser renders byte-identically to today.
- A tab tap posts `{t:'navigate',path}`; the console calls react-router `navigate()`, a client-side transition that keeps SSE and any live socket alive.
- **NORMATIVE fallback:** if the page has not said `hello` within **1.5 s**, the tab falls back to `loadUrl`. `web/dist` is compiled into the Go binary, so a phone can meet a server whose console predates the bridge — exactly when the operator most needs navigation to work. The console's own fallback is symmetrical: if `rmmShell` was never set, its drawer stays, so no configuration ends up with no navigation at all.
- The bar is a **sibling view, not an overlay**, so the WebView is simply shorter and the bottom safe-area inset is handled natively.
- **More** is a bottom sheet with the remaining nine nav entries, the server switcher, Connection test, App settings and Sign out.
- App Shortcuts (`res/xml/shortcuts.xml`): Alerts, Devices, Last device.

**Back**, via `OnBackPressedDispatcher`, in order: (1) dismiss custom view (fullscreen); (2) close an open sheet; (3) post `{t:'back'}` and give the page 120 ms to consume it (open modal/drawer); (4) `webView.goBack()` if `canGoBack()`; (5) finish to the server list. `BrowserRouter` pushes real history entries and `App.tsx:107` has a catch-all route, so there is never a 404 to get stuck on.

### 3.5 Lifecycle

- `android:configChanges="orientation|screenSize|screenLayout|smallestScreenSize|keyboardHidden|keyboard|uiMode|density|fontScale|navigation|touchscreen"` — the single highest-value manifest line. Without it, rotating the phone destroys the WebView, kills `/ws/shell` (the shell on the agent dies) and restarts the desktop stream from a full frame, at exactly the moment a user rotates for a wider terminal.
- `android:windowSoftInputMode="adjustResize"` stays for API 30–34.
- **Edge-to-edge IME handling is load-bearing.** targetSdk 35 forces edge-to-edge and `Window#setDecorFitsSystemWindows` is deprecated-and-disabled, so `adjustResize` alone no longer shrinks content: the keyboard arrives as an inset, the WebView keeps full height, CSS `100dvh` never recomputes, and the terminal stays under the keyboard with the PTY still believing the old row count.

```kotlin
ViewCompat.setOnApplyWindowInsetsListener(webContainer) { v, insets ->
    val ime  = insets.getInsets(WindowInsetsCompat.Type.ime())
    val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                                or WindowInsetsCompat.Type.displayCutout())
    v.setPadding(bars.left, bars.top, bars.right, maxOf(ime.bottom, bars.bottom))
    WindowInsetsCompat.CONSUMED
}
```

Shrinking the container shrinks the WebView → recomputes `100dvh` → trips the `ResizeObserver` already wired at `Terminal.tsx:133-140` → `FitAddon.fit()` → `send({t:'resize',cols,rows})`. The native inset handler and console change C4 must land together; either alone leaves the terminal broken.

- `onStop`: `webView.onPause()`, `CookieManager.flush()`, post `{t:'visibility','hidden'}` so the console closes live sockets cleanly with `{t:'close'}` instead of leaving half-open ones the server never reaps (`handleShellWS` has no read deadline, only a 15 s per-frame write deadline).
- Resume: post `{t:'visibility','visible'}`; if backgrounded > 60 s also probe `GET /api/auth/state` with the pinned client — `user == null` means the 14-day session died, so load `/login` rather than letting the page 401 its way there.
- Close code **1006 is the normal outcome of a backgrounded radio** and is never surfaced as a native error.
- Process death: do **not** rely on `WebView.saveState` (back/forward list only, can blow the 1 MB Binder limit). Persist `{serverId, lastPath}` on every `onPageFinished`; relaunch = gate, then reload.

### 3.6 The bridge

`WebViewCompat.addWebMessageListener(webView, "RmmHost", setOf(entry.origin), listener)`, feature-gated on `WebViewFeature.WEB_MESSAGE_LISTENER` (WebView 88+, effectively universal at minSdk 30).

Chosen over `addJavascriptInterface`, which exposes the object to **every frame of every page**. Origin scoping is enforced by Chromium, and because a native object injection is **not a script load**, `script-src 'self'` never applies — the CSP question is designed away rather than answered. The JS shim ships **in the console** (`web/src/lib/host.ts`), so nothing depends on `evaluateJavascript` or `addDocumentStartJavaScript` bypassing CSP either.

**Degraded path** (feature unsupported): `addJavascriptInterface` with a per-call `webView.url` host check, **plus removal of the interface in `onPageStarted` whenever the origin does not match**, plus a one-time warning on Server detail. Never degrade silently.

Frames, page → native: `hello` · `save` (CSV/text → `MediaStore.Downloads`) · `clip.read` · `clip.write` · `badge` (open/critical counts from the SSE stream the console already consumes — no extra polling) · `busy` (keep-awake) · `sse` (the Connection-test row-3 signal) · `signedOut`.
Native → page (via the retained `JavaScriptReplyProxy`): `navigate` · `visibility` · `paste` · `back` · `theme`.

**Every frame is feature-detected in both directions.** The console checks for the host object before using it; the native side never assumes the page will say `hello`.

**Clipboard is asynchronous.** A synchronous `@JavascriptInterface fun readClipboard(): String` is **not implementable** — it runs on the JavaBridge thread and `ClipboardManager` requires a Looper. The read is marshalled to the main thread and answered through `replyProxy`. (Android 10+ restricts clipboard reads to the focused app, which the foregrounded WebView app is.) This is the only working Paste path in the terminal and the remote desktop even over https: `navigator.clipboard.readText()` needs `CLIPBOARD_READ_WRITE`, and WebView's `onPermissionRequest` covers only media/MIDI/protected-media.

---

## 4. Screens

| Screen | Purpose | Notes |
|---|---|---|
| **Lock** (overlay on MainActivity) | Gate a 14-day session that can reboot the fleet | Opaque, clickable, full-bleed view over the WebView; the page is **never** unloaded and cookies are **never** cleared (re-auth costs a password + TOTP against a 10/min limiter). `BiometricPrompt` with `setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)` — legal without branching only at API 30+, one of three reasons for minSdk 30 — and `setConfirmationRequired(false)`; **no negative button** (setting both throws at `build()`). `canAuthenticate()` ≠ SUCCESS ⇒ hard stop with a button to `Settings.ACTION_BIOMETRIC_ENROLL`; the app refuses to run without a device lock. Re-lock driven by `ProcessLifecycleOwner` ON_STOP + a grace period (0/30/60/300 s, default 60) so flipping to Tailscale, an authenticator or the file picker does not re-prompt. |
| **Shell (main)** | The console itself | `MaterialToolbar` (server label + chevron → picker, a live-connection dot mirrored from the console's `bus.connected()` — today it lives in `.nav-foot` inside the drawer and is invisible on a phone, overflow: Reload / Connection test / Lock now / Server details / Sign out), WebView, `BottomNavigationView`. |
| **Server list / picker** | One-tap switching | Rows: label, host:port, last-used, reachability dot refreshed by a 2 s-timeout pinned `GET /api/auth/state` when the sheet opens, and a trust chip: **Pinned** (green) or **System trust** (amber — marked as the weaker mode). Long-press: rename / show pin / forget. Footer: Add server, Export list. Renders **before** the biometric prompt on the re-lock path, which is why the keystore key has no user-auth binding. |
| **Add server** | Learn url + fingerprint out of band | Three inputs: Label; URL (prefilled `https://`, `inputType=textUri`, `autoCapitalize=none`, `autoCorrect=off`; an `http://` URL is refused inline in release with the reason); Fingerprint (paste-friendly — strips `:` and whitespace, lowercases, live-validates `^[0-9a-f]{64}$` with a counter, matching `internal/agent/conn.go:25` exactly). An **empty** fingerprint is legal and means system trust. Sources: **manual paste is the primary, guaranteed path**; "Scan QR" launches the bundled ZXing scanner; a `homelabrmm://pair?url=&fp=&name=` deep link prefills. Nothing is stored here. |
| **Trust review** | The human confirmation gate | Fingerprint in **4 rows of 4 groups of 4** monospace characters, uniform, **with no emphasis on the first or last bytes** (emphasising the ends invites exactly the partial comparison a prefix-collision attack targets). Source badge: QR / Manual / Deep link. A mandatory checkbox: "This matches the fingerprint shown on the server's Settings page." Then **Verify & save** runs a pinned `GET /api/auth/state` — unauthenticated, a GET, so no `X-Requested-With`, Origin or Content-Type needed (verified live: `{"needs_setup":false,"setup_code_required":false,"user":null,"version":"dev"}`). On success the entry is sealed and stored, and the reply routes the first load (`needs_setup` ⇒ `/setup`, `user != null` ⇒ skip login). On mismatch the entry is **discarded** and the mismatch screen appears. **You cannot store a pin you have not successfully used.** A deep link never auto-adds and never auto-navigates. |
| **Connection test** | Turn the one real unknown into a permanent product diagnostic | Five ordered rows — see §6. Runs automatically once when a server is added; also on the overflow menu and the unreachable screen. |
| **Pin mismatch** | A deliberate dead end | Host, expected and presented fingerprints in 4×4 groups with the first differing group highlighted; the two innocent causes (cert regenerated / different server) and the one that matters. Buttons: Back to servers · Server details (where a pin can be rotated *deliberately*, through Trust review again). No "proceed anyway" anywhere. |
| **Unreachable** | Own the failure the console cannot (no service worker, no offline shell) | Driven by `onReceivedError` for the **main frame only** (`request.isForMainFrame`). `onReceivedHttpError` is **ignored** — `writeErr` always emits JSON and unknown paths return `index.html` with 200, so it never signals a navigation failure. Codes mapped to plain English: `ERR_NAME_NOT_RESOLVED` → "MagicDNS name not resolving — is Tailscale connected?", `ERR_CONNECTION_REFUSED` → "Nothing listening on host:port", `ERR_ADDRESS_UNREACHABLE`/`ERR_INTERNET_DISCONNECTED` → "No route to the tailnet". A `ConnectivityManager` hint (transport type + absence of `NET_CAPABILITY_NOT_VPN` as an honest "Tailscale looks up" proxy). Retry is **diagnostic**, not a blind reload: it runs the pinned probe first, so it distinguishes back / still-no-route / certificate-changed. **Open Tailscale** appears only when `com.tailscale.ipn` resolves through the manifest `<queries>` entry. |
| **Fullscreen viewer** | Make the desktop Fullscreen button work at all | The default `WebChromeClient` silently ignores `requestFullscreen()`, so `fullscreenchange` never fires and the console's state stays `false`. `onShowCustomView` adds the view, hides toolbar + bottom bar, `WindowInsetsControllerCompat.hide(systemBars())` with `BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE`, sets `FLAG_KEEP_SCREEN_ON`, and shows a floating orientation-lock chip toggling `SCREEN_ORIENTATION_USER_LANDSCAPE` ↔ `_UNSPECIFIED`. System back exits fullscreen first — Shift+Escape (`Desktop.tsx:510-512`) is unreachable on a phone. |
| **Server detail** | Everything about one entry; the only place trust changes | Label, URL, trust mode, fingerprint in 4×4 with Copy, Added / Last connected / Pin rotated, and a **non-blocking** banner if the presented cert is past `NotAfter`. Actions: Rotate pin (re-enters Trust review, records `pinRotatedAt`), Sign out, Forget server (wipes the entry and calls `ProfileStore.deleteProfile`). |
| **App settings** | The few knobs worth having | Lock grace period · Block screenshots (FLAG_SECURE, default on, with the honest note that it also blocks the owner's own screen recordings) · Default remote-desktop quality (**35**, not the console's 60, on coarse pointers) · Alert notifications (v1.1) · Export server list · Clear web storage (preferences only) · About (app version + WebView package version, logged for bug reports) · a one-paragraph Security section stating what the pin is and that the app never fetches it over the connection it secures. |
| **Alert notification** (v1.1) | The 30-second job without opening the app | See §10. |

---

## 5. Pinning design

### 5.1 The kernel (`:trust`, pure JVM)

```kotlin
sealed interface Decision {
    data object Trusted : Decision
    data class Rejected(val why: Failure) : Decision
}
sealed interface Failure {
    data class NoHost(val url: String) : Failure
    data class UnknownHost(val host: String) : Failure
    data object NoCertificate : Failure
    data class PinMismatch(val host: String, val presented: String, val expected: String) : Failure
}

object Fingerprint {
    /** Matches internal/agent/conn.go:25 exactly. */
    fun normalize(s: String) = s.replace(":", "").filterNot(Char::isWhitespace).lowercase()
    fun isValid(s: String) = s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }
    /** Matches internal/server/tls.go:45-49: hex(sha256(DER)), lower case, no colons. */
    fun ofDer(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }
    fun groupsOf4(fp: String): List<String> = fp.chunked(4)
}

class TrustStore(entries: List<ServerEntry>) {
    private val byHost = entries.associateBy { it.host.lowercase() }

    fun evaluate(url: String?, der: ByteArray?, host: String?): Decision {
        val h = host?.lowercase() ?: return Decision.Rejected(Failure.NoHost(url ?: ""))
        val e = byHost[h] ?: return Decision.Rejected(Failure.UnknownHost(h))
        if (e.trustMode == TrustMode.SYSTEM) return Decision.Rejected(Failure.UnknownHost(h))
        val bytes = der ?: return Decision.Rejected(Failure.NoCertificate)
        val got = Fingerprint.ofDer(bytes)
        return if (MessageDigest.isEqual(got.toByteArray(US_ASCII), e.pinHex.toByteArray(US_ASCII)))
            Decision.Trusted else Decision.Rejected(Failure.PinMismatch(h, got, e.pinHex))
    }
}
```

`Fingerprint`/`TrustStore` are the **single source of pin truth**, used by `onReceivedSslError` and by `PinnedHttp`'s TrustManager alike. Two copies is exactly how two copies drift.

### 5.2 The single call site

```kotlin
override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
    val host = runCatching { Uri.parse(error.url).host }.getOrNull()
    val der  = runCatching { error.certificate.x509Certificate?.encoded }.getOrNull()
    when (val d = trust.evaluate(error.url, der, host)) {
        is Decision.Trusted  -> handler.proceed()      // the ONLY proceed() in the tree
        is Decision.Rejected -> { handler.cancel(); onPinFailure(d.why) }
    }
}
```

`SslCertificate.getX509Certificate()` is API 29+, which minSdk 30 makes unconditional. The default `WebViewClient.onReceivedSslError` calls `cancel()`, so forgetting to set a client fails closed too.

### 5.3 The native side

```kotlin
private class PinTrust(private val trust: TrustStore, private val url: String, private val host: String)
    : X509TrustManager {
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        if (trust.evaluate(url, chain.firstOrNull()?.encoded, host) !is Decision.Trusted)
            throw CertificateException("certificate fingerprint mismatch")
    }
    override fun checkClientTrusted(c: Array<X509Certificate>, a: String) =
        throw CertificateException()                       // never `= Unit`
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}
// and, because the SANs will not cover the tailnet name — see §2.2 rule 1:
conn.hostnameVerifier = HostnameVerifier { _, _ -> true }  // safe ONLY because the pin is exact
```

Use a **plain `X509TrustManager`**, not `X509ExtendedTrustManager`: the extended class is abstract with four further methods including `checkServerTrusted(chain, authType, Socket)` and `(…, SSLEngine)`, so an anonymous object overriding only the two-argument form **will not compile**. Conscrypt invokes the two-argument form for a non-extended manager. When the entry's pin is empty, `PinnedHttp` uses the platform default socket factory and the default hostname verifier — system trust, no bypass.

The `hostnameVerifier { true }` will trip any security scanner, so it carries a comment pointing at `tls.go:111-124` and at this document, and it lives in the same file and the same test suite as the pin check.

### 5.4 Coverage

One handler secures navigation, subresources, `fetch`, `EventSource('/api/events')` and `wss://` alike, because `AwContentBrowserClient::AllowCertificateError` ignores `is_primary_main_frame_request` — a WebView divergence from desktop Chrome, which never prompts for subresources. See §1 for the traced path and §2.2 rules 6–7 for the two corollaries.

### 5.5 Pairing

The pin is **never** fetched over the connection it secures. `docs/SECURITY.md:229` already says so. The existing exposure is correct and must not change: `GET /api/system` (`api.go:565-579`) and `GET /api/enroll` (`api_agents.go:532-540`) are session-gated; `GET /api/auth/state` returns no fingerprint at all.

Channels, in order:

1. **Manual entry** — the guaranteed path, always available, so the camera permission can be denied forever.
2. **QR off the console's own screen** — screen-to-camera is a genuine out-of-band channel. The console renders `homelabrmm://pair?url=<enc>&fp=<64hex>&name=<label>` **and the same string as copyable text**, using `qrcode` 1.5.4 which is already a dependency and already called at `Account.tsx:114` (verified in `web/package.json`). The APK ships a bundled scanner (`zxing-android-embedded`), because **"the phone's own camera resolves the custom scheme" is not reliable**: stock camera and Lens surface an "open" affordance for `http(s)` and a short list of well-known schemes, and commonly render an arbitrary custom scheme as inert raw text. An `https` App Link is **not** a substitute either: `android:autoVerify` requires a publicly fetchable `/.well-known/assetlinks.json` over publicly-trusted TLS, which a self-signed tailnet host cannot serve.
3. **Deep link** — the same URI as an `<intent-filter>` (scheme `homelabrmm`, host `pair`), useful from a note or a password manager. Prefills only.

All three converge on Trust review. There is no path by which an unverified pin becomes a trusted one.

### 5.6 `:trust` test suite (`./gradlew :trust:test` — the gate)

`normalize_strips_colons_and_lowercases` · `rejects_63_and_65_chars` · `rejects_non_hex` · `ofDer_matches_known_vector` (a fixed DER with its Go-computed hex) · `evaluate_rejects_unknown_host` · `evaluate_rejects_null_der` · `evaluate_rejects_system_trust_mode` · `evaluate_accepts_exact_match` · **`evaluate_rejects_every_single_char_mutation`** (all 64 positions × 15 substitutions) · `pair_uri_rejects_http` · `pair_uri_rejects_short_fp` · `pair_uri_rejects_empty_host` · `sealed_blob_rejects_tag_mutation` · `sealed_blob_rejects_iv_mutation` · **`proceed_appears_exactly_once`** (source scan across `app/src/main` and `trust/src/main`).

---

## 6. Connection test (five rows)

Each row shows pass/fail and the raw error. Run in order against the active server.

1. **TLS + pin** — pinned `GET /api/auth/state`; shows received vs expected fingerprint side by side.
2. **Page load** — the WebView reaches `onPageFinished` on `/`.
3. **Live events** — the console reports its SSE `hello` through the bridge. This is the non-navigation *subresource* path.
4. **WebSocket (in the WebView)** — the page opens `new WebSocket(location.origin.replace(/^http/,'ws') + '/ws/shell/__rmm_pin_probe__')`. Verified in the repo: `handleShellWS` does `sameOrigin` and then `if !s.hub.IsOnline(agentID) { writeErr(w, 409, "agent is offline") }` **before** `upgrader.Upgrade`, so an unknown id can never spawn a shell and nothing is audited as a session.
   **Observation channel — this is the part every earlier draft got wrong.** Page JS **cannot** see a status code for a *failed* WebSocket handshake: the API surfaces an `error` event and a `close` with code 1006 and no status in **both** the 409 case and the TLS-rejection case. Reporting row 4 from page JS alone yields a false negative. Instead the row is decided natively, from two signals the shell already has:
   - `WebChromeClient.onConsoleMessage` — Chromium logs `"Error during WebSocket handshake: Unexpected response code: 409"` for the HTTP-level rejection versus an SSL error string for the TLS rejection;
   - whether `onReceivedSslError` fired for that host during the attempt (it is the shell's own handler, so this is directly observable).
   `409 seen` ⇒ **PASS, and the gating unknown is answered affirmatively.** `SSL error string, or neither signal within 10 s` ⇒ FAIL with the named fallback (§9), not a silently dead Terminal tab.
5. **WebSocket (native control)** — `PinnedHttp` issues a raw `Upgrade:` request to the same path and reads the status directly. This proves server-side reachability independently of the WebView, so a row-4 failure can be attributed to the WebView's network stack rather than to the tailnet.

---

## 7. WebView configuration (`web/WebViewSetup.kt`, one auditable function)

**On:** `javaScriptEnabled`; `domStorageEnabled` (six `rmm.*` localStorage keys); `useWideViewPort` + `loadWithOverviewMode`; `setSupportZoom(true)` + `builtInZoomControls = true` + `displayZoomControls = false` (pinch-zoom is the only escape hatch for the 1653 px baseline matrix until the card renderer lands); `cacheMode = LOAD_DEFAULT` (hashed `/assets/*` are `immutable`, `index.html` is `no-cache` — exactly right for an in-place server upgrade); `userAgentString += " HomelabRMM/1.0 (Android)"` so `createSession` stores something identifiable in `sessions.user_agent`.

**Off, hard:** `allowFileAccess = false`, `allowContentAccess = false`, `allowFileAccessFromFileURLs = false`, `allowUniversalAccessFromFileURLs = false`, `setGeolocationEnabled(false)`, `setSupportMultipleWindows(false)` with `onCreateWindow` returning `false`, `mixedContentMode = MIXED_CONTENT_NEVER_ALLOW`.

**Not enabled:** `setRequestedWithHeaderOriginAllowList` (§2.6); algorithmic darkening — `web/index.html:6` declares `color-scheme: dark light` and the console ships its own themes, so darkening would double-invert.

**Navigation containment** (`shouldOverrideUrlLoading`): allow only `scheme == "https" && host.equals(entry.host, true) && port == entry.port`. `otpauth:` goes to `ACTION_VIEW` — that is the TOTP hand-off that makes enrollment possible on the phone being enrolled. Everything else is **blocked with a toast**, not handed to the system browser: the console contains no `target="_blank"` and no external links (the only URLs it holds are user-entered webhooks in `Automations.tsx:244`, never navigated), so an off-origin navigation means something has gone wrong.

**Required overrides — the silent-failure cluster.** Omitting `onShowFileChooser` breaks the Files Upload button with no error; omitting `onShowCustomView` makes Fullscreen do nothing; omitting `DownloadListener` breaks file download. All three fail with **no message**, which reads as "the app ignored my tap". Write them first and test them first. `onShowFileChooser` must call `onReceiveValue(...)` exactly once including `null` on cancel, or the file input is permanently dead for the life of the page.

**Downloads** stream through `PinnedHttp` with `Cookie` copied from `CookieManager.getInstance().getCookie(url)` and the WebView's UA, filename from `URLUtil.guessFileName(url, contentDisposition, mimeType)`, into `MediaStore.Downloads`. Do **not** add a defensive `blob:` branch to `DownloadListener`: it can never fire (§8, C6) and would be dead code that looks like a safety net.

---

## 8. Console changes

`web/dist` is embedded in the Go binary, so every console change ships with the server and also improves tablets and desktop touch. Ordered smallest-first, highest-gate-first. C1–C11 are prerequisites for a usable shell.

**C1 — Untyped-input selector fix.** `web/src/styles/global.css:640` (verified: the rule head is still the enumerated attribute list). `input[type="text"]` matches the **attribute**; a bare `<input>` has IDL type `text` but no attribute, so ~54 call sites render as raw ~25.6 px native controls (measured `#li-user`: background `rgb(59,59,59)`, border `2px inset`, padding `1px 2px`) directly above a correctly styled 33.6 px `#li-pw`. Replace with `input:not([type="checkbox"]):not([type="radio"]):not([type="range"]):not([type="file"]):not([type="color"]):not([type="submit"]):not([type="button"]):not([type="image"]):not([type="reset"]):not([type="hidden"]), select, textarea, .input`. In the same edit add `autoCapitalize="none" autoCorrect="off" spellCheck={false}` to `Login.tsx:58`, `Setup.tsx:148/:165`, and the search/path fields — Android capitalises the first letter, so the owner types "Admin", gets "Invalid username or password", on the first screen of the app. **One rule; it gates the entire product; it fixes the desktop too.**

**C2 — Pairing card + readable fingerprint.** `Settings.tsx:190-195` (verified) renders the pin as `<code className="truncate" style={{maxWidth:320}} title={…}>` inside a `flexWrap:'nowrap'` row in a `dl.kv` computing to `122px 198px` at 390 px: ~20 of 64 characters visible, the rest only in a `title` tooltip touch never fires. Drop `.truncate`/`maxWidth`, render `<code style={{wordBreak:'break-all'}}>` on its own line with a full-size `CopyButton`, add `@media (max-width:700px){ .kv{grid-template-columns:1fr} .kv dt{margin-top:8px} }`. Then add a "Pair a phone" block: a QR of `homelabrmm://pair?url=…&fp=…&name=…` via `QRCode.toDataURL` plus the same string as copyable text. `img-src 'self' data:` already allows the data PNG. Mirror on `EnrollDrawer.tsx:113-125`. ~30 lines, **no new dependency**.

**C3 — `web/src/lib/host.ts`** (~120 lines + ~8 call sites). Promise-based shim over the `RmmHost` message channel: `host.available`, `saveText`, `clipboardRead/Write`, `badge`, `busy`, `sse`, `signedOut`, and `onNavigate`/`onVisibility`/`onPaste`/`onBack` subscriptions. On `hello` it sets `document.documentElement.dataset.rmmShell = 'android'`. Every call feature-detected; a plain browser is byte-identical to today. C6, C7 and C12 depend on this.

**C4 — Viewport, safe areas, `dvh`.** `web/index.html:5` → `width=device-width, initial-scale=1.0, viewport-fit=cover, interactive-widget=resizes-content`. Then `env(safe-area-inset-*)` on `.topbar` (:278), `.nav` (:207), `.main` (:338) and `.toast-host` (:1974, whose bottom edge measures y=828 of 844 — inside the gesture strip); swap `100vh`→`100dvh` at :1979 and :1982; add `html{-webkit-tap-highlight-color:transparent}` (default is the Android cyan flash) and `.main{overscroll-behavior-y:contain}`. Targeting SDK 35 forces edge-to-edge; without this the 52 px topbar paints under the status bar. Lands **with** the native inset listener (§3.5).

**C5 — Coarse-pointer tap targets.** One `@media (pointer: coarse)` block beside the existing `@media (hover:none)` at :882. Nothing reaches 44 px today: `.btn` 30.9, `.btn.sm` 23.6, `.btn.xs` 19, `.btn.icon` 30×30, modal close 26×26, checkboxes 15×15, `.switch` 34×19, `.toast-close` 11.3×16, `.chip .x` ~8×14, nav items 37.6. Sub-40 px counts: Alert-rule modal 71, Alert rules 57, Dashboard 45, Alerts 39, Devices 32. Raise `.btn` 44 / `.sm` 40 / `.xs` 36, icon buttons 44×44, checkboxes 22 px with `td.check` 48 px, `.switch` 48×28 (**recompute the `::after` translate at :784-786**), `.menu` rows 48, `.tabs` 44, inputs 44 px/16 px, `.chip .x` a 28 px inline-flex box, `.toast-close` 44×44. Do this **after** C9 — bigger type makes wide tables wider.

**C6 — CSV export through the bridge.** `DataTable.tsx:263-275` (verified: still Blob + `createObjectURL` + synthetic anchor, measured `blob:http://127.0.0.1:18080/…`, name `devices-2026-09-16.csv`). `DownloadListener` never fires for `blob:` and no HTTP client can resolve one, so every Export CSV button on Devices, Alerts, Runs, Patches and Audit is a **silent no-op** — the worst failure shape, because it looks like the app ignored the tap. **This can only be fixed in the console**, before the Blob is created: `if (await host.saveText(filename, 'text/csv;charset=utf-8', csv)) return;`.

**C7 — Clipboard guards + native paste.** Three unguarded `writeText` sites: `Terminal.tsx:166`, `Desktop.tsx:418`, and the dangerous one at `Terminal.tsx:119-125` — `void navigator.clipboard.writeText(sel).catch(…)` **cannot** catch the TypeError from reading `.writeText` of `undefined`, so on a non-secure origin Ctrl+C with a selection throws *inside* xterm's synchronous `attachCustomKeyEventHandler`. Give all three the `CopyButton` treatment (`ui.tsx:41-57`: try/catch + `document.execCommand('copy')` fallback). Prefer `host.clipboardRead/Write` when present — it is the only working Paste path (§3.6). The terminal accepts `{"t":"in","data":…}`, the desktop helper `{"t":"paste","text":…}` (`docs/DESKTOP-PROTOCOL.md:51`).

**C8 — Terminal.** (a) A `.term-keybar` between `.term-wrap` and `.statusline`, shown under `@media (pointer: coarse)` at 44 px, feeding the existing `send({t:'in',data})` at `Terminal.tsx:110`: Esc `\x1b`, Tab `\t`, Ctrl+C `\x03`, Ctrl+D `\x04`, Ctrl+Z `\x1a`, Ctrl+L `\x0c`, Ctrl+R `\x12`, arrows `\x1b[A/B/C/D`, Home `\x1b[H`, End `\x1b[F`, PgUp/PgDn `\x1b[5~`/`\x1b[6~`, `| ~ / -`, plus a sticky Ctrl toggle mapping the next letter with `String.fromCharCode(k.toUpperCase().charCodeAt(0)-64)`. Gboard emits none of these. (b) Height: `.fill-page` computes 672 px starting 247 px down the page — already 75 px past the fold *before* the keyboard, with "Connected · powershell" permanently below it. Switch :1568/:1983 to `100dvh`, add `@media (max-width:700px){ .main{display:flex;flex-direction:column} .fill-page{height:auto;flex:1 1 auto;min-height:0} }`, add a `visualViewport` resize listener that re-fits, hide the 366×35 tip span at `Terminal.tsx:205`, give `.statusline` `order:-1`. (c) After `t.open(el)` set `term.textarea?.setAttribute('inputmode','text')` and `enterkeyhint='send'`. (d) **Security:** gate the 50 ms auto-connect at `Terminal.tsx:152-156` behind an explicit tap when `matchMedia('(pointer: coarse)')` matches — today, merely opening the tab spawns an audited shell on a live device, which from a pocket is a real hazard.

**C9 — DataTable phone cards + `.tbl-foot`.** Add `mobile?: 'primary'|'secondary'|'hide'` to `Column<T>` (`DataTable.tsx:6-21`), default show-everything, emit `data-label={headerText(c)}` on each `<td>` (:185), and under `matchMedia('(max-width:700px)')` render a `<ul class="card-list">` of cards with the action row **first** at full size. Measured in a 364 px wrap: Devices 1211 px/13 cols, Alerts 1079/8, BaselineStatus 1653/8, Baselines 1383, Scripts 1151, Processes 1265, Services 1170. No sticky first column, so scrolling right to read Disk/Alerts/Patches leaves the row anonymous, and the Alerts row Ack/Resolve buttons (33×19, 54×19) are entirely off the right edge at scrollLeft 0. Annotate Devices and Alerts first. **Separately and cheaply:** lift `.tbl-foot` out of the `overflow:auto` `.table-wrap` — as a block child it is laid out at 364 px, so dragging the table sideways slides the row counts and Export CSV off the left edge (measured left 13 → −834). Also fixes the never-engaging sticky header: `.tbl th{position:sticky;top:0}` resolves against `.table-wrap`, which has `max-height:none` and therefore never scrolls vertically; `DataTable` already accepts a `maxHeight` prop (:38) that `Devices.tsx:422` and `Alerts.tsx:220` simply do not pass.

**C10 — Two inline-style grids** (verified). `Overview.tsx:25` `gridTemplateColumns:'minmax(300px,380px) 1fr'` computes to `352px 0px` at 390 px: every live stat tile, all four metrics charts, open alerts, disks and interfaces are off-screen (`main.scrollWidth` 1045 vs 390). `ScriptEditor.tsx:139` `'340px 1fr'` leaves the code textarea ~30 px against a scrollWidth of 884. Inline styles cannot be reached by the media query — replace both with classes, use `minmax(0,1fr)` for the second track (the plain `1fr` is what let the track collapse instead of forcing a scroll), and collapse to one column on phones with `order:2` on Overview's first column so stats and charts come **before** the identity edit form.

**C11 — Modals as phone sheets.** `Modal.tsx:99` closes on `onMouseDown` when the target is the overlay, and at phone width the overlay leaves a 16 px gutter — verified that a tap at (8, 400) discards a half-filled New task dialog while a drag correctly does not, i.e. it fires on exactly a fat-finger miss. Disable backdrop dismiss under `(pointer: coarse)`; make dialogs full-bleed (`.overlay{padding:0}`, `.modal{width:100%;max-width:none;border-radius:14px 14px 0 0}`, sticky `.modal-foot`); `.drawer,.drawer.wide{width:100%}` (it currently leaves an unusable 23 px strip); and **skip `useDialogFocus`'s auto-focus (`Modal.tsx:52-55`) on coarse pointers** — the New automation and Add-check dialogs already measure 783 px tall with bottom 843 in an 844 px viewport, i.e. zero slack before Gboard.

**C12 — Shell navigation contract.** Under `[data-rmm-shell]`, hide `.nav`, `.nav-scrim`, `.nav-toggle`; wire `{t:'navigate'}` to react-router `navigate()` in `Layout.tsx`; feed `host.badge()` from the existing `useEvents` alert kind. Default-off and feature-detected; if the bridge never says `hello`, the drawer stays.

**C13 — Device tab strip.** 12 items, 985 px in a 366 px box, no chevron or fade; deep-linking to `/devices/<id>/events` leaves `scrollLeft` 0 with the active tab at left 933. Add a ref + `useEffect(() => ref.current?.querySelector('a.active')?.scrollIntoView({inline:'center',block:'nearest'}), [pathname])`, scroll-snap, an edge mask, 44 px tabs. Also trim the 121 px page head: hide last-IP and the OS label (both on Overview) and fold Run script / Inventory / Wake into the existing More dropdown.

**C14 — Remote desktop touch.** `Desktop.tsx` binds only React synthetic **mouse** events and `touch-action` computes to `auto`, so a tap works (compat events) but a drag pans the page, there is no right-click, and pinch zooms the page. Add `touch-action:none` + `overscroll-behavior:contain` and a Pointer Events path with `setPointerCapture`, using a **trackpad model, not absolute mapping** — a 1920×1080 session fits at 0.19× in the measured 364×507 wrapper, where a fingertip covers ~130 remote pixels: one-finger drag = relative cursor move; tap = click at the cursor; tap-then-press-and-drag within 300 ms = drag with the button held; long-press >500 ms with <10 px travel = button 2; two-finger drag = wheel (sub-notch deltas already accepted); pinch = local canvas zoom. Replace the fit-only `layout()` (:132-142) with scale/offset state + `overflow:auto` and a Fit / 1:1 toggle (`toRemote()` derives from `getBoundingClientRect()` so it stays correct at any zoom). Keyboard: a visually-hidden `<input>` plus a Keyboard button (a `tabIndex` div never raises the soft keyboard) and a key bar sending real W3C codes — Android IMEs report `code:""`/`key:"Unidentified"` and the helper falls back to `key` only for single printable runes (`internal/agent/desktop/keymap.go:232-235`). Route typed text through `{t:'paste',text}`. Default quality 35 on coarse pointers; move Quality/Monitor/Refresh into an overflow so the toolbar is one row.

**C15 — Alerts toolbar.** `.toolbar > .btn-group` gets `flex:1 1 140px` and shrinks to clientWidth 179 while needing 242, and `.btn-group` is `overflow-x:visible`, so "Resolved" is cut mid-word and "All" is painted under the adjacent select and unreachable. Give it `flex:1 0 100%; overflow-x:auto` with non-shrinking children (or a native `<select>` at phone widths). Same rule fixes `DevicePatches.tsx:133-145` (163 px box, 298 px content).

**C16 — Global search.** The topbar search collapses to 103 px, the placeholder truncates to "Search (", and results inherit that width (68 px per row). `.topbar .search{position:static}` + `.search-results{position:fixed;left:8px;right:8px;top:calc(var(--topbar-h) + 4px);max-height:60vh}`, stack the meta line, give the input `flex:1 1 auto;min-width:0`, hide the theme toggle and the "( / )" hint below 700 px. Relieved further by the bottom bar (C12).

**C17 — Dashboard above the fold.** Move `GettingStarted` below the stat grid (it is onboarding, not operations, and currently fills the entire first screen so the open-alert count sits ~1.3 screens down); carve `.grid.cols-4` out of the blanket phone `1fr` rule to `repeat(2, minmax(0,1fr))` and compact `.stat`; swap the `role="link"` divs for real `<Link>`s.

**C18 — BaselineStatus matrix.** 1653 px with a 198 px sticky column leaves 166 px of matrix for 7 checks. Transpose to one card per device; de-truncate the check names (currently `title`-only).

**C19 — Long tail.** Patches "Install approved (per device)" lands directly under "Approve" once the toolbar wraps because the `<span style={{width:12}}/>` separator collapses — move it to its own bordered row. Devices bulk bar out of the filter toolbar into a sticky bottom bar; Devices filters behind a `<details>`. Services' six per-row buttons → one Dropdown. EventLog Source/ID hidden with the message allowed to wrap. Replace `title`-only data (`Audit.tsx:40-41`, `BaselineStatus.tsx:294`, `Scripts.tsx:54`, `Compliance.tsx:154-161`) with wrapping text or tap-to-expand — touch never fires a tooltip. `CodeEditor.tsx`: guard the Enter branch with `if (e.nativeEvent.isComposing || e.keyCode === 229) return;` and add Tab/Shift+Tab/wrap buttons (no Android keyboard has Tab, while the hint says "Tab indents"). Body scroll lock while the drawer or a modal is open (measured `body.overflow: visible`). Power/More menu rows to 48 px. `otpauth://` "Open in authenticator app" link beside the TOTP CopyButton. Type scale: body 13.5 px with a tail at 10–11.5 px.

---

## 9. Server changes

**None are required for v1.** Verified live: `GET /api/auth/state` answers unauthenticated; the console sets `X-Requested-With` itself; WebSocket upgrades are exempt from the CSRF check via `isWebSocket` (`auth.go:340`); unknown paths return `index.html`/200 so deep links need no configuration; `rmm_session` is `Max-Age=1209600` so it survives process death; the CSP already permits the desktop viewer's blob tiles.

Optional, in value order:

1. **WebSocket PING on the viewer socket** (`relay.go:218-242`). `hub.keepalive` pings the *agent* socket every 30 s and drops after 90 s, but nothing ever pings the *browser* socket: `handleShellWS` loops on `ws.ReadJSON` with no read deadline and the only deadline anywhere is a 15 s per-frame **write** deadline. A mobile NAT idle timeout (30–120 s) therefore kills an idle terminal silently and leaves a half-open socket the server never reaps. Emit a PING every ~25 s from `wsWriter`; set a ~90 s read deadline refreshed on pong. ~20 lines, mirroring `hub.go`. **Do not** send a no-op `{"t":"in","data":""}` from the client as a keepalive — that types into the shell.
2. **Sliding session + revoke.** `createSession` stamps `now+14d` once and `userBySession` only compares it — no idle timeout, no refresh endpoint, no per-session revoke. The phone dies exactly 14 days after login with no warning. Add `if exp-now() < sessionTTL/2 { UPDATE sessions SET expires_at = ? }`. **Security condition:** sliding must ship *together with* `GET /api/me/sessions` and a revoke (all + single). An indefinitely-renewing credential on a lost phone is acceptable only if it can be killed from elsewhere. The table already stores `ip` and `user_agent` (`db.go:72-79`) and nothing reads them back.
3. **SSE filtering** — `GET /api/events?agent=&kinds=`, a predicate in the select loop (`api.go:488-500`) or in `hub.subscribe`. Today an idle phone receives a full metrics sample for **every** device every 30 s: the dominant mobile-data cost of the whole app. The 64-slot buffer drops events for a slow phone anyway, so filtering cuts both bytes and drop rate.
4. **Honour `X-Forwarded-Proto` in `setSessionCookie`** (`auth.go:372-382`). `Secure` is computed as `r.TLS != nil || !s.cfg.Insecure`, so behind `tailscale serve` (`--insecure --listen 127.0.0.1:8080`) the cookie is issued **without** `Secure` although the browser's connection is HTTPS. One line, gated on `s.isTrustedProxy(peer)`. Mandatory companion in that deployment: `--trusted-proxies 127.0.0.1`, or `clientIP` returns 127.0.0.1 for every request and the 10/min login limiter becomes **global** rather than per-device.
5. **Pairing code (phase 2)** so the phone never types a password plus a TOTP digit. `POST /api/pair` on the **inner** api mux (inherits `requireUser` + CSRF) mints `randomHex(5)` bound to the caller, single use, ~120 s, in an in-memory mutex-guarded map exactly like `s.desktops.pending` (dying with the process is the right failure mode). `POST /api/auth/pair` on the **outer** mux wrapped in `s.authGuard`, gated by the existing `loginLimiter`, compares with `constantTimeEqual`, then `createSession` + `setSessionCookie` + an audit row. The QR gains `&code=`.
6. **Certificate hot-reload** — only if the `tailscale cert` route is taken. The keypair is read once at `server.New` into a static `tls.Config.Certificates` with no `GetCertificate` callback, no SIGHUP and no file watcher, so replacing the files does nothing until restart.

---

## 10. Build, sign, install

**Toolchain state on this PC — verified this session, do not budget bring-up for it.** `JAVA_HOME` is already `C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot`. `C:\Android\Sdk` already contains `build-tools/35.0.0`, `platforms/android-35`, `platform-tools`, `cmdline-tools/latest` and `licenses/` including `android-sdk-license` (7 files). Earlier notes claiming `cmdline-tools` is empty or `JAVA_HOME` is unset are **stale**. What remains: `ANDROID_HOME` on PATH, `android/local.properties`, and the wrapper bootstrap.

```powershell
$env:ANDROID_HOME = 'C:\Android\Sdk'
$env:PATH = "$env:JAVA_HOME\bin;$env:ANDROID_HOME\platform-tools;$env:PATH"
# android/local.properties (gitignored):  sdk.dir=C\:\\Android\\Sdk
```

**Wrapper bootstrap (once).** `gradle-wrapper.jar` is executable code committed to the repo, so its only acceptable provenance is "generated by a checksum-verified Gradle distribution" — never copied from another project or a template. Download `gradle-8.14.3-bin.zip`, verify sha256 `bd71102213493060956ec229d946beee57158dbd89d0e62b91bca0fa2c5f3531`, unzip to `C:\Gradle`, then from `android/`:

```powershell
C:\Gradle\gradle-8.14.3\bin\gradle.bat wrapper --gradle-version 8.14.3 --distribution-type bin
Get-FileHash .\gradle\wrapper\gradle-wrapper.jar -Algorithm SHA256   # 7d3a4ac4de1c32b59bc6a4eb8ecb8e612ccd0cf1ae1e99f66902da64df296172
Add-Content .\gradle\wrapper\gradle-wrapper.properties 'distributionSha256Sum=bd71102213493060956ec229d946beee57158dbd89d0e62b91bca0fa2c5f3531'
```

That last line makes every future `gradlew` re-verify its own distribution. `C:\Gradle` can then be deleted. (`winget` is not an option — there is no `Gradle.Gradle` package on this machine's sources.)

**Release keystore, outside the repository:**

```powershell
& "$env:JAVA_HOME\bin\keytool.exe" -genkeypair -v `
  -keystore C:\Users\temp\.android-keys\homelab-rmm-release.jks `
  -storetype PKCS12 -keyalg RSA -keysize 4096 -validity 10000 `
  -alias rmm -dname "CN=Homelab RMM, O=Homelab"
```

Passwords via `RMM_KS_PASS` / `RMM_KEY_PASS` or a gitignored `android/keystore.properties`. `enableV1Signing = false`, v2 + v3 on (minSdk 30 makes v1 pointless). **Back this keystore up before the first install**: the AndroidKeyStore key that seals the server list is bound to the signing identity and UID, so changing keystores later destroys the sealed pins irrecoverably, and a debug-signed APK cannot be upgraded in place by a release-signed one. Never ship the debug keystore.

**Build variants.**

- `release`: `isMinifyEnabled = false` for v1 — R8 is deferred until the bridge surface stabilises. A WebView app that works in debug and breaks under minification is a classic, and the `WebMessageListener` choice removes the `@JavascriptInterface` keep-rule hazard only on the primary path, not the degraded one.
- `debug`: `applicationIdSuffix = ".debug"` so both APKs coexist, plus a **debug-only** `network_security_config` permitting cleartext to `127.0.0.1`. Driven over `adb reverse tcp:18080 tcp:18080`, this is the only way to exercise the app against the live `--insecure` dev server.

```powershell
.\gradlew.bat :trust:test          # the trust kernel gate — JVM, no device
.\gradlew.bat assembleRelease      # app\build\outputs\apk\release\app-release.apk
adb install -r app\build\outputs\apk\release\app-release.apk
```

**`.gitignore` additions:** `/android/local.properties`, `/android/keystore.properties`, `/android/.gradle/`, `/android/build/`, `/android/app/build/`, `/android/trust/build/`, `/android/*.jks`.

---

## 11. Testing

**Automated, no device:** `./gradlew :trust:test` (§5.6). This is the only automated gate that exists on this machine — there is no emulator.

**Read this before the first device test, or an hour disappears:** the live dev server runs `--insecure` over **plain HTTP** with `"fingerprint":""` (verified). The release build sets `cleartextTrafficPermitted="false"` and therefore **cannot reach `http://127.0.0.1:18080` by design. That is correct behaviour, not a defect.** Use the `.debug` variant over `adb reverse tcp:18080 tcp:18080`, or stand up a separate TLS `rmm-server` instance with a generated certificate.

**Device smoke list, in order:**

1. **A2 spike** — the gating `wss://` question, before anything else is built.
2. Connection test, all five rows, against a TLS instance.
3. Pin mismatch: point an entry at a second server; confirm the dead end and that nothing is stored.
4. Pin rotation: regenerate the server cert; confirm agents log `server certificate fingerprint mismatch` and the phone shows the mismatch screen — **document the rotation procedure before anyone does this by accident while chasing a SAN problem.**
5. The silent-failure cluster: Files upload (chooser), file download (pinned stream to `MediaStore.Downloads`), desktop Fullscreen, CSV export via the bridge.
6. Terminal with a real keyboard open: key bar, `resize` reaching the agent, rotation not killing the session.
7. Remote desktop trackpad gestures and the key bar (needs an agent in an interactive session — the agent on this box runs as SYSTEM in session 0 and reports `capture monitor 0: BitBlt failed`, so throughput and fit scale are **unmeasured**).
8. Renderer recovery: `adb shell am send-trim-memory <pid> COMPLETE`, confirm `onRenderProcessGone` rebuilds and reloads `lastPath`.
9. Background/foreground: SSE drops and resyncs via the synthetic `hello`; 1006 is not surfaced as an error.
10. Version skew: run the APK against a server whose `web/dist` predates `host.ts`; confirm the 1.5 s `loadUrl` fallback and that the console keeps its own drawer.
11. Release build separately from debug (R8 is off, but the NSC and signing differ).

**Bitdefender note:** this workstation's Bitdefender has already quarantined `dist\rmm-agent.exe` and blocked the service name. Expect it to take an interest in a freshly built unknown-publisher APK, the Gradle daemon's temp output and `adb`. Keep the keystore out of any Bitdefender-locked path.

---

## 12. Roadmap

**v1** (§§2–9): pinned shell, biometric gate, bottom bar, server picker, Trust review, Connection test, downloads/uploads/clipboard/fullscreen, console changes C1–C14. No server change.

**v1.1 — alert notifications, scoped and held to that scope.** A `WorkManager` periodic worker on the 15-minute floor does a pinned `GET /api/alerts?status=open&limit=50`, diffs ids against DataStore, posts on a high-importance channel grouped by device, with **Open** and **Ack** actions. `POST_NOTIFICATIONS` requested at first launch on API 33+. While foregrounded the badge comes from the SSE stream instead, so there is no duplicate polling. **No FCM** — the server's model is tailnet-only with no outbound internet.

Two hard constraints on this feature:

- The **Ack** action's `PendingIntent` must be `getActivity()` onto a small transparent Activity that gates and then POSTs. A `BroadcastReceiver` trampoline is **blocked on API 31+** (a receiver or service may not start an Activity from a notification action; the start is refused and the action appears to do nothing), and `BiometricPrompt` needs a `FragmentActivity` anyway. Alternatively the receiver performs the pinned POST with no UI at all and posts a result notification.
- **Exactly two endpoints.** If a third screen wants native data fetching, the WebView-shell premise is being abandoned by accident.

**v1.2+:** R8 on once the bridge surface stabilises · per-server profiles everywhere · a native tile decoder into a `SurfaceView` if the WebView canvas proves too slow · server changes 1–3.

**Rejected, with reasons recorded so nobody rebuilds them:** an in-app loopback relay (see §9/A2 fallback ranking — several hundred lines of Origin-rewriting proxy in the most security-sensitive path; it must rewrite `Origin` to the upstream `Host` because `relay.go` compares `strings.EqualFold(u.Host, r.Host)` literally and `Origin: null` parses to `""` and is refused, and it must proxy the `Upgrade` handshake and stream SSE unbuffered) · Compose in v1 · OkHttp · ML Kit barcode · everything in §2.6.

### Fallback if the A2 spike fails

Do **not** reach for the relay. Prefer the operator-side move: `tailscale cert <magicdns>` + `rmm-server --cert/--key`, with the app entry switched to `trustMode = SYSTEM`. State the cost up front and accept it knowingly: **every agent must be re-enrolled with `--fingerprint ""`**, plus an `rmm-server` restart per ~90-day renewal (§9.6). Self-signed-plus-pin and `tailscale cert` are mutually exclusive — one listener, one certificate, one fingerprint.
