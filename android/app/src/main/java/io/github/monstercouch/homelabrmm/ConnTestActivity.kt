package io.github.monstercouch.homelabrmm

import androidx.appcompat.app.AppCompatActivity

/**
 * The five-row Connection test.
 *
 * FOUNDATION STAGE - filled in by task A16, which is also the task that answers
 * the gating `wss://` question on a real phone (no device is attached here, so
 * the A2 spike was not run; the Chromium path is traced in docs/ANDROID.md §1
 * and row 4 is what confirms it in the field).
 *
 * Rows 1 and 5 are already implementable from `net/PinnedHttp.kt`:
 * `probeAuthState()` and `upgradeProbe()`, the latter reading the server's
 * status line directly off an SSLSocket because the platform URL stack will not
 * let a caller set `Connection: Upgrade`.
 */
class ConnTestActivity : AppCompatActivity()
