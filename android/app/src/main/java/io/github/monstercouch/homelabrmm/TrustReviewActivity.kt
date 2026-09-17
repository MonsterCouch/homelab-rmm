package io.github.monstercouch.homelabrmm

import androidx.appcompat.app.AppCompatActivity

/**
 * The human confirmation gate, and the only place trust is created.
 *
 * FOUNDATION STAGE - filled in by task A14. The two halves it needs already
 * exist: `Fingerprint.rows()` renders 4 rows of 4 groups of 4 characters,
 * uniform and with no emphasis on the first or last bytes, and
 * `PinnedHttp.probeAuthState()` runs the pinned `GET /api/auth/state` that must
 * succeed before an entry is sealed.
 *
 * You cannot store a pin you have not successfully used.
 */
class TrustReviewActivity : AppCompatActivity()
