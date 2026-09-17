package io.github.monstercouch.homelabrmm

import androidx.appcompat.app.AppCompatActivity

/**
 * Manual entry, scan result, and the `homelabrmm://pair` deep-link target.
 *
 * FOUNDATION STAGE - filled in by task A14. The parsing half already exists and
 * is tested with no device: `trust/PairUri.kt`, which normalises the URL, folds
 * a pasted fingerprint (colons and whitespace stripped, lower-cased) and refuses
 * `http://`, a short fingerprint and an empty host.
 *
 * Nothing is stored here. All three pairing channels converge on Trust review,
 * and a deep link never auto-adds and never auto-navigates.
 */
class AddServerActivity : AppCompatActivity()
