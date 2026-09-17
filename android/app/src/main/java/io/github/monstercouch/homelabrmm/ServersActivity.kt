package io.github.monstercouch.homelabrmm

import androidx.appcompat.app.AppCompatActivity

/**
 * Server list: one-tap switching, rename / show pin / forget, Add server and
 * Export list.
 *
 * FOUNDATION STAGE - filled in by task A14. It renders BEFORE the biometric
 * prompt on the re-lock path, which is exactly why the AndroidKeyStore key in
 * `store/Keystore.kt` carries no `setUserAuthenticationRequired` binding.
 */
class ServersActivity : AppCompatActivity()
