package io.github.monstercouch.homelabrmm

import android.app.Application

/**
 * The Application object.
 *
 * FOUNDATION STAGE. Task A11 attaches the `ProcessLifecycleOwner` observer that
 * drives `lock/LockState` here - ON_STOP plus the configured grace period is
 * what re-arms the biometric gate, and it has to be process-wide so that
 * flipping to Tailscale, an authenticator or the system file picker does not
 * re-prompt on the way back.
 *
 * Nothing is read from disk in `onCreate`: the cold-start order is gate first,
 * sealed list second.
 */
class App : Application()
