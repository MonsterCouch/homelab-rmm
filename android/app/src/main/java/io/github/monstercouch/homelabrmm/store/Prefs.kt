package io.github.monstercouch.homelabrmm.store

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/** Separate file from the sealed list, deliberately. See [Prefs]. */
private val Context.rmmPrefs: DataStore<Preferences> by preferencesDataStore(name = "rmm_prefs")

/**
 * The unsealed, non-security state: which server was last used, where the
 * console was, and the handful of knobs in App settings.
 *
 * None of this is in the sealed blob, and that is a design decision rather than
 * an oversight. `lastPath` changes on every `onPageFinished`; putting it beside
 * the pins would put the trust blob through a re-encrypt-and-write cycle dozens
 * of times a session, widening the window in which a bad write costs the
 * operator every pin. Losing any value in this file costs one tap.
 */
class Prefs(private val context: Context) {

    private val ds get() = context.rmmPrefs

    // ---- server selection and restore ------------------------------------

    suspend fun lastServerId(): String? = ds.data.first()[LAST_SERVER]

    suspend fun setLastServerId(id: String) = edit { it[LAST_SERVER] = id }

    /**
     * The console path to restore after process death. Per server, because
     * switching servers should not carry a device id from one fleet to another.
     *
     * `WebView.saveState` is deliberately not used for this: it persists only
     * the back/forward list and can blow the 1 MB Binder limit.
     */
    suspend fun lastPath(serverId: String): String =
        ds.data.first()[lastPathKey(serverId)] ?: "/"

    suspend fun setLastPath(serverId: String, path: String) =
        edit { it[lastPathKey(serverId)] = path }

    suspend fun clearServer(serverId: String) = edit {
        it.remove(lastPathKey(serverId))
        if (it[LAST_SERVER] == serverId) it.remove(LAST_SERVER)
    }

    // ---- App settings ----------------------------------------------------

    /**
     * Seconds the app may stay backgrounded before the biometric gate re-arms.
     * 0 / 30 / 60 / 300, default 60: flipping to Tailscale, an authenticator or
     * the system file picker must not re-prompt.
     */
    suspend fun lockGraceSeconds(): Int = ds.data.first()[LOCK_GRACE] ?: DEFAULT_LOCK_GRACE

    suspend fun setLockGraceSeconds(seconds: Int) = edit { it[LOCK_GRACE] = seconds }

    /**
     * FLAG_SECURE on the window, default on, so the recents thumbnail and
     * screenshots cannot leak a device list or a live terminal. Honest cost:
     * it also blocks the owner's own screen recordings.
     */
    fun blockScreenshots(): Flow<Boolean> = ds.data.map { it[BLOCK_SCREENSHOTS] ?: true }

    suspend fun blockScreenshotsNow(): Boolean = ds.data.first()[BLOCK_SCREENSHOTS] ?: true

    suspend fun setBlockScreenshots(on: Boolean) = edit { it[BLOCK_SCREENSHOTS] = on }

    /**
     * Remote-desktop quality on a coarse pointer: 35, not the console's 60.
     * A 1920x1080 session fits at 0.19x in a phone-width wrapper, so the extra
     * bytes buy nothing a fingertip can see.
     */
    suspend fun desktopQuality(): Int = ds.data.first()[DESKTOP_QUALITY] ?: DEFAULT_DESKTOP_QUALITY

    suspend fun setDesktopQuality(q: Int) = edit { it[DESKTOP_QUALITY] = q.coerceIn(5, 95) }

    private suspend fun edit(block: (androidx.datastore.preferences.core.MutablePreferences) -> Unit) {
        ds.edit(block)
    }

    companion object {
        const val DEFAULT_LOCK_GRACE = 60
        const val DEFAULT_DESKTOP_QUALITY = 35

        private val LAST_SERVER = stringPreferencesKey("last_server_id")
        private val LOCK_GRACE = intPreferencesKey("lock_grace_seconds")
        private val BLOCK_SCREENSHOTS = booleanPreferencesKey("block_screenshots")
        private val DESKTOP_QUALITY = intPreferencesKey("desktop_quality")

        private fun lastPathKey(serverId: String) = stringPreferencesKey("last_path.$serverId")
    }
}
