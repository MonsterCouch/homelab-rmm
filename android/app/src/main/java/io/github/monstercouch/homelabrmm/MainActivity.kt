package io.github.monstercouch.homelabrmm

import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * The only long-lived Activity: toolbar, WebView host, bottom bar, lock overlay.
 *
 * FOUNDATION STAGE - this is a placeholder body so that the manifest, the
 * signing config and the resource set can be built and installed while the
 * shell itself is written. Tasks A11/A12/A13 replace it with the real thing:
 *
 *   - `FLAG_SECURE` first, then inflate the shell WITHOUT creating a WebView,
 *     then `BiometricGate.require()`; nothing is read from disk until it passes.
 *   - on success, open the sealed list, select `Prefs.lastServerId`, build the
 *     WebView and load `entry.url + lastPath`. An empty list goes to
 *     `ServersActivity`.
 *   - the window-insets listener that pads the WebView container by
 *     `max(ime.bottom, bars.bottom)`, which is what makes `100dvh` recompute and
 *     the terminal resize (console change C4 must land with it).
 *   - the `OnBackPressedDispatcher` chain: fullscreen, sheet, `{t:'back'}` with
 *     a 120 ms grace, `goBack()`, finish.
 *
 * The one line already worth having is FLAG_SECURE: the recents thumbnail must
 * not leak a device list or a live terminal even from a half-built app.
 */
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(
            TextView(this).apply {
                setText(R.string.foundation_placeholder)
                gravity = Gravity.CENTER
                setPadding(48, 48, 48, 48)
            }
        )
    }
}
