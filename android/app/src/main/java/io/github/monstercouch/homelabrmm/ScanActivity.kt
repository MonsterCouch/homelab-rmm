package io.github.monstercouch.homelabrmm

import androidx.appcompat.app.AppCompatActivity

/**
 * The bundled ZXing scanner host, restricted to QR_CODE.
 *
 * FOUNDATION STAGE - filled in by task A15. It is bundled rather than delegated
 * to the phone's own camera app because "the camera resolves the custom scheme"
 * is not reliable: stock camera and Lens surface an open affordance for
 * `http(s)` and a short list of well-known schemes, and commonly render an
 * arbitrary custom scheme as inert raw text. An `https` App Link is no
 * substitute either - `autoVerify` needs a publicly fetchable
 * `/.well-known/assetlinks.json` over publicly-trusted TLS, which a self-signed
 * tailnet host cannot serve.
 *
 * exported="false": nothing outside the app may start the camera.
 */
class ScanActivity : AppCompatActivity()
