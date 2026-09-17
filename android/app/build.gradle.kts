import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

// ---------------------------------------------------------------------------
// Release signing material. The keystore itself lives OUTSIDE this repository
// and is NEVER generated or committed by the build (docs/ANDROID.md §10):
//
//   keytool -genkeypair -v -keystore C:\Users\temp\.android-keys\homelab-rmm-release.jks \
//     -storetype PKCS12 -keyalg RSA -keysize 4096 -validity 10000 \
//     -alias rmm -dname "CN=Homelab RMM, O=Homelab"
//
// BACK THAT FILE UP BEFORE THE FIRST INSTALL. The AndroidKeyStore key that
// seals the server list is bound to the app UID and the signing identity, so
// changing keystores later destroys every stored pin irrecoverably - and a
// debug-signed APK cannot be upgraded in place by a release-signed one.
//
// Values come from a gitignored android/keystore.properties, or from the
// environment (RMM_KEYSTORE / RMM_KS_PASS / RMM_KEY_ALIAS / RMM_KEY_PASS).
// Nothing here ever falls back to the world-known debug keystore for a release.
// ---------------------------------------------------------------------------
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.isFile) f.inputStream().use { load(it) }
}

fun signingValue(key: String, env: String): String? =
    keystoreProps.getProperty(key)?.takeIf { it.isNotBlank() }
        ?: System.getenv(env)?.takeIf { it.isNotBlank() }

val releaseKeystore: File? =
    signingValue("storeFile", "RMM_KEYSTORE")
        ?.let { File(it) }
        ?.takeIf { it.isFile }

android {
    namespace = "io.github.monstercouch.homelabrmm"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        // PERMANENT. Reverse-DNS from the Go module path
        // (github.com/MonsterCouch/homelab-rmm), a namespace the owner controls.
        // The AndroidKeyStore key that seals the server list is bound to the app
        // UID, so changing this later destroys every stored pin.
        applicationId = "io.github.monstercouch.homelabrmm"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "1.0"
        // No androidTest runner is declared: there is no emulator on this
        // machine, and :trust:test is the gate that must stay device-free.
    }

    signingConfigs {
        create("release") {
            if (releaseKeystore != null) {
                storeFile = releaseKeystore
                storePassword = signingValue("storePassword", "RMM_KS_PASS")
                keyAlias = signingValue("keyAlias", "RMM_KEY_ALIAS") ?: "rmm"
                keyPassword = signingValue("keyPassword", "RMM_KEY_PASS")
            }
            // minSdk 30 makes the v1 (JAR) scheme pointless; v2 + v3 are what
            // the platform actually verifies.
            enableV1Signing = false
            enableV2Signing = true
            enableV3Signing = true
            enableV4Signing = false
        }
    }

    buildTypes {
        release {
            // R8 is DEFERRED to v1.2 (task A20), not forgotten. A WebView app
            // that works in debug and breaks under minification is a classic,
            // and the degraded @JavascriptInterface bridge path still carries a
            // keep-rule hazard. Turn this on only once the bridge stabilises.
            isMinifyEnabled = false
            isShrinkResources = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = if (releaseKeystore != null) signingConfigs.getByName("release") else null
            // res/xml/shortcuts.xml needs the concrete applicationId, and a
            // res/xml file cannot see a manifest placeholder.
            resValue("string", "app_id", "io.github.monstercouch.homelabrmm")
        }
        debug {
            // Both APKs coexist on one phone, so the debug build can be driven
            // against the live --insecure dev server while the release build
            // stays installed and pinned.
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            isMinifyEnabled = false
            resValue("string", "app_id", "io.github.monstercouch.homelabrmm.debug")
            // src/debug/res/xml/network_security_config.xml overrides the main
            // one by resource merging: cleartext to 127.0.0.1 ONLY, for
            // `adb reverse tcp:18080 tcp:18080`. See that file and
            // src/debug/AndroidManifest.xml.
        }
    }

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        // The foundation stage ships activity skeletons that later tasks fill
        // in; lint's structural checks are re-enabled with R8 in v1.2 (A20).
        abortOnError = false
    }

    packaging {
        resources.excludes += setOf(
            "META-INF/AL2.0",
            "META-INF/LGPL2.1",
            "DebugProbesKt.bin",
        )
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // The trust kernel. Pure JVM, so ./gradlew :trust:test needs no device.
    implementation(project(":trust"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.activity.ktx)
    implementation(libs.material)
    implementation(libs.androidx.webkit)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.datastore.prefs)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.zxing.embedded)

    // No OkHttp: net/PinnedHttp.kt is HttpsURLConnection, and two native call
    // sites do not justify the dependency (docs/ANDROID.md §2.6, §3.3).
    // No androidx.security:security-crypto: every API in it is deprecated in
    // favour of direct AndroidKeyStore use, which is what store/Keystore.kt does.
}
