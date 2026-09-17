// :trust is kotlin("jvm"), NOT com.android.library, on purpose.
//
// There is no emulator on this machine, so `./gradlew :trust:test` is the only
// automated verification gate that exists - and it must genuinely need no
// device. An Android library module would run its unit tests against the stub
// android.jar, where anything touching android.net.Uri throws
// "Method parse in android.net.Uri not mocked". PairUri therefore parses with
// java.net.URI and this module depends on nothing Android. (docs/ANDROID.md §3.1)

plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    testImplementation(libs.junit)
}

// proceed_appears_exactly_once scans the sibling source trees, so it needs to
// know where the android/ build root is regardless of the test working dir.
val androidRoot = rootProject.layout.projectDirectory.asFile.absolutePath

tasks.test {
    useJUnit()
    systemProperty("rmm.android.root", androidRoot)
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
