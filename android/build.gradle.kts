// Plugin aliases only - no buildscript{} block, no allprojects{} repositories.
// Every version lives in gradle/libs.versions.toml (docs/ANDROID.md §3.1).
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.jvm) apply false
}
