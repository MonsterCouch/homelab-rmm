// android/ is a SEPARATE Gradle build from the Go module and the Vite console.
// Nothing here is reachable from `go build ./...` or `npm run build`, and the
// Makefile's apk: target deliberately does not hang off `all` - the Go/web build
// must stay usable on a machine with no Android SDK. See docs/ANDROID.md §3.1.

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    // Subprojects declaring their own repositories is how a build quietly starts
    // resolving the trust kernel from somewhere unreviewed.
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "homelab-rmm-android"

include(":app", ":trust")
