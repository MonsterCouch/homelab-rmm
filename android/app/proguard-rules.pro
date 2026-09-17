# R8 is OFF for v1 (isMinifyEnabled = false). This file exists so that turning
# it on in v1.2 (task A20) starts from the rules that are already known to be
# needed, rather than from a blank file and a broken bridge.
#
# When R8 is enabled, verify in this order - all three fail silently:
#   1. the WebMessageListener bridge ("RmmHost") still receives `hello`;
#   2. the degraded @JavascriptInterface fallback still works on a device whose
#      WebView lacks WEB_MESSAGE_LISTENER;
#   3. onShowFileChooser / onShowCustomView / DownloadListener still fire.

# Any @JavascriptInterface member is reached only from JavaScript, so R8 cannot
# see the call and will strip it. This is the degraded bridge path (§3.6).
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# The trust kernel is small, security-critical and reflected over by nothing.
# Keeping it intact keeps stack traces from the pin path readable in a bug report.
-keep class io.github.monstercouch.homelabrmm.trust.** { *; }

# WebView clients are instantiated by us but called back from native code.
-keep class * extends android.webkit.WebViewClient { *; }
-keep class * extends android.webkit.WebChromeClient { *; }

-keepattributes SourceFile,LineNumberTable,*Annotation*
