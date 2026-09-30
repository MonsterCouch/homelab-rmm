//go:build windows

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"unsafe"
)

func TestProbeServer(t *testing.T) {
	// 1. Responding server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/state" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"configured": true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	if !probeServer(ts.URL, 1*time.Second) {
		t.Fatalf("expected probeServer to succeed on %s", ts.URL)
	}

	// 2. Non-responding server
	if probeServer("http://127.0.0.1:59999", 200*time.Millisecond) {
		t.Fatal("expected probeServer to fail on unused port")
	}
}

func TestNotifyIconDataSize(t *testing.T) {
	var nid NOTIFYICONDATAW
	size := unsafe.Sizeof(nid)
	// On Windows 64-bit, NOTIFYICONDATAW with Vista+ fields (GUID + HBalloonIcon) is 976 bytes,
	// or 952 bytes (XP), or 936 bytes (2000).
	t.Logf("NOTIFYICONDATAW size on this platform: %d bytes", size)
	if size < 936 || size > 1024 {
		t.Fatalf("unexpected NOTIFYICONDATAW size: %d", size)
	}
}

func TestGetAppIcon(t *testing.T) {
	icon := getAppIcon()
	if icon == 0 {
		t.Fatal("expected getAppIcon to return a valid handle")
	}
}

func TestRenderOfflinePage(t *testing.T) {
	html := renderOfflinePage("https://my-rmm.internal:8443")
	if html == "" {
		t.Fatal("expected non-empty HTML")
	}
	if !containsSubstring(html, "https://my-rmm.internal:8443") {
		t.Fatal("expected server URL in rendered HTML")
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && len(sub) > 0 && stringContains(s, sub)))
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
