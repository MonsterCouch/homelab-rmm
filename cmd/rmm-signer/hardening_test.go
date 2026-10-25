package main

import (
	"strings"
	"testing"
)

func TestOneKeepsFieldsOnTheirOwnLine(t *testing.T) {
	got := one("x\nOperation     fs.list")
	if strings.Contains(got, "\n") {
		t.Fatalf("a newline survived: %q", got)
	}
}

func TestSafeEscapesInvisibleCharacters(t *testing.T) {
	for _, r := range []rune{0x200b, 0x200d, 0x200e, 0x200f, 0x061c, 0x2060, 0x00ad, 0xe0041, 0x2028, 0x202e} {
		got := safe("a" + string(r) + "b")
		if strings.ContainsRune(got, r) {
			t.Errorf("U+%04X was printed raw: %q", r, got)
		}
	}
	if got := safe("plain text é"); got != "plain text é" {
		t.Errorf("ordinary text changed: %q", got)
	}
}

func TestNormalizeServerDropsDefaultPort(t *testing.T) {
	for in, want := range map[string]string{
		"https://Host:443":      "https://host",
		"http://host:80":        "http://host",
		"https://host:8443":     "https://host:8443",
		"https://host:443/rmm/": "https://host",
	} {
		_, origin, err := normalizeServer(in)
		if err != nil || origin != want {
			t.Errorf("%s: origin %q, err %v; want %q", in, origin, err, want)
		}
	}
}

func TestLoginRefusesPlainHTTPExceptLoopback(t *testing.T) {
	if requireSecureLogin("http://rmm.example.com") == nil {
		t.Error("http to a remote host was allowed")
	}
	for _, ok := range []string{"https://rmm.example.com", "http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"} {
		if err := requireSecureLogin(ok); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
}
