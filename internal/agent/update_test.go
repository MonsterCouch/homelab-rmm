package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What agent.update installs runs as SYSTEM/root on the next restart. An
// empty sha256 used to skip verification entirely, and the transport is no
// backstop: a device with no pinned fingerprint gets a plain tls.Config, and
// the URL was unconstrained, so http:// bypassed TLS altogether (upd-01).
func TestSelfUpdateRequiresAHashAndRefusesBeforeFetching(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte("payload"))
	}))
	defer srv.Close()
	cfg := &Config{ServerURL: srv.URL}

	for _, sum := range []string{
		"",
		"deadbeef",
		strings.Repeat("z", 64),
		strings.Repeat("a", 63),
		" " + strings.Repeat("a", 64),
	} {
		err := doSelfUpdate(context.Background(), cfg, srv.URL+"/rmm-agent", sum)
		if err == nil {
			t.Errorf("sha256 %q was accepted", sum)
			continue
		}
		if !strings.Contains(err.Error(), "sha256") {
			t.Errorf("sha256 %q: the refusal must name the reason, got %v", sum, err)
		}
	}
	if hits != 0 {
		t.Errorf("the binary was downloaded %d times before the hash was checked", hits)
	}
}

// The URL decides which host gets to hand this machine its next SYSTEM
// binary, so it is bounded too.
func TestCheckUpdateURL(t *testing.T) {
	const server = "http://rmm.lan:18080"
	for _, u := range []string{
		"https://rmm.lan:8443/api/agent-download/rmm-agent-windows-amd64.exe",
		"https://releases.example.com/rmm-agent",
		"http://rmm.lan:18080/api/agent-download/rmm-agent-linux-amd64",
		"HTTP://RMM.LAN:18080/x", // the host comparison is case-insensitive
	} {
		if err := checkUpdateURL(server, u); err != nil {
			t.Errorf("%s should be allowed: %v", u, err)
		}
	}
	for _, u := range []string{
		"http://attacker.example/x.exe",
		"http://rmm.lan:9999/x.exe", // same name, another port, another server
		"file:///C:/Windows/Temp/x.exe",
		"ftp://rmm.lan/x.exe",
		"/relative/path",
		"",
	} {
		if err := checkUpdateURL(server, u); err == nil {
			t.Errorf("%s must be refused", u)
		}
	}
	// A server the agent cannot parse is not a reason to trust plain http.
	if err := checkUpdateURL("", "http://rmm.lan/x"); err == nil {
		t.Error("plain http was accepted with no configured server to match")
	}
}
