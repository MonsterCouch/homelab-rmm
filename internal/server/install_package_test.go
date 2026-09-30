package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallPackageEndpoints(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})

	// Set up agent binaries in test data directory
	agentsDir := s.cfg.path("agents")
	if err := os.MkdirAll(agentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if msiData, err := os.ReadFile(filepath.Join("..", "..", "dist", "rmm-agent-v0.3.0-x64.msi")); err == nil {
		_ = os.WriteFile(filepath.Join(agentsDir, "rmm-agent.msi"), msiData, 0o644)
	} else {
		_ = os.WriteFile(filepath.Join(agentsDir, "rmm-agent.msi"), []byte("DUMMY_MSI_COMPOUND_DOCUMENT_HEADER"), 0o644)
	}
	if binData, err := os.ReadFile(filepath.Join("..", "..", "dist", "rmm-agent-linux-amd64")); err == nil {
		_ = os.WriteFile(filepath.Join(agentsDir, "rmm-agent-linux-amd64"), binData, 0o755)
	} else {
		_ = os.WriteFile(filepath.Join(agentsDir, "rmm-agent-linux-amd64"), []byte("DUMMY_LINUX_AGENT_BINARY_PAYLOAD"), 0o755)
	}

	// 1. Create an enroll token
	var created struct {
		ID    int    `json:"id"`
		Token string `json:"token"`
	}
	b.mustJSON("POST", "/api/enroll", map[string]any{
		"name":      "pkg-test-token",
		"uses":      5,
		"ttl_hours": 24,
	}, &created)

	if created.Token == "" {
		t.Fatal("expected created token")
	}

	client := ts.Client()

	// 2. Test MSI Endpoint
	t.Run("MSI Package Download", func(t *testing.T) {
		resp, err := client.Get(ts.URL + "/install/" + created.Token + "/msi")
		if err != nil {
			t.Fatalf("failed to GET msi: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		if ct := resp.Header.Get("Content-Type"); ct != "application/x-msi" {
			t.Errorf("expected Content-Type application/x-msi, got %q", ct)
		}
		if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "HomelabRMM-Agent.msi") {
			t.Errorf("expected Content-Disposition with HomelabRMM-Agent.msi, got %q", cd)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		// Verify binary overlay presence
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "[HOMELAB_RMM_CONFIG]") {
			t.Error("MSI payload missing [HOMELAB_RMM_CONFIG] start tag")
		}
		if !strings.Contains(bodyStr, "[END_HOMELAB_RMM_CONFIG]") {
			t.Error("MSI payload missing [END_HOMELAB_RMM_CONFIG] end tag")
		}
		if !strings.Contains(bodyStr, "TOKEN="+created.Token) {
			t.Errorf("MSI payload missing TOKEN=%s", created.Token)
		}
		if !strings.Contains(bodyStr, "SERVER="+s.PublicURL()) {
			t.Errorf("MSI payload missing SERVER=%s", s.PublicURL())
		}
	})

	// 3. Test DEB Endpoint
	t.Run("Deb Package Download and Structure", func(t *testing.T) {
		resp, err := client.Get(ts.URL + "/install/" + created.Token + "/deb?arch=amd64")
		if err != nil {
			t.Fatalf("failed to GET deb: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		if ct := resp.Header.Get("Content-Type"); ct != "application/vnd.debian.binary-package" {
			t.Errorf("expected Content-Type application/vnd.debian.binary-package, got %q", ct)
		}
		if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "homelab-rmm-agent_amd64.deb") {
			t.Errorf("expected Content-Disposition with homelab-rmm-agent_amd64.deb, got %q", cd)
		}

		debBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read deb body: %v", err)
		}

		// Must start with ar signature "!<arch>\n"
		if !bytes.HasPrefix(debBytes, []byte("!<arch>\n")) {
			t.Fatal("invalid deb package: missing ar signature")
		}

		// Extract data.tar.gz member from the ar archive
		dataGzBytes := extractArMember(t, debBytes, "data.tar.gz")
		if len(dataGzBytes) == 0 {
			t.Fatal("data.tar.gz not found in deb package")
		}

		// Uncompress and untar data.tar.gz
		gr, err := gzip.NewReader(bytes.NewReader(dataGzBytes))
		if err != nil {
			t.Fatalf("failed to gzip decompress data.tar.gz: %v", err)
		}
		defer gr.Close()

		tr := tar.NewReader(gr)
		var foundAgentJSON bool
		var agentJSONContent []byte

		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed reading tar: %v", err)
			}
			if hdr.Name == "./etc/homelab-rmm/agent.json" {
				foundAgentJSON = true
				agentJSONContent, _ = io.ReadAll(tr)
			}
		}

		if !foundAgentJSON {
			t.Fatal("./etc/homelab-rmm/agent.json not found inside data.tar.gz")
		}

		var cfg map[string]string
		if err := json.Unmarshal(agentJSONContent, &cfg); err != nil {
			t.Fatalf("failed to parse agent.json: %v", err)
		}

		if cfg["enroll_token"] != created.Token {
			t.Errorf("expected enroll_token %s, got %s", created.Token, cfg["enroll_token"])
		}
		if cfg["server_url"] != s.PublicURL() {
			t.Errorf("expected server_url %s, got %s", s.PublicURL(), cfg["server_url"])
		}
	})

	// 4. Test Invalid / Expired Token
	t.Run("Invalid Token 404", func(t *testing.T) {
		resp, err := client.Get(ts.URL + "/install/nonexistenttoken12345/msi")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 for invalid msi token, got %d", resp.StatusCode)
		}

		resp2, err := client.Get(ts.URL + "/install/nonexistenttoken12345/deb")
		if err != nil {
			t.Fatal(err)
		}
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 for invalid deb token, got %d", resp2.StatusCode)
		}
	})
}

// extractArMember extracts the contents of a member from an ar archive
func extractArMember(t *testing.T, arData []byte, memberName string) []byte {
	t.Helper()
	if len(arData) < 8 || string(arData[:8]) != "!<arch>\n" {
		t.Fatal("not an ar archive")
	}
	offset := 8
	for offset < len(arData) {
		if offset+60 > len(arData) {
			break
		}
		header := arData[offset : offset+60]
		name := strings.TrimSpace(string(header[:16]))
		sizeStr := strings.TrimSpace(string(header[48:58]))
		var size int
		for _, ch := range sizeStr {
			if ch >= '0' && ch <= '9' {
				size = size*10 + int(ch-'0')
			}
		}
		offset += 60
		if offset+size > len(arData) {
			break
		}
		content := arData[offset : offset+size]
		if name == memberName {
			return content
		}
		offset += size
		if offset%2 != 0 {
			offset++
		}
	}
	return nil
}
