package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadTaggedConfig(t *testing.T) {
	tmp := t.TempDir()
	msiPath := filepath.Join(tmp, "HomelabRMM-Agent.msi")

	// Dummy base MSI data
	baseData := make([]byte, 1024)
	for i := range baseData {
		baseData[i] = 0xAA
	}

	tagPayload := "\n[HOMELAB_RMM_CONFIG]\nSERVER=https://rmm.lan:8443\nTOKEN=tok_secret123456\nFINGERPRINT=aa:bb:cc\n[END_HOMELAB_RMM_CONFIG]\n"
	fullData := append(baseData, []byte(tagPayload)...)

	if err := os.WriteFile(msiPath, fullData, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := readTaggedConfig(msiPath)
	if err != nil {
		t.Fatalf("failed to read tagged config: %v", err)
	}
	if cfg.Server != "https://rmm.lan:8443" {
		t.Errorf("got server %q, want https://rmm.lan:8443", cfg.Server)
	}
	if cfg.Token != "tok_secret123456" {
		t.Errorf("got token %q, want tok_secret123456", cfg.Token)
	}
	if cfg.Fingerprint != "aa:bb:cc" {
		t.Errorf("got fp %q, want aa:bb:cc", cfg.Fingerprint)
	}

	// Non-tagged file should error cleanly
	untaggedPath := filepath.Join(tmp, "untagged.msi")
	os.WriteFile(untaggedPath, baseData, 0o644)
	if _, err := readTaggedConfig(untaggedPath); err == nil {
		t.Error("expected error reading untagged file, got nil")
	}
}
