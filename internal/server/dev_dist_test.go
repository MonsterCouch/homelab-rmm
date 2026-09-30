package server

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDevDistDir_Unset(t *testing.T) {
	t.Setenv("RMM_DEV_DIST_DIR", "")
	t.Setenv("RMM_DEV_DIST", "")

	if got := devDistDir(); got != "" {
		t.Fatalf("expected empty devDistDir when env vars are unset, got %q", got)
	}
}

func TestDevDistDir_NonexistentOrFile(t *testing.T) {
	t.Setenv("RMM_DEV_DIST", "")

	// 1. Nonexistent directory
	t.Setenv("RMM_DEV_DIST_DIR", filepath.Join(t.TempDir(), "nonexistent_dir_12345"))
	if got := devDistDir(); got != "" {
		t.Fatalf("expected empty devDistDir for nonexistent directory, got %q", got)
	}

	// 2. Regular file instead of a directory
	tmpFile := filepath.Join(t.TempDir(), "not_a_dir.txt")
	if err := os.WriteFile(tmpFile, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RMM_DEV_DIST_DIR", tmpFile)
	if got := devDistDir(); got != "" {
		t.Fatalf("expected empty devDistDir when pointing to a regular file, got %q", got)
	}
}

func TestDevDistDir_ValidDirectory(t *testing.T) {
	t.Setenv("RMM_DEV_DIST", "")

	tmpDir := t.TempDir()
	t.Setenv("RMM_DEV_DIST_DIR", tmpDir)

	if got := devDistDir(); got != tmpDir {
		t.Fatalf("expected %q, got %q", tmpDir, got)
	}
}

func TestDevDistDir_DevFlag(t *testing.T) {
	t.Setenv("RMM_DEV_DIST_DIR", "")

	// When dist exists and is a directory
	if st, err := os.Stat("dist"); err == nil && st.IsDir() {
		t.Setenv("RMM_DEV_DIST", "1")
		if got := devDistDir(); got != "dist" {
			t.Fatalf("expected 'dist', got %q", got)
		}
	}
}

func TestAgentBinaryPath_WithDevDistDir(t *testing.T) {
	s, _ := newServerOnly(t, Config{})

	devDir := t.TempDir()
	t.Setenv("RMM_DEV_DIST_DIR", devDir)
	t.Setenv("RMM_DEV_DIST", "")

	// Binary present in dev directory
	binName := "rmm-agent-linux-amd64"
	binPath := filepath.Join(devDir, binName)
	if err := os.WriteFile(binPath, []byte("mock binary content"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := s.agentBinaryPath("linux", "amd64")
	if got != binPath {
		t.Fatalf("expected agentBinaryPath to return %q, got %q", binPath, got)
	}

	// Binary not present in dev directory
	gotMissing := s.agentBinaryPath("linux", "arm")
	if gotMissing != "" {
		t.Fatalf("expected empty string for missing arch, got %q", gotMissing)
	}
}

func TestAgentMSIPath_WithDevDistDir(t *testing.T) {
	s, _ := newServerOnly(t, Config{})

	devDir := t.TempDir()
	t.Setenv("RMM_DEV_DIST_DIR", devDir)
	t.Setenv("RMM_DEV_DIST", "")

	msiPath := filepath.Join(devDir, "rmm-agent-windows-amd64.msi")
	if err := os.WriteFile(msiPath, []byte("mock msi content"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := s.agentMSIPath()
	if got != msiPath {
		t.Fatalf("expected agentMSIPath to return %q, got %q", msiPath, got)
	}
}

func TestFindStagedServerBinary_WithDevDistDir(t *testing.T) {
	s, _ := newServerOnly(t, Config{})

	devDir := t.TempDir()
	t.Setenv("RMM_DEV_DIST_DIR", devDir)
	t.Setenv("RMM_DEV_DIST", "")

	var binName string
	if runtime.GOOS == "windows" {
		binName = "rmm-server.exe"
	} else {
		binName = "rmm-server"
	}
	serverBinPath := filepath.Join(devDir, binName)
	if err := os.WriteFile(serverBinPath, []byte("mock server binary content"), 0o755); err != nil {
		t.Fatal(err)
	}

	stagedPath, st, err := s.findStagedServerBinary()
	if err != nil {
		t.Fatalf("findStagedServerBinary failed: %v", err)
	}
	if stagedPath != serverBinPath {
		t.Fatalf("expected %q, got %q", serverBinPath, stagedPath)
	}
	if st.Size() == 0 {
		t.Fatal("expected non-zero size for staged binary")
	}
}

func TestDevDistDir_InvalidPathDoesNotPanic(t *testing.T) {
	s, _ := newServerOnly(t, Config{})

	t.Setenv("RMM_DEV_DIST_DIR", filepath.Join(t.TempDir(), "nonexistent_sub", "path"))
	t.Setenv("RMM_DEV_DIST", "")

	if got := s.agentBinaryPath("windows", "amd64"); got != "" {
		t.Fatalf("expected empty for invalid dev dir, got %q", got)
	}

	if got := s.agentMSIPath(); got != "" {
		t.Fatalf("expected empty MSI for invalid dev dir, got %q", got)
	}

	if _, _, err := s.findStagedServerBinary(); err == nil {
		t.Fatal("expected error from findStagedServerBinary with invalid dev dir")
	}
}
