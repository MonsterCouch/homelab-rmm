package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

const testUploadID = "upl_0123456789abcdef"

func stageAll(t *testing.T, id string, data []byte, chunk int) {
	t.Helper()
	for off := 0; off < len(data) || off == 0; off += chunk {
		end := min(off+chunk, len(data))
		if err := fsStage(protocol.FsStage{UploadID: id, Offset: int64(off), Data: data[off:end]}); err != nil {
			t.Fatalf("stage at %d: %v", off, err)
		}
		if end == len(data) {
			break
		}
	}
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestStagedUploadCommit(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	dest := filepath.Join(t.TempDir(), "sub", "payload.bin")
	data := bytes.Repeat([]byte("homelab-rmm "), 300_000) // ~3.6 MB, well past the old 1 MiB cap
	stageAll(t, testUploadID, data, 1<<20)

	if err := fsCommit(protocol.FsCommit{UploadID: testUploadID, Path: dest, Size: int64(len(data)), SHA256: digest(data)}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("committed file differs (err %v, %d bytes)", err, len(got))
	}
	if _, err := os.Stat(filepath.Join(stagingDir(), testUploadID+".part")); !os.IsNotExist(err) {
		t.Error("the staging file outlived its commit")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), ".rmm-upload-*")); len(left) > 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

// What was staged is not what was signed: nothing reaches the destination,
// and an existing file there is untouched.
func TestStagedUploadMismatchRefused(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	dest := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(dest, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	signed := []byte("the file the operator approved")
	stageAll(t, testUploadID, []byte("something else entirely"), 64)
	err := fsCommit(protocol.FsCommit{UploadID: testUploadID, Path: dest, Size: int64(len(signed)), SHA256: digest(signed)})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatch accepted: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "original" {
		t.Errorf("destination changed to %q", got)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), ".rmm-upload-*")); len(left) > 0 {
		t.Errorf("temp files left behind: %v", left)
	}
	// Same bytes, wrong size claim.
	stageAll(t, testUploadID, signed, 64)
	if err := fsCommit(protocol.FsCommit{UploadID: testUploadID, Path: dest, Size: int64(len(signed)) - 1, SHA256: digest(signed)}); err == nil {
		t.Error("a short size claim was accepted")
	}
}

func TestStagingRules(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	if err := fsStage(protocol.FsStage{UploadID: testUploadID, Offset: 0, Data: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	if err := fsStage(protocol.FsStage{UploadID: testUploadID, Offset: 10, Data: []byte("x")}); err == nil {
		t.Error("an out-of-order chunk was accepted")
	}
	if err := fsStage(protocol.FsStage{UploadID: testUploadID, Offset: 0, Data: []byte("x")}); err != nil {
		t.Errorf("offset 0 must restart the upload: %v", err)
	}
	for _, id := range []string{"../../etc/passwd", "short", `upl_..\..\x_padding_padding`, ""} {
		if err := fsStage(protocol.FsStage{UploadID: id, Data: []byte("x")}); err == nil {
			t.Errorf("upload id %q accepted", id)
		}
	}
	if err := fsCommit(protocol.FsCommit{UploadID: "upl_never_staged_00000", Path: filepath.Join(t.TempDir(), "x"), Size: 1, SHA256: digest([]byte("x"))}); err == nil || !strings.Contains(err.Error(), "not staged") {
		t.Errorf("commit of an unknown upload: %v", err)
	}
	// The staging area is inside the agent's config directory, which the
	// file browser refuses, so staged bytes cannot be read back or reused.
	if _, err := fsCheckPath(filepath.Join(stagingDir(), testUploadID+".part")); err == nil {
		t.Error("the staging area is reachable through the file browser")
	}
}

func TestStagingPrunesAbandonedUploads(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	if err := fsStage(protocol.FsStage{UploadID: "upl_abandoned_0000000", Data: []byte("old")}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * stagedUploadTTL)
	os.Chtimes(filepath.Join(stagingDir(), "upl_abandoned_0000000.part"), old, old)
	if err := fsStage(protocol.FsStage{UploadID: testUploadID, Data: []byte("new")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stagingDir(), "upl_abandoned_0000000.part")); !os.IsNotExist(err) {
		t.Error("an abandoned upload was not pruned")
	}
}
