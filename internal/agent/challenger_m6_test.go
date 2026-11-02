package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/supervisor"
)

// validPEOrELFHeader returns valid header bytes for the current platform.
func validPEOrELFHeader() []byte {
	if runtime.GOOS == "windows" {
		return []byte{0x4D, 0x5A, 0x90, 0x00}
	}
	return []byte{0x7F, 'E', 'L', 'F'}
}

// countStagingTempFiles counts any leftover .stage-*.tmp files in the directory.
func countStagingTempFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read dir %s: %v", dir, err)
	}
	count := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".stage-") && strings.HasSuffix(name, ".tmp") {
			count++
		}
	}
	return count
}

// 1. Verify update downloads to .stage-*.tmp in inactive slot and cleans up properly.
func TestChallenger_StageBinary_TempFilePatternAndCleanup(t *testing.T) {
	dir := t.TempDir()
	targetBin := filepath.Join(dir, supervisor.BinaryExecutableName)

	validHeader := validPEOrELFHeader()
	validContent := append(validHeader, []byte("-payload-version-test-12345")...)
	h := sha256.Sum256(validContent)
	validSHA := hex.EncodeToString(h[:])

	// Case A: Successful staging cleans up .stage-*.tmp and creates targetBin
	err := stageBinaryToSlot(bytes.NewReader(validContent), dir, targetBin, validSHA)
	if err != nil {
		t.Fatalf("stageBinaryToSlot failed on valid payload: %v", err)
	}
	if n := countStagingTempFiles(t, dir); n != 0 {
		t.Errorf("expected 0 leftover .stage-*.tmp files after success, got %d", n)
	}
	data, err := os.ReadFile(targetBin)
	if err != nil {
		t.Fatalf("target binary was not created: %v", err)
	}
	if !bytes.Equal(data, validContent) {
		t.Errorf("staged binary content mismatch")
	}

	// Case B: Aborted reader midway cleans up .stage-*.tmp
	failingReader := &errorAfterNReader{data: validContent, failAfter: 10}
	err = stageBinaryToSlot(failingReader, dir, targetBin, validSHA)
	if err == nil {
		t.Fatal("expected error on failing reader, got nil")
	}
	if n := countStagingTempFiles(t, dir); n != 0 {
		t.Errorf("expected 0 leftover .stage-*.tmp files after stream failure, got %d", n)
	}

	// Case C: Invalid header cleans up .stage-*.tmp
	invalidHeaderPayload := []byte("INVALID_NOT_MZ_OR_ELF_DATA_STREAM")
	hInv := sha256.Sum256(invalidHeaderPayload)
	err = stageBinaryToSlot(bytes.NewReader(invalidHeaderPayload), dir, targetBin, hex.EncodeToString(hInv[:]))
	if err == nil {
		t.Fatal("expected error on invalid header, got nil")
	}
	if n := countStagingTempFiles(t, dir); n != 0 {
		t.Errorf("expected 0 leftover .stage-*.tmp files after invalid header, got %d", n)
	}

	// Case D: Checksum mismatch cleans up .stage-*.tmp
	err = stageBinaryToSlot(bytes.NewReader(validContent), dir, targetBin, strings.Repeat("0", 64))
	if err == nil {
		t.Fatal("expected error on checksum mismatch, got nil")
	}
	if n := countStagingTempFiles(t, dir); n != 0 {
		t.Errorf("expected 0 leftover .stage-*.tmp files after checksum mismatch, got %d", n)
	}
}

type errorAfterNReader struct {
	data      []byte
	offset    int
	failAfter int
}

func (r *errorAfterNReader) Read(p []byte) (int, error) {
	if r.offset >= r.failAfter {
		return 0, fmt.Errorf("simulated network read failure at byte %d", r.offset)
	}
	available := r.failAfter - r.offset
	toRead := len(p)
	if toRead > available {
		toRead = available
	}
	n := copy(p, r.data[r.offset:r.offset+toRead])
	r.offset += n
	return n, nil
}

// 2. Verify bad binary headers are rejected (ValidateBinaryHeader).
func TestChallenger_ValidateBinaryHeader_Exhaustive(t *testing.T) {
	testCases := []struct {
		name      string
		header    []byte
		expectErr bool
	}{
		{"nil slice", nil, true},
		{"empty slice", []byte{}, true},
		{"single byte 0x4D", []byte{0x4D}, true},
		{"single byte 0x7F", []byte{0x7F}, true},
		{"inverted MZ 0x5A 0x4D", []byte{0x5A, 0x4D}, true},
		{"all zeroes 4 bytes", []byte{0x00, 0x00, 0x00, 0x00}, true},
		{"all 0xFF 4 bytes", []byte{0xFF, 0xFF, 0xFF, 0xFF}, true},
		{"ASCII text bash shebang", []byte("#!/bin/bash"), true},
		{"ASCII text batch", []byte("@echo off\r\n"), true},
		{"HTML tag", []byte("<!DOCTYPE html>"), true},
		{"JSON object", []byte("{\"error\":\"404\"}"), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := supervisor.ValidateBinaryHeader(tc.header)
			if tc.expectErr && err == nil {
				t.Errorf("ValidateBinaryHeader(%q) expected error, got nil", tc.header)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("ValidateBinaryHeader(%q) unexpected error: %v", tc.header, err)
			}
		})
	}

	// Platform specific checks
	if runtime.GOOS == "windows" {
		// Valid PE MZ
		if err := supervisor.ValidateBinaryHeader([]byte{0x4D, 0x5A, 0x90, 0x00}); err != nil {
			t.Errorf("ValidateBinaryHeader expected valid PE header, got: %v", err)
		}
		// On Windows, ELF header MUST be rejected!
		if err := supervisor.ValidateBinaryHeader([]byte{0x7F, 'E', 'L', 'F'}); err == nil {
			t.Errorf("ValidateBinaryHeader on Windows accepted ELF header, expected rejection!")
		}
	} else if runtime.GOOS == "linux" {
		// Valid ELF
		if err := supervisor.ValidateBinaryHeader([]byte{0x7F, 'E', 'L', 'F'}); err != nil {
			t.Errorf("ValidateBinaryHeader expected valid ELF header, got: %v", err)
		}
		// On Linux, PE header MUST be rejected!
		if err := supervisor.ValidateBinaryHeader([]byte{0x4D, 0x5A, 0x90, 0x00}); err == nil {
			t.Errorf("ValidateBinaryHeader on Linux accepted PE header, expected rejection!")
		}
	}
}

// 3. Verify atomic replacement into inactive slot executable (replaceBinaryAtomic).
func TestChallenger_ReplaceBinaryAtomic_OverwritesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new.bin")
	dst := filepath.Join(dir, "target.bin")

	// Target already exists with old content
	oldContent := []byte("OLD_BINARY_CONTENT_VERSION_1")
	if err := os.WriteFile(dst, oldContent, 0755); err != nil {
		t.Fatalf("failed to write existing target: %v", err)
	}

	newContent := []byte("NEW_BINARY_CONTENT_VERSION_2")
	if err := os.WriteFile(src, newContent, 0755); err != nil {
		t.Fatalf("failed to write new src: %v", err)
	}

	// Atomic replacement must overwrite dst
	if err := replaceBinaryAtomic(src, dst); err != nil {
		t.Fatalf("replaceBinaryAtomic failed: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("failed to read dst: %v", err)
	}
	if !bytes.Equal(got, newContent) {
		t.Errorf("dst has %q, want %q", got, newContent)
	}

	// src must no longer exist (moved)
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("src file should have been moved/removed, but still exists")
	}

	// Non-existent source should fail gracefully
	nonExistentSrc := filepath.Join(dir, "nonexistent.bin")
	if err := replaceBinaryAtomic(nonExistentSrc, dst); err == nil {
		t.Errorf("replaceBinaryAtomic on nonexistent source should fail, got nil")
	}
}

// 4. Verify SHA-256 digest mismatches and pre-flight validation.
func TestChallenger_SHA256Validation(t *testing.T) {
	validHeader := validPEOrELFHeader()
	validPayload := append(validHeader, []byte("SHA256_TEST_PAYLOAD")...)
	h := sha256.Sum256(validPayload)
	actualSHA := hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(validPayload)
	}))
	defer srv.Close()

	cfg := &Config{ServerURL: srv.URL}

	// Pre-flight check rejects invalid hash formats before even contacting supervisor or server
	invalidHashes := []struct {
		name string
		hash string
	}{
		{"empty hash", ""},
		{"short hash (63 hex)", strings.Repeat("a", 63)},
		{"long hash (65 hex)", strings.Repeat("a", 65)},
		{"non-hex characters", strings.Repeat("a", 63) + "g"},
		{"whitespace included", " " + actualSHA[:63]},
		{"uppercase with invalid char", strings.ToUpper(actualSHA[:63]) + "Z"},
	}

	for _, tc := range invalidHashes {
		t.Run(tc.name, func(t *testing.T) {
			req := protocol.AgentUpdate{
				URL:     srv.URL + "/download",
				SHA256:  tc.hash,
				Version: "v2.0.0",
			}
			err := ApplyStagedUpdate(context.Background(), cfg, req, nil)
			if err == nil {
				t.Fatalf("expected pre-flight refusal for %s (%s), got nil", tc.name, tc.hash)
			}
			if !strings.Contains(err.Error(), "sha256") {
				t.Errorf("error must mention sha256, got: %v", err)
			}
		})
	}

	// Case-insensitivity: Uppercase hex of the correct hash MUST succeed
	uppercaseSHA := strings.ToUpper(actualSHA)
	slotDir := t.TempDir()
	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()

	ipcServer := supervisor.NewIPCServer()
	defer ipcServer.Stop()

	ipcServer.RegisterHandler(supervisor.MsgGetInactive, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		return &supervisor.IPCMessage{
			Type: supervisor.MsgInactiveResp,
			Slot: "slot_b",
			Path: slotDir,
		}, nil
	})
	ipcServer.RegisterHandler(supervisor.MsgRequestRestart, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		return nil, nil
	})
	_ = ipcServer.Start(pipe)

	clientConn, _ := pipe.Dial()
	ipcClient := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = ipcClient.Connect(clientConn)
	defer ipcClient.Close()

	origExit := updateExitFunc
	origDelay := updateExitDelay
	exitCalled := make(chan int, 1)
	updateExitFunc = func(code int) {
		exitCalled <- code
	}
	updateExitDelay = 10 * time.Millisecond
	defer func() {
		updateExitFunc = origExit
		updateExitDelay = origDelay
	}()

	req := protocol.AgentUpdate{
		URL:     srv.URL + "/download",
		SHA256:  uppercaseSHA,
		Version: "v2.0.0",
	}
	err := ApplyStagedUpdate(context.Background(), cfg, req, ipcClient)
	if err != nil {
		t.Fatalf("expected uppercase valid hex SHA-256 to succeed, got: %v", err)
	}

	select {
	case <-exitCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker exit")
	}
}

// 5. Verify restart request is sent over IPC (MsgRequestRestart) with accurate payload.
func TestChallenger_MsgRequestRestart_PayloadAccuracy(t *testing.T) {
	slotDir := t.TempDir()
	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()

	ipcServer := supervisor.NewIPCServer()
	defer ipcServer.Stop()

	restartMsgCh := make(chan *supervisor.IPCMessage, 1)

	ipcServer.RegisterHandler(supervisor.MsgGetInactive, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		return &supervisor.IPCMessage{
			Type: supervisor.MsgInactiveResp,
			Slot: "slot_b",
			Path: slotDir,
		}, nil
	})
	ipcServer.RegisterHandler(supervisor.MsgRequestRestart, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		restartMsgCh <- msg
		return nil, nil
	})
	_ = ipcServer.Start(pipe)

	clientConn, _ := pipe.Dial()
	ipcClient := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = ipcClient.Connect(clientConn)
	defer ipcClient.Close()

	validHeader := validPEOrELFHeader()
	validContent := append(validHeader, []byte("-payload-v3.1.4")...)
	h := sha256.Sum256(validContent)
	sum := hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(validContent)
	}))
	defer srv.Close()

	origExit := updateExitFunc
	origDelay := updateExitDelay
	exitCalled := make(chan int, 1)
	updateExitFunc = func(code int) {
		exitCalled <- code
	}
	updateExitDelay = 10 * time.Millisecond
	defer func() {
		updateExitFunc = origExit
		updateExitDelay = origDelay
	}()

	cfg := &Config{ServerURL: srv.URL}
	targetVersion := "v3.1.4-rc1"
	req := protocol.AgentUpdate{
		URL:     srv.URL + "/update",
		SHA256:  sum,
		Version: targetVersion,
	}

	err := ApplyStagedUpdate(context.Background(), cfg, req, ipcClient)
	if err != nil {
		t.Fatalf("ApplyStagedUpdate failed: %v", err)
	}

	select {
	case msg := <-restartMsgCh:
		if msg.Type != supervisor.MsgRequestRestart {
			t.Errorf("expected type MsgRequestRestart (%s), got %s", supervisor.MsgRequestRestart, msg.Type)
		}
		if msg.PID != os.Getpid() {
			t.Errorf("expected PID %d, got %d", os.Getpid(), msg.PID)
		}
		if msg.Reason != "update_staged" {
			t.Errorf("expected Reason 'update_staged', got %s", msg.Reason)
		}
		if msg.Version != targetVersion {
			t.Errorf("expected Version %s, got %s", targetVersion, msg.Version)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for MsgRequestRestart on IPC channel")
	}

	select {
	case code := <-exitCalled:
		if code != 0 {
			t.Errorf("expected worker exit code 0, got %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker exit")
	}
}
