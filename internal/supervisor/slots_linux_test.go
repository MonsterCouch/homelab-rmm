//go:build linux

package supervisor

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLinux_AtomicSymlinkReplacement(t *testing.T) {
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	slotA := filepath.Join(binDir, "slot_a")
	slotB := filepath.Join(binDir, "slot_b")
	current := filepath.Join(binDir, "current")

	if err := os.MkdirAll(slotA, 0755); err != nil {
		t.Fatalf("Failed to create slot_a: %v", err)
	}
	if err := os.MkdirAll(slotB, 0755); err != nil {
		t.Fatalf("Failed to create slot_b: %v", err)
	}

	// 1. Initial link to slot_a
	if err := createOrUpdateLink(current, slotA); err != nil {
		t.Fatalf("Initial createOrUpdateLink failed: %v", err)
	}

	target, err := readLinkTarget(current)
	if err != nil {
		t.Fatalf("readLinkTarget failed: %v", err)
	}
	if filepath.Base(target) != "slot_a" {
		t.Errorf("Expected slot 'slot_a', got %q", filepath.Base(target))
	}

	// Verify symlink is stored as relative path
	rawTarget, err := os.Readlink(current)
	if err != nil {
		t.Fatalf("os.Readlink failed: %v", err)
	}
	if rawTarget != "slot_a" {
		t.Errorf("Expected relative symlink target 'slot_a', got raw %q", rawTarget)
	}

	// 2. Atomic switch to slot_b
	if err := createOrUpdateLink(current, slotB); err != nil {
		t.Fatalf("Switch to slot_b failed: %v", err)
	}

	target, err = readLinkTarget(current)
	if err != nil {
		t.Fatalf("readLinkTarget failed: %v", err)
	}
	if filepath.Base(target) != "slot_b" {
		t.Errorf("Expected slot 'slot_b', got %q", filepath.Base(target))
	}

	rawTarget, err = os.Readlink(current)
	if err != nil {
		t.Fatalf("os.Readlink failed: %v", err)
	}
	if rawTarget != "slot_b" {
		t.Errorf("Expected relative symlink target 'slot_b', got raw %q", rawTarget)
	}
}

func TestLinux_SymlinkPortabilityAfterDirectoryMove(t *testing.T) {
	parentDir := t.TempDir()
	originalBase := filepath.Join(parentDir, "orig_rmm")
	binDir := filepath.Join(originalBase, "bin")
	slotA := filepath.Join(binDir, "slot_a")
	current := filepath.Join(binDir, "current")

	if err := os.MkdirAll(slotA, 0755); err != nil {
		t.Fatalf("Failed to create slot_a: %v", err)
	}

	markerContent := []byte("payload-slot-a-content")
	if err := os.WriteFile(filepath.Join(slotA, "app.bin"), markerContent, 0755); err != nil {
		t.Fatalf("Failed to write marker file: %v", err)
	}

	if err := createOrUpdateLink(current, slotA); err != nil {
		t.Fatalf("createOrUpdateLink failed: %v", err)
	}

	newBase := filepath.Join(parentDir, "moved_rmm")
	if err := os.Rename(originalBase, newBase); err != nil {
		t.Fatalf("Failed to rename base directory: %v", err)
	}

	movedCurrent := filepath.Join(newBase, "bin", "current")
	target, err := readLinkTarget(movedCurrent)
	if err != nil {
		t.Fatalf("readLinkTarget failed after move: %v", err)
	}
	if filepath.Base(target) != "slot_a" {
		t.Errorf("Expected slot 'slot_a' after move, got %q", filepath.Base(target))
	}

	readContent, err := os.ReadFile(filepath.Join(movedCurrent, "app.bin"))
	if err != nil {
		t.Fatalf("Failed to read file through moved symlink: %v", err)
	}
	if !bytes.Equal(readContent, markerContent) {
		t.Errorf("Content mismatch through moved symlink: got %s, want %s", string(readContent), string(markerContent))
	}
}

func TestLinux_ConcurrentSwitchingNoDeadlocksOrGaps(t *testing.T) {
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	slotA := filepath.Join(binDir, "slot_a")
	slotB := filepath.Join(binDir, "slot_b")
	current := filepath.Join(binDir, "current")

	_ = os.MkdirAll(slotA, 0755)
	_ = os.MkdirAll(slotB, 0755)
	_ = os.WriteFile(filepath.Join(slotA, "id.txt"), []byte("slot_a"), 0644)
	_ = os.WriteFile(filepath.Join(slotB, "id.txt"), []byte("slot_b"), 0644)

	_ = createOrUpdateLink(current, slotA)

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					data, err := os.ReadFile(filepath.Join(current, "id.txt"))
					if err != nil {
						t.Errorf("CRITICAL: Reader observed gap/error reading through current link: %v", err)
						return
					}
					content := string(data)
					if content != "slot_a" && content != "slot_b" {
						t.Errorf("Corrupt data observed: %q", content)
						return
					}
				}
			}
		}()
	}

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			targets := []string{slotA, slotB}
			for j := 0; j < 50; j++ {
				target := targets[j%2]
				if err := createOrUpdateLink(current, target); err != nil {
					t.Errorf("Concurrent createOrUpdateLink failed: %v", err)
				}
				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	time.Sleep(200 * time.Millisecond)
	close(stopCh)
	wg.Wait()
}

func TestLinux_ValidateBinaryHeader(t *testing.T) {
	validELF := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	if err := validateBinaryHeader(validELF); err != nil {
		t.Errorf("Valid ELF rejected: %v", err)
	}

	invalidPE := []byte{0x4D, 0x5A, 0x90, 0x00}
	if err := validateBinaryHeader(invalidPE); err == nil {
		t.Errorf("Expected error for PE header on Linux, got nil")
	}

	shortHeader := []byte{0x7F, 'E'}
	if err := validateBinaryHeader(shortHeader); err == nil {
		t.Errorf("Expected error for truncated header, got nil")
	}

	corrupted := []byte("INVALID_ELF_DATA")
	if err := validateBinaryHeader(corrupted); err == nil {
		t.Errorf("Expected error for corrupted header, got nil")
	}
}
