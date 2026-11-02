//go:build linux

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// BinaryExecutableName is the binary name on Linux.
	BinaryExecutableName = "rmm-agent"

	// DefaultInstallBaseDir is the standard installation directory for homelab-rmm on Linux.
	DefaultInstallBaseDir = "/opt/homelab-rmm"
)

// validateBinaryHeader checks for standard 4-byte ELF magic header (\x7fELF) on Linux.
func validateBinaryHeader(header []byte) error {
	if len(header) < 4 {
		return fmt.Errorf("binary header too short: got %d bytes, need at least 4", len(header))
	}
	if header[0] != 0x7F || header[1] != 'E' || header[2] != 'L' || header[3] != 'F' {
		return fmt.Errorf("invalid ELF binary header: expected 0x7F454C46, got 0x%02X%02X%02X%02X",
			header[0], header[1], header[2], header[3])
	}
	return nil
}

// readLinkTarget reads the destination of linkPath. If the target is relative,
// it resolves it relative to filepath.Dir(linkPath) and returns the cleaned absolute path.
func readLinkTarget(linkPath string) (string, error) {
	rawTarget, err := os.Readlink(linkPath)
	if err != nil {
		return "", fmt.Errorf("failed to read symlink target %s: %w", linkPath, err)
	}

	var resolved string
	if filepath.IsAbs(rawTarget) {
		resolved = rawTarget
	} else {
		resolved = filepath.Join(filepath.Dir(linkPath), rawTarget)
	}
	return filepath.Clean(resolved), nil
}

// createOrUpdateLink atomically creates or updates the symbolic link at linkPath to targetPath.
// Computes a relative target, creates a unique temp symlink in the same directory, and performs
// an atomic os.Rename.
func createOrUpdateLink(linkPath, targetPath string) error {
	linkDir := filepath.Dir(linkPath)
	if err := os.MkdirAll(linkDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for link %s: %w", linkDir, err)
	}

	var symlinkTarget string
	if filepath.IsAbs(targetPath) {
		rel, err := filepath.Rel(linkDir, targetPath)
		if err == nil {
			symlinkTarget = rel
		} else {
			symlinkTarget = targetPath
		}
	} else {
		symlinkTarget = targetPath
	}
	symlinkTarget = filepath.ToSlash(symlinkTarget)

	if fi, err := os.Lstat(linkPath); err == nil {
		if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
			if rmErr := os.Remove(linkPath); rmErr != nil {
				return fmt.Errorf("link path %s is an existing directory: %w", linkPath, rmErr)
			}
		}
	}

	tmpLink := filepath.Join(linkDir, fmt.Sprintf(".current.tmp.%d.%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.Symlink(symlinkTarget, tmpLink); err != nil {
		return fmt.Errorf("failed to create temporary symlink %s -> %s: %w", tmpLink, symlinkTarget, err)
	}

	if err := os.Rename(tmpLink, linkPath); err != nil {
		_ = os.Remove(tmpLink)
		return fmt.Errorf("failed to atomically replace symlink %s with %s: %w", linkPath, tmpLink, err)
	}

	return nil
}

// replaceFileAtomic atomically replaces dst with src on Linux using rename(2).
func replaceFileAtomic(src, dst string) error {
	return os.Rename(src, dst)
}
