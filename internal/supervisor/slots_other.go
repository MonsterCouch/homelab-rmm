//go:build !windows && !linux

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// BinaryExecutableName is the binary name on other POSIX systems.
	BinaryExecutableName = "rmm-agent"

	// DefaultInstallBaseDir is the fallback installation directory on other POSIX systems.
	DefaultInstallBaseDir = "/usr/local/homelab-rmm"
)

// validateBinaryHeader checks for standard ELF or Mach-O executable headers.
func validateBinaryHeader(header []byte) error {
	if len(header) < 4 {
		return fmt.Errorf("binary header too short: got %d bytes, need at least 4", len(header))
	}

	// ELF magic (\x7fELF)
	if header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		return nil
	}

	// Mach-O headers (Darwin / macOS)
	if (header[0] == 0xCF && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) ||
		(header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA && header[3] == 0xCF) ||
		(header[0] == 0xCE && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) ||
		(header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA && header[3] == 0xCE) ||
		(header[0] == 0xCA && header[1] == 0xFE && header[2] == 0xBA && header[3] == 0xBE) ||
		(header[0] == 0xBE && header[1] == 0xBA && header[2] == 0xFE && header[3] == 0xCA) {
		return nil
	}

	return fmt.Errorf("unrecognized executable binary header: 0x%02X%02X%02X%02X",
		header[0], header[1], header[2], header[3])
}

// readLinkTarget reads the destination of linkPath on POSIX systems.
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

// replaceFileAtomic atomically replaces dst with src on POSIX systems using rename(2).
func replaceFileAtomic(src, dst string) error {
	return os.Rename(src, dst)
}
