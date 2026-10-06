//go:build windows

package supervisor

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const (
	// BinaryExecutableName is the binary name on Windows.
	BinaryExecutableName = "rmm-agent.exe"

	// DefaultInstallBaseDir is the standard installation directory for homelab-rmm on Windows.
	DefaultInstallBaseDir = `C:\Program Files\HomelabRMM`

	fsctlSetReparsePoint   = 0x000900A4
	ioReparseTagMountPoint = 0xA0000003
)

// validateBinaryHeader checks for PE binary MZ magic bytes (0x4D, 0x5A) on Windows.
func validateBinaryHeader(header []byte) error {
	if len(header) < 2 {
		return fmt.Errorf("binary header too short: got %d bytes, need at least 2", len(header))
	}
	if header[0] != 0x4D || header[1] != 0x5A {
		return fmt.Errorf("invalid PE binary header: expected 0x4D5A (MZ), got 0x%02X%02X", header[0], header[1])
	}
	return nil
}

// cleanLinkTarget normalizes the target path returned by os.Readlink or DeviceIoControl.
func cleanLinkTarget(target string) string {
	target = strings.TrimPrefix(target, `\??\`)
	target = strings.TrimPrefix(target, `\\?\`)
	target = strings.TrimRight(target, `\/`)
	return filepath.Clean(target)
}

// readLinkTarget reads the destination path of a junction or symlink on Windows.
func readLinkTarget(linkPath string) (string, error) {
	rawTarget, err := os.Readlink(linkPath)
	if err != nil {
		// Fallback to filepath.EvalSymlinks in case os.Readlink encounters non-standard reparse tag
		evalTarget, evalErr := filepath.EvalSymlinks(linkPath)
		if evalErr == nil && evalTarget != linkPath {
			rawTarget = evalTarget
		} else {
			return "", fmt.Errorf("read link target %q: %w", linkPath, err)
		}
	}

	cleaned := cleanLinkTarget(rawTarget)
	if !filepath.IsAbs(cleaned) {
		cleaned = filepath.Join(filepath.Dir(linkPath), cleaned)
		cleaned = filepath.Clean(cleaned)
	}
	return cleaned, nil
}

// createJunctionCmd creates an NTFS junction using cmd.exe /c mklink /J with hidden window attributes.
func createJunctionCmd(linkPath, targetPath string) error {
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		absTarget = targetPath
	}

	cmd := exec.Command("cmd", "/c", "mklink", "/J", linkPath, absTarget)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // windows.CREATE_NO_WINDOW
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink /J failed (%s): %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// createJunctionNative creates an NTFS junction using direct Win32 DeviceIoControl.
func createJunctionNative(linkPath, targetPath string) error {
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolve abs target %q: %w", targetPath, err)
	}

	fi, err := os.Stat(absTarget)
	if err != nil {
		return fmt.Errorf("stat target directory %q: %w", absTarget, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("target %q is not a directory", absTarget)
	}

	if err := os.Mkdir(linkPath, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("mkdir link %q: %w", linkPath, err)
	}

	linkPathW, err := windows.UTF16PtrFromString(linkPath)
	if err != nil {
		_ = os.Remove(linkPath)
		return err
	}

	h, err := windows.CreateFile(
		linkPathW,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		_ = os.Remove(linkPath)
		return fmt.Errorf("CreateFile %q: %w", linkPath, err)
	}
	defer windows.CloseHandle(h)

	cleanTarget := filepath.Clean(absTarget)
	if !strings.HasSuffix(cleanTarget, `\`) {
		cleanTarget += `\`
	}
	substituteName := `\??\` + cleanTarget
	printName := cleanTarget

	substUTF16 := utf16.Encode([]rune(substituteName))
	printUTF16 := utf16.Encode([]rune(printName))

	substByteLen := len(substUTF16) * 2
	printByteLen := len(printUTF16) * 2

	substOffset := 0
	printOffset := substByteLen + 2

	pathBufferLen := printOffset + printByteLen + 2
	reparseDataLength := 8 + pathBufferLen

	buf := make([]byte, 8+reparseDataLength)

	binary.LittleEndian.PutUint32(buf[0:4], ioReparseTagMountPoint)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(reparseDataLength))
	binary.LittleEndian.PutUint16(buf[6:8], 0)

	binary.LittleEndian.PutUint16(buf[8:10], uint16(substOffset))
	binary.LittleEndian.PutUint16(buf[10:12], uint16(substByteLen))
	binary.LittleEndian.PutUint16(buf[12:14], uint16(printOffset))
	binary.LittleEndian.PutUint16(buf[14:16], uint16(printByteLen))

	offset := 16 + substOffset
	for i, u := range substUTF16 {
		binary.LittleEndian.PutUint16(buf[offset+i*2:], u)
	}

	offset = 16 + printOffset
	for i, u := range printUTF16 {
		binary.LittleEndian.PutUint16(buf[offset+i*2:], u)
	}

	var bytesReturned uint32
	var overlapped windows.Overlapped
	err = windows.DeviceIoControl(
		h,
		fsctlSetReparsePoint,
		&buf[0],
		uint32(len(buf)),
		nil,
		0,
		&bytesReturned,
		&overlapped,
	)
	if err != nil {
		_ = os.Remove(linkPath)
		return fmt.Errorf("DeviceIoControl FSCTL_SET_REPARSE_POINT: %w", err)
	}

	return nil
}

// createPartitionLink creates a junction or symbolic link trying cmd /c mklink /J,
// Win32 DeviceIoControl, and os.Symlink.
func createPartitionLink(linkPath, targetPath string) error {
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		absTarget = targetPath
	}

	// Strategy 1: cmd /c mklink /J (standard and unprivileged)
	if err := createJunctionCmd(linkPath, absTarget); err == nil {
		return nil
	}

	// Strategy 2: Direct Win32 FSCTL_SET_REPARSE_POINT
	if err := createJunctionNative(linkPath, absTarget); err == nil {
		return nil
	}

	// Strategy 3: os.Symlink fallback
	if err := os.Symlink(absTarget, linkPath); err == nil {
		return nil
	}

	return fmt.Errorf("all junction and link creation strategies failed for %s -> %s", linkPath, absTarget)
}

// createOrUpdateLink creates or updates linkPath to point to targetPath on Windows.
// Uses a transactional rename-backup-create-cleanup pattern with instant rollback.
func createOrUpdateLink(linkPath, targetPath string) error {
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("invalid target path %q: %w", targetPath, err)
	}

	fi, err := os.Stat(absTarget)
	if err != nil {
		return fmt.Errorf("target path %q stat failed: %w", absTarget, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("target path %q is not a directory", absTarget)
	}

	oldBackup := fmt.Sprintf("%s.old.%d", linkPath, time.Now().UnixNano())
	_ = os.Remove(oldBackup)

	linkExists := false
	if _, err := os.Lstat(linkPath); err == nil {
		linkExists = true
		if err := os.Rename(linkPath, oldBackup); err != nil {
			// If rename fails, try removing link directly
			if remErr := os.Remove(linkPath); remErr != nil {
				return fmt.Errorf("failed to backup or remove existing link %q: %w (backup err: %v)", linkPath, remErr, err)
			}
			linkExists = false
		}
	}

	// Attempt junction creation
	if err := createPartitionLink(linkPath, absTarget); err != nil {
		// ROLLBACK: Restore previous link if it existed
		if linkExists {
			_ = os.Rename(oldBackup, linkPath)
		}
		return fmt.Errorf("failed to create link %s -> %s: %w", linkPath, absTarget, err)
	}

	// SUCCESS: Clean up backup
	if linkExists {
		_ = os.Remove(oldBackup)
	}
	return nil
}

// replaceFileAtomic replaces dst with src on Windows with retry backoff.
func replaceFileAtomic(src, dst string) error {
	var lastErr error
	for i := 0; i < 5; i++ {
		err := os.Rename(src, dst)
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}

	// Fallback: remove target and rename
	_ = os.Remove(dst)
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	return fmt.Errorf("replace file %s -> %s: %w", src, dst, lastErr)
}
