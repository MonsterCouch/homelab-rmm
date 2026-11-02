//go:build windows

package telemetry

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// LockDataDir takes the lock that says "a process is using this data
// directory". The server holds it while it runs; the migration commands take
// it to be sure no server is writing underneath them. The lock is released by
// the returned function, or by Windows if the process dies.
func LockDataDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "rmm.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the data directory lock: %w", err)
	}
	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); err != nil {
		f.Close()
		return nil, ErrDataDirBusy
	}
	return func() {
		windows.UnlockFileEx(h, 0, 1, 0, new(windows.Overlapped))
		f.Close()
	}, nil
}
