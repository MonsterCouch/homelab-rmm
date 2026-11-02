//go:build unix

package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// LockDataDir takes the advisory lock that says "a process is using this data
// directory". The server holds it while it runs; the migration commands take
// it to be sure no server is writing underneath them. The lock is released by
// the returned function, or by the kernel if the process dies.
func LockDataDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "rmm.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the data directory lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrDataDirBusy
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
