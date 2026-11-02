//go:build !unix && !windows

package telemetry

// LockDataDir does nothing on a platform without a file lock we use; the
// migration then relies on the engines' own locking.
func LockDataDir(dir string) (func(), error) { return func() {}, nil }
