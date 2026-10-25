//go:build !windows && !linux && !darwin && !freebsd

package cache

// freeSpace cannot be read on this platform, so the store relies on its byte
// budget alone.
func freeSpace(string) (int64, bool) { return 0, false }
