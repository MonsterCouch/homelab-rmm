//go:build linux || darwin || freebsd

package cache

import "syscall"

// freeSpace is the bytes available to this process on the volume holding dir.
// ok is false when the platform cannot say, in which case no check is made.
func freeSpace(dir string) (n int64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return int64(uint64(st.Bavail) * uint64(st.Bsize)), true
}
