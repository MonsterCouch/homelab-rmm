//go:build windows

package cache

import "golang.org/x/sys/windows"

// freeSpace is the bytes available to this process on the volume holding dir.
// ok is false when the platform cannot say, in which case no check is made.
func freeSpace(dir string) (n int64, ok bool) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, false
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return 0, false
	}
	return int64(avail), true
}
