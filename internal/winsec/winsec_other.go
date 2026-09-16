//go:build !windows

package winsec

// SecureDir does nothing off Windows: the directory's mode, which MkdirAll
// already applied, is the access control there.
func SecureDir(path string) error { return nil }
