//go:build !windows

package desktop

import "errors"

// errBackstageUnsupported is returned when backstage (an isolated
// administrative desktop the logged-in user never sees) is requested on a
// platform that has no such concept. Only Windows virtual desktops implement
// it; elsewhere the caller falls back to the console desktop.
var errBackstageUnsupported = errors.New("backstage mode is only supported on Windows")

// newBackstage has no implementation off Windows.
func newBackstage() (capturer, injector, error) {
	return nil, nil, errBackstageUnsupported
}
