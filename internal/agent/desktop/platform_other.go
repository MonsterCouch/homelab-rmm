//go:build !windows && !linux

package desktop

import "errors"

var errUnsupported = errors.New("remote desktop is not supported on this platform")

func platformInit() error { return errUnsupported }

type threadDesktop struct{}

func newThreadDesktop() *threadDesktop { return &threadDesktop{} }
func (*threadDesktop) follow() error   { return nil }
func (*threadDesktop) close()          {}
