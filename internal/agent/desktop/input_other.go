//go:build !windows && !linux

package desktop

func newInjector() (injector, error) { return nil, errUnsupported }
