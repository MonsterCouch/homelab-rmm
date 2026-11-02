//go:build !linux

package stream

// platformMem has no implementation off Linux: the server only exists there.
func platformMem() Mem { return nil }

// platformSignal has no implementation off Linux.
func platformSignal() Signal { return nil }
