//go:build !windows

package portalpipe

import "context"

// Serve does nothing: the tray app is Windows only.
func Serve(ctx context.Context, name string, get PassFunc) {}

// Ask always fails off Windows.
func Ask(name string) (string, error) { return "", errUnsupported }
