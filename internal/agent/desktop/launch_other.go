//go:build !windows && !linux

package desktop

func launch(exe string, cfg Config) (string, error) {
	return "", errUnsupported
}
