//go:build !windows && !linux

package desktop

func launch(exe, serverURL, token, fingerprint string, quality int) (string, error) {
	return "", errUnsupported
}
