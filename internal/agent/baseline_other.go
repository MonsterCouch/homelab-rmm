//go:build !windows && !linux

package agent

// The platform contract for the baseline kinds on a platform that has
// neither implementation (darwin, and whatever else the package is built for
// to type-check it). Every per-OS kind resolves to nil, which the engine
// reports as `skipped`, never `error`: nothing has drifted on a device the
// kind was never written for.

import (
	"errors"
	"os"
)

func platformKind(kind string) *kindImpl { return nil }

func blFileOwner(string) (string, error) {
	return "", errors.New("file ownership is not checked on this platform")
}

func blStatOwner(os.FileInfo) (int, int, bool) { return 0, 0, false }

// errString mirrors the Linux helper for the shared kinds.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func promptRebootUser(ctx context.Context, reason string, displaySec, postponesRemaining, maxPostpones int) (string, error) {
	return "headless", nil
}
