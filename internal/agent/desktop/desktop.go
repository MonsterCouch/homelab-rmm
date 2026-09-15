// Package desktop implements the remote-desktop helper: screen capture with
// dirty-tile JPEG streaming, keyboard/mouse injection, and the logic that
// launches the helper inside the interactive session (Windows session 0
// isolation, Linux X11 display ownership).
//
// Wire protocol: see docs/DESKTOP-PROTOCOL.md.
package desktop

import (
	"context"
	"errors"
)

// Serve runs inside the helper process (or in-process when the agent already
// runs in the user's session). It connects to serverURL's
// /ws/desktop-agent?token=<token> endpoint, pinning the certificate by
// fingerprint, and streams until the socket closes or ctx ends.
func Serve(ctx context.Context, serverURL, token, fingerprint string, quality int) error {
	return errors.New("remote desktop is not implemented on this platform")
}

// Launch starts the helper for the interactive session from the agent
// service. exe is the agent binary (the helper is `<exe> desktop-helper ...`).
// It returns a note for the operator ("attached to console session of user
// X", "no user logged in, showing the logon screen") and an error when no
// interactive session can be reached.
func Launch(exe, serverURL, token, fingerprint string, quality int) (note string, err error) {
	return "", errors.New("remote desktop is not implemented on this platform")
}
