// Package portalpipe is the local channel between the tray app and the agent
// for client portal passes. The tray app writes "pass"; the agent works out
// who is asking from the pipe itself (the Windows account of the process on
// the other end, never anything the caller says), gets a pass for that
// account from the server, and writes back one JSON line. A user can
// therefore only ever get a pass for themselves on their own device.
//
// It is Windows only; elsewhere Serve does nothing and Ask fails.
package portalpipe

import (
	"context"
	"errors"
)

// Name is the pipe both sides use.
const Name = `\\.\pipe\homelab-rmm-portal`

// Account is who is on the other end of the pipe.
type Account struct {
	// User is DOMAIN\name for a domain account, the bare name for an
	// account local to this computer.
	User string
	// Local is true for an account local to this computer.
	Local bool
}

// PassFunc gets a portal pass for acct from the server.
type PassFunc func(ctx context.Context, acct Account) (string, error)

// reply is the one line the agent writes back.
type reply struct {
	Pass  string `json:"pass,omitempty"`
	Error string `json:"error,omitempty"`
}

var errUnsupported = errors.New("the client portal pipe is only available on Windows")
