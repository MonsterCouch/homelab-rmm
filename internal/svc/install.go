package svc

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// ImagePathWarning is the warning `install` prints when the executable it is
// about to register lives somewhere an account that is not already an
// administrator can write to, or "" when the location is sound.
//
// The service manager starts that file with full system privileges
// (LocalSystem on Windows, root on Linux) at every boot, so whoever can
// replace it owns the machine - and the manual install both README.md and
// docs/SECURITY.md recommend says nothing about where to put the binary, so
// "wherever it was downloaded to" is the normal outcome. The rendered install
// script gets this right by construction (%ProgramFiles%\HomelabRMM), which is
// why the check names that directory as the way out.
//
// It warns rather than refuses on purpose: running the agent from a build tree
// is how the agent is developed, and an install that cannot be completed at
// all would just be worked around. A location that cannot be inspected is not
// an accusation either - no warning is printed when the check itself fails.
//
// Both the directory and the file itself are inspected. Writing the directory
// is the way a binary is swapped out wholesale, and it is checked first
// because it is the one that also explains the file; but a binary built or
// unpacked by an unprivileged account carries an explicit entry of its own
// (the live box had an explicit "<user>:(F)" entry on rmm-agent.exe), which
// lets that account rewrite it in place even inside a protected directory.
func ImagePathWarning(exe string) string {
	recommended := recommendedImageDir()
	dir := filepath.Dir(exe)
	if writers, err := unprotectedWriters(dir); err == nil && len(writers) > 0 {
		return imagePathWarning(dir, writers, recommended)
	}
	if writers, err := unprotectedWriters(exe); err == nil && len(writers) > 0 {
		return imagePathWarning(exe, writers, recommended)
	}
	return ""
}

// imagePathWarning renders the warning. It is separate from the platform
// inspection so the wording - which has to name what is unprotected, who can
// write it and where the binary belongs instead - can be tested anywhere.
// "Copy", not "move": a move keeps an explicit entry that is on the file
// itself, while a copy into a protected directory takes that directory's
// inherited ACL.
func imagePathWarning(path string, writers []string, recommended string) string {
	var b strings.Builder
	b.WriteString("WARNING: " + path + " can be modified by accounts that are not administrators:\n")
	for _, w := range writers {
		b.WriteString("           " + w + "\n")
	}
	b.WriteString("         The service manager runs the executable registered here with full\n")
	b.WriteString("         system privileges at every start, so anyone who can replace it runs\n")
	b.WriteString("         code as LocalSystem/root on this machine.\n")
	b.WriteString("         Copy the binary into " + recommended + " (where the install command the\n")
	b.WriteString("         console prints puts it) and run install again from there.")
	return b.String()
}

// unixWriters names the accounts that can write a directory with this mode and
// owner, from the point of view of a service that runs as root. Group- and
// world-writable are the classic mistakes; an owner that is not root is the
// one this project actually produces, because a binary copied into a user's
// home or Downloads keeps that user as its owner with the usual 0755.
func unixWriters(mode fs.FileMode, uid int) []string {
	var who []string
	if uid != 0 {
		who = append(who, fmt.Sprintf("its owner (uid %d, not root)", uid))
	}
	if mode&0o020 != 0 {
		who = append(who, fmt.Sprintf("its group (mode %#o)", mode.Perm()))
	}
	if mode&0o002 != 0 {
		who = append(who, fmt.Sprintf("every local user (world-writable, mode %#o)", mode.Perm()))
	}
	return who
}
