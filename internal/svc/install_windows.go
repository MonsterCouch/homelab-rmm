//go:build windows

package svc

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// setErrorControl gives the registered service SERVICE_ERROR_NORMAL.
//
// kardianos builds its mgr.Config without an ErrorControl field, and
// CreateService takes the zero value literally: SERVICE_ERROR_IGNORE, under
// which "the startup program ignores the error and continues" - no Service
// Control Manager entry in the System event log when the service fails to
// start. sc.exe defaults to NORMAL, which is what leaves the 7000/7009 pair an
// operator can actually find. There is no option to pass through at create
// time, so the value is changed on the service afterwards; SERVICE_NO_CHANGE
// for every other parameter keeps the account, start type and image path
// exactly as they were registered.
func setErrorControl(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	return windows.ChangeServiceConfig(s.Handle,
		windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE, windows.SERVICE_ERROR_NORMAL,
		nil, nil, nil, nil, nil, nil, nil)
}

// recommendedImageDir is where the console's rendered install script puts the
// agent: a directory under %ProgramFiles% inherits its administrators-only ACL.
func recommendedImageDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "HomelabRMM")
}

// fileDeleteChild is winnt.h's FILE_DELETE_CHILD, which x/sys does not define.
// On a directory it is the right to delete the files inside it.
const fileDeleteChild = 0x00000040

// writeAccess is every right that lets a principal put a different executable
// where the service manager will find it: write or append to the file, delete
// it, delete it out of its directory, or rewrite the object's own owner or
// DACL and grant itself the rest. The generic bits are included because an ACE
// can carry them unmapped.
const writeAccess = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | fileDeleteChild |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

func grantsWrite(mask uint32) bool { return mask&writeAccess != 0 }

// administrative reports whether sid already holds administrative control of
// the machine, so being able to replace a service binary tells us nothing new
// about it.
func administrative(sid string) bool {
	switch sid {
	case "S-1-5-18", // NT AUTHORITY\SYSTEM
		"S-1-5-32-544", // BUILTIN\Administrators
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": // NT SERVICE\TrustedInstaller
		return true
	}
	return false
}

// unprotectedWriters lists the principals the DACL of path - a directory or
// the binary itself - grants write access to, other than the administrative
// accounts above. Inherited entries count - the profile-wide grant a binary
// under C:\Users picks up is exactly the problem - while inherit-only entries
// do not, because they describe the children rather than this object (CREATOR
// OWNER under %ProgramFiles% is one, and treating it as a writer would make
// the recommended location look unsafe).
func unprotectedWriters(path string) ([]string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		// A NULL DACL grants everyone everything; an empty one grants nobody
		// anything, and DACL() reports both as a nil ACL. Only the first is
		// possible for an object that exists and can be written at all.
		return []string{"everyone (no DACL)"}, nil
	}
	var writers []string
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if !grantsWrite(uint32(ace.Mask)) {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		text := sid.String()
		if administrative(text) || seen[text] {
			continue
		}
		seen[text] = true
		writers = append(writers, principal(sid, text))
	}
	return writers, nil
}

// principal renders a SID the way an operator will recognise it, falling back
// to the SID itself for an account this machine cannot resolve.
func principal(sid *windows.SID, text string) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return text
	}
	if domain == "" {
		return fmt.Sprintf("%s (%s)", account, text)
	}
	return fmt.Sprintf("%s\\%s (%s)", domain, account, text)
}
