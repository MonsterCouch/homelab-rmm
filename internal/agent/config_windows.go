//go:build windows

package agent

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// fileAllAccess is winnt.h's FILE_ALL_ACCESS, the mask icacls writes for an
// "(F)" grant. x/sys has no constant for it, and windows.GENERIC_ALL is not a
// safe stand-in: generic bits are mapped to an object type's specific rights
// when a descriptor is assigned or inherited, not when an ACE already sitting
// on the object is evaluated, so a GENERIC_ALL ACE can read as "grants
// nothing" for an open that asks for FILE_READ_DATA. Spell out the rights
// Windows' own tools spell out.
const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF

// secureDir locks down a directory the agent owns. Unix modes are a no-op on
// Windows, so %ProgramData%\HomelabRMM is created with %ProgramData%'s own
// inherited ACL, which grants BUILTIN\Users read-and-execute: every local
// account could read agent.json (device key and enrolment token) and
// agent.log. This replaces the directory's DACL with a PROTECTED one -
// inheritance from the parent is dropped rather than merged - granting full
// control to SYSTEM and the local Administrators group only, inheritable by
// the files and subdirectories created inside it ((OI)(CI) in icacls terms).
//
// Windows propagates the new inheritable entries to the existing children,
// so an agent.json written before this landed is re-secured too.
func secureDir(path string) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("SYSTEM sid: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("Administrators sid: %w", err)
	}
	// The SIDs are Go-heap allocations and the TRUSTEE only holds their
	// addresses; pin them for as long as the entries are read.
	var pinner runtime.Pinner
	pinner.Pin(system)
	pinner.Pin(admins)
	defer pinner.Unpin()

	entries := make([]windows.EXPLICIT_ACCESS, 0, 2)
	for _, sid := range []*windows.SID{system, admins} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	// nil for the merged ACL: the old entries are deliberately discarded.
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return fmt.Errorf("set DACL on %s: %w", path, err)
	}
	return nil
}
