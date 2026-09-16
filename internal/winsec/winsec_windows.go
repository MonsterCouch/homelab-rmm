//go:build windows

package winsec

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

// SecureDir locks down a directory the service owns. Unix modes are a no-op on
// Windows, so a child of %ProgramData% is created with %ProgramData%'s own
// inherited ACL, which grants BUILTIN\Users read-and-execute: every local
// account could read the agent's agent.json (device key and enrolment token)
// or the server's rmm.db and server.key. This replaces the directory's DACL
// with a PROTECTED one - inheritance from the parent is dropped rather than
// merged - granting full control to SYSTEM and the local Administrators group
// only, inheritable by the files and subdirectories created inside it
// ((OI)(CI) in icacls terms).
//
// Windows propagates the new inheritable entries to the existing children,
// so a file written before this landed is re-secured too.
//
// The DACL alone is not enough. %ProgramData% lets any local user create a
// directory and stamps them as its CREATOR OWNER, and an owner holds
// READ_CONTROL and WRITE_DAC whatever the DACL says - so a standard user who
// pre-creates the directory before the first install can hand BUILTIN\Users
// read access straight back afterwards. The owner is therefore set to
// Administrators as well, and read back to prove it took (acl-01).
func SecureDir(path string) error {
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
	// Separate call on purpose: setting an owner needs rights the DACL does
	// not, and a caller that cannot take ownership (a non-elevated developer
	// run) should still get the DACL rather than neither.
	return secureOwner(path, admins)
}

// secureOwner makes SYSTEM or Administrators the owner of path, and says so
// when it cannot: an owner that is neither can rewrite the DACL SecureDir
// just applied, so a silent failure here is the whole bug.
func secureOwner(path string, admins *windows.SID) error {
	if owner, err := ownerOf(path); err == nil && ownerIsPrivileged(owner) {
		return nil
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		return fmt.Errorf("set owner on %s: %w", path, err)
	}
	owner, err := ownerOf(path)
	if err != nil {
		return fmt.Errorf("read back the owner of %s: %w", path, err)
	}
	if !ownerIsPrivileged(owner) {
		return fmt.Errorf("%s is owned by %s, which can rewrite its permissions", path, owner)
	}
	return nil
}

// ownerOf reads the object's current owner SID.
func ownerOf(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, err
	}
	return owner, nil
}

// ownerIsPrivileged reports whether an owner already has, through the DACL
// SecureDir writes, everything ownership would give it anyway.
func ownerIsPrivileged(owner *windows.SID) bool {
	if owner == nil {
		return false
	}
	for _, known := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if sid, err := windows.CreateWellKnownSid(known); err == nil && owner.Equals(sid) {
			return true
		}
	}
	return false
}
