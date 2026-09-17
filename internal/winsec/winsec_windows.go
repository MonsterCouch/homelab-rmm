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

// grant is one entry of the DACL SecureDir writes. The trustee type is
// informational once the form is TRUSTEE_IS_SID, but it is what the entry
// means, so it travels with the SID.
type grant struct {
	sid *windows.SID
	typ windows.TRUSTEE_TYPE
}

// SecureDir locks down a directory the service owns. Unix modes are a no-op on
// Windows, so a child of %ProgramData% is created with %ProgramData%'s own
// inherited ACL, which grants BUILTIN\Users read-and-execute: every local
// account could read the agent's agent.json (device key and enrollment token)
// or the server's rmm.db and server.key. This replaces the directory's DACL
// with a PROTECTED one - inheritance from the parent is dropped rather than
// merged - granting full control to SYSTEM and the local Administrators group
// only, inheritable by the files and subdirectories created inside it
// ((OI)(CI) in icacls terms).
//
// Windows propagates the new inheritable entries to the existing children,
// so a file written before this landed is re-secured too.
//
// The account this process runs as is granted the same access when those two
// entries would not cover it - see uncoveredCaller - so that securing a
// directory never costs the caller the use of it.
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
	grants := []grant{
		{sid: system, typ: windows.TRUSTEE_IS_WELL_KNOWN_GROUP},
		{sid: admins, typ: windows.TRUSTEE_IS_WELL_KNOWN_GROUP},
	}
	caller, err := uncoveredCaller([]*windows.SID{system, admins})
	if err != nil {
		return fmt.Errorf("the account this process runs as: %w", err)
	}
	if caller != nil {
		grants = append(grants, grant{sid: caller, typ: windows.TRUSTEE_IS_USER})
	}

	// The SIDs are Go-heap allocations and the TRUSTEE only holds their
	// addresses; pin them for as long as the entries are read.
	var pinner runtime.Pinner
	defer pinner.Unpin()
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(grants))
	for _, g := range grants {
		pinner.Pin(g.sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  g.typ,
				TrusteeValue: windows.TrusteeValueFromSID(g.sid),
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

// uncoveredCaller returns the account this process runs as when a DACL that
// grants only sids would lock it out, and nil when one of those entries covers
// it already.
//
// SYSTEM + Administrators covers the two ways this code is meant to run: the
// installed service, whose token user is SYSTEM, and an elevated install. It
// does not cover `rmm-server run --data-dir <dir>` from an ordinary shell, or
// `go test ./internal/server/` on a developer machine - and there the lockout
// is not something the next line recovers from. The DACL write itself succeeds
// (the caller created the directory, and an owner keeps WRITE_DAC), and then
// the open of rmm.db inside it fails with "Access is denied" on a directory
// that is now protected and, as far as that process can tell, unusable.
//
// Granting the caller its own entry gives nothing away: it is the directory's
// owner, so it could grant itself that access at any moment anyway. Everyone
// else - BUILTIN\Users above all - stays just as excluded, and on the two
// installs that matter the DACL is exactly the one it was before.
func uncoveredCaller(sids []*windows.SID) (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("token user: %w", err)
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return nil, fmt.Errorf("token groups: %w", err)
	}
	if tokenCovered(user.User.Sid, groups.AllGroups(), sids) {
		return nil, nil
	}
	// Copy it out of the token information buffer, which the ACE built from
	// this SID outlives.
	sid, err := user.User.Sid.Copy()
	if err != nil {
		return nil, fmt.Errorf("copy the token user sid: %w", err)
	}
	return sid, nil
}

// tokenCovered reports whether an access token with this user and these groups
// is granted anything by an ACE for one of sids.
//
// Only a group with SE_GROUP_ENABLED counts. A token can carry
// BUILTIN\Administrators as SE_GROUP_USE_FOR_DENY_ONLY - a UAC-filtered shell,
// or a restricted token - where it is present but can match deny entries only,
// and that is exactly the token this has to answer "no" for. Asking the group
// itself is what stays right for both: windows.Token.IsElevated() answers true
// for a restricted token whose Administrators group is deny-only.
func tokenCovered(user *windows.SID, groups []windows.SIDAndAttributes, sids []*windows.SID) bool {
	for _, sid := range sids {
		if user != nil && user.Equals(sid) {
			return true
		}
		for _, g := range groups {
			if g.Attributes&windows.SE_GROUP_ENABLED == 0 {
				continue
			}
			if g.Sid != nil && g.Sid.Equals(sid) {
				return true
			}
		}
	}
	return false
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
