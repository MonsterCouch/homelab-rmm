//go:build windows

package svc

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// fileAllAccess is winnt.h's FILE_ALL_ACCESS, the mask icacls writes for an
// "(F)" grant; x/sys has no constant for it.
const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF

func TestGrantsWrite(t *testing.T) {
	cases := []struct {
		name string
		mask uint32
		want bool
	}{
		{"read and execute", windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE, false},
		{"read the ACL", windows.READ_CONTROL | windows.SYNCHRONIZE, false},
		{"write the file", windows.FILE_WRITE_DATA, true},
		{"append to it", windows.FILE_APPEND_DATA, true},
		{"delete it", windows.DELETE, true},
		{"delete it out of its directory", fileDeleteChild, true},
		{"rewrite its DACL", windows.WRITE_DAC, true},
		{"take ownership", windows.WRITE_OWNER, true},
		{"unmapped generic write", windows.GENERIC_WRITE, true},
		{"unmapped full control", windows.GENERIC_ALL, true},
	}
	for _, tc := range cases {
		if got := grantsWrite(tc.mask); got != tc.want {
			t.Errorf("grantsWrite(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAdministrativeAccounts(t *testing.T) {
	// NT AUTHORITY\SYSTEM, BUILTIN\Administrators, NT SERVICE\TrustedInstaller.
	for _, sid := range []string{
		"S-1-5-18",
		"S-1-5-32-544",
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
	} {
		if !administrative(sid) {
			t.Errorf("%s should not be reported as a writer: it is already an administrator", sid)
		}
	}
	// BUILTIN\Users, Everyone, Authenticated Users, INTERACTIVE, a local account.
	for _, sid := range []string{
		"S-1-5-32-545",
		"S-1-1-0",
		"S-1-5-11",
		"S-1-5-4",
		"S-1-5-21-1-2-3-1001",
	} {
		if administrative(sid) {
			t.Errorf("%s was treated as an administrator", sid)
		}
	}
}

// tempDirWithACL makes a directory this test owns, so it can still rewrite the
// DACL after grant locks it down.
func tempDirWithACL(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// grant replaces path's DACL with one allow entry per SID, inheritance from
// the parent dropped, so the test knows exactly what the ACL says. inherit is
// what the entries themselves pass down: SUB_CONTAINERS_AND_OBJECTS_INHERIT
// for a directory, NO_INHERITANCE for a file.
func grant(t *testing.T, path string, sids []*windows.SID, mask windows.ACCESS_MASK, inherit uint32) {
	t.Helper()
	var pinner runtime.Pinner
	defer pinner.Unpin()
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for _, sid := range sids {
		pinner.Pin(sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo(%s): %v", path, err)
	}
	// Hand the directory back so the temp-directory cleanup can delete it:
	// after a protected SYSTEM+Administrators DACL the test process is no
	// longer on the ACL. Registered after t.TempDir's own cleanup, so it runs
	// before it.
	t.Cleanup(func() {
		windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, nil, nil)
	})
}

func wellKnown(t *testing.T, which windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(which)
	if err != nil {
		t.Fatalf("CreateWellKnownSid: %v", err)
	}
	return sid
}

// The directory the rendered installer uses (%ProgramFiles%\HomelabRMM) carries
// exactly this DACL, and `install` must not cry wolf about it.
func TestUnprotectedWritersAcceptsAnAdministratorsOnlyDirectory(t *testing.T) {
	dir := tempDirWithACL(t, "HomelabRMM")
	grant(t, dir, []*windows.SID{
		wellKnown(t, windows.WinLocalSystemSid),
		wellKnown(t, windows.WinBuiltinAdministratorsSid),
	}, fileAllAccess, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	writers, err := unprotectedWriters(dir)
	if err != nil {
		t.Fatalf("unprotectedWriters: %v", err)
	}
	if len(writers) != 0 {
		t.Fatalf("an administrators-only directory was reported as writable by %v", writers)
	}
}

// The state the live box was found in: the image of a LocalSystem service in a
// directory whose ACL grants a non-administrative principal write access.
func TestUnprotectedWritersFindsANonAdministrativeWriter(t *testing.T) {
	dir := tempDirWithACL(t, "Downloads")
	grant(t, dir, []*windows.SID{
		wellKnown(t, windows.WinLocalSystemSid),
		wellKnown(t, windows.WinBuiltinAdministratorsSid),
		wellKnown(t, windows.WinBuiltinUsersSid),
	}, fileAllAccess, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	writers, err := unprotectedWriters(dir)
	if err != nil {
		t.Fatalf("unprotectedWriters: %v", err)
	}
	if len(writers) != 1 || !strings.Contains(writers[0], "S-1-5-32-545") {
		t.Fatalf("writers = %v, want BUILTIN\\Users reported once", writers)
	}
	// And it has to reach the operator through the warning `install` prints.
	if w := ImagePathWarning(filepath.Join(dir, "rmm-agent.exe")); !strings.Contains(w, dir) || !strings.Contains(w, "S-1-5-32-545") {
		t.Fatalf("ImagePathWarning = %q", w)
	}
}

// A read-only grant is not a way to replace the binary.
func TestUnprotectedWritersIgnoresReadOnlyPrincipals(t *testing.T) {
	dir := tempDirWithACL(t, "ProgramFiles")
	grant(t, dir, []*windows.SID{wellKnown(t, windows.WinBuiltinUsersSid)},
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	writers, err := unprotectedWriters(dir)
	if err != nil {
		t.Fatalf("unprotectedWriters: %v", err)
	}
	if len(writers) != 0 {
		t.Fatalf("a read-only grant was reported as write access: %v", writers)
	}
}

// The other half of the live state: the directory was fine but the binary in
// it carried an explicit entry for the interactive user, which is what a
// binary built or unpacked by that account looks like. Replacing it in place
// is SYSTEM at the next start just the same, so the check must not stop at the
// directory.
func TestImagePathWarningFlagsTheBinaryItselfInsideASoundDirectory(t *testing.T) {
	dir := tempDirWithACL(t, "HomelabRMM")
	exe := filepath.Join(dir, "rmm-agent.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The binary: full control for a non-administrative principal.
	grant(t, exe, []*windows.SID{
		wellKnown(t, windows.WinLocalSystemSid),
		wellKnown(t, windows.WinBuiltinAdministratorsSid),
		wellKnown(t, windows.WinBuiltinUsersSid),
	}, fileAllAccess, windows.NO_INHERITANCE)
	// The directory: nobody but administrators can write it, but the test
	// process still has to be able to read the file's ACL through it.
	grant(t, dir, []*windows.SID{
		wellKnown(t, windows.WinLocalSystemSid),
		wellKnown(t, windows.WinBuiltinAdministratorsSid),
	}, fileAllAccess, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if writers, err := unprotectedWriters(dir); err != nil || len(writers) != 0 {
		t.Fatalf("the directory should be sound: writers = %v, err = %v", writers, err)
	}

	w := ImagePathWarning(exe)
	if !strings.Contains(w, exe) || !strings.Contains(w, "S-1-5-32-545") {
		t.Fatalf("ImagePathWarning = %q, want it to name %s and BUILTIN\\Users", w, exe)
	}
}
