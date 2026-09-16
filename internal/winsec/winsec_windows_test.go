//go:build windows

package winsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// unprotect hands the directory back to everyone so the test's own cleanup
// can delete it: after SecureDir a test running as a plain user is no longer
// on the ACL. Only the owner's implicit right to rewrite a DACL makes this
// possible - which is the very right this package takes away from whoever
// pre-created the directory.
func unprotect(t *testing.T, path string) {
	t.Helper()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, nil, nil); err != nil {
		t.Logf("could not reopen %s for cleanup: %v", path, err)
	}
}

// %ProgramData% lets any local user create a directory and stamps them as its
// owner, and an owner keeps READ_CONTROL and WRITE_DAC whatever the DACL says:
// a standard user who pre-creates the directory before the agent or the server
// is installed can simply grant BUILTIN\Users read access back afterwards, and
// then read the device key, the enrolment token, rmm.db and server.key. So the
// owner is part of the fix, and a failure to set it is never silent (acl-01).
func TestSecureDirTakesOwnershipOrSaysWhyNot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "HomelabRMM")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unprotect(t, dir) })

	err := SecureDir(dir)

	owner, oerr := ownerOf(dir)
	if oerr != nil {
		t.Fatalf("reading the owner back: %v", oerr)
	}
	switch {
	case ownerIsPrivileged(owner):
		if err != nil {
			t.Errorf("SecureDir reported a failure it did not have: %v", err)
		}
	case err == nil:
		t.Errorf("%s is owned by %s, which can rewrite its permissions, and SecureDir said nothing", dir, owner)
	case !strings.Contains(err.Error(), "owner"):
		t.Errorf("the failure must name the owner problem, got %v", err)
	}

	// Whatever happened to the owner, the DACL is applied: the two are
	// separate calls precisely so a caller that cannot take ownership still
	// gets the protection it can have.
	sd, derr := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if derr != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", derr)
	}
	acl := sd.String()
	control, _, cerr := sd.Control()
	if cerr != nil {
		t.Fatalf("Control: %v", cerr)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("the DACL is not protected, so the parent's entries are still inherited: %s", acl)
	}
	for _, want := range []string{"(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)"} {
		if !strings.Contains(acl, want) {
			t.Errorf("DACL %s is missing %s", acl, want)
		}
	}
	// BU BUILTIN\Users, WD Everyone, AU Authenticated Users, IU Interactive,
	// and the raw SIDs in case a language pack renders them differently.
	for _, deny := range []string{";BU)", ";WD)", ";AU)", ";IU)", ";S-1-5-32-545)", ";S-1-1-0)", ";S-1-5-11)", ";S-1-5-4)"} {
		if strings.Contains(acl, deny) {
			t.Errorf("%s is readable beyond SYSTEM and Administrators: %s", dir, acl)
		}
	}
}

// A directory that is not there cannot be secured, and saying so is what
// makes the callers' warning reachable.
func TestSecureDirReportsAMissingDirectory(t *testing.T) {
	if err := SecureDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("SecureDir silently accepted a missing directory")
	}
}
