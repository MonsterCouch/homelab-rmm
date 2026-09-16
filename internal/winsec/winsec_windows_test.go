//go:build windows

package winsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// unprotect drops the protection again so the test's own cleanup can delete the
// directory whatever happened to its owner: SecureDir hands ownership to
// Administrators, and a non-elevated run keeps only the entry SecureDir wrote
// for it.
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

// Securing a directory must not cost the caller the use of it. The service
// runs as SYSTEM and an install runs elevated, so SYSTEM + Administrators
// covers them - but `rmm-server run --data-dir <dir>` from an ordinary shell,
// and `go test ./internal/server/` on a developer machine, run as whoever is
// at the keyboard, and for them a DACL with only those two entries denies the
// write below with "Access is denied" on a directory that is now protected
// and, from that process, unusable. Tests that are themselves elevated cannot
// see it, which is why tokenCovered is pinned separately.
func TestSecureDirLeavesTheCallerAbleToUseTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "HomelabRMM")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unprotect(t, dir) })

	if err := SecureDir(dir); err != nil {
		// Taking ownership needs rights an ordinary account does not have;
		// the DACL is applied either way, and that is what is under test.
		t.Logf("SecureDir: %v", err)
	}

	db := filepath.Join(dir, "rmm.db")
	if err := os.WriteFile(db, []byte("data"), 0o600); err != nil {
		t.Fatalf("the process that secured %s can no longer write in it: %v", dir, err)
	}
	if _, err := os.ReadFile(db); err != nil {
		t.Errorf("reading back a file it just wrote: %v", err)
	}
	// The entries are inheritable, so a child directory gets them too.
	if err := os.MkdirAll(filepath.Join(dir, "backups"), 0o700); err != nil {
		t.Errorf("creating a subdirectory: %v", err)
	}
}

// tokenCovered is the decision the fix above turns on, and the only part of it
// that can be exercised whatever the test run's own privileges are.
func TestTokenCoveredIgnoresADenyOnlyAdministrators(t *testing.T) {
	sid := func(known windows.WELL_KNOWN_SID_TYPE) *windows.SID {
		t.Helper()
		s, err := windows.CreateWellKnownSid(known)
		if err != nil {
			t.Fatalf("CreateWellKnownSid: %v", err)
		}
		return s
	}
	system := sid(windows.WinLocalSystemSid)
	admins := sid(windows.WinBuiltinAdministratorsSid)
	users := sid(windows.WinBuiltinUsersSid)
	alice, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatalf("StringToSid: %v", err)
	}
	granted := []*windows.SID{system, admins}

	for _, tc := range []struct {
		name   string
		user   *windows.SID
		groups []windows.SIDAndAttributes
		want   bool
	}{
		{
			name:   "the installed service, whose token user is SYSTEM",
			user:   system,
			groups: []windows.SIDAndAttributes{{Sid: admins, Attributes: windows.SE_GROUP_ENABLED}},
			want:   true,
		},
		{
			name:   "an elevated administrator",
			user:   alice,
			groups: []windows.SIDAndAttributes{{Sid: admins, Attributes: windows.SE_GROUP_ENABLED | windows.SE_GROUP_ENABLED_BY_DEFAULT}},
			want:   true,
		},
		{
			// Measured on a real filtered token: attributes 0x10, where
			// 0xf is what an elevated one carries.
			name: "an administrator in a UAC-filtered shell",
			user: alice,
			groups: []windows.SIDAndAttributes{
				{Sid: admins, Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY},
				{Sid: users, Attributes: windows.SE_GROUP_ENABLED},
			},
			want: false,
		},
		{
			name:   "a standard user",
			user:   alice,
			groups: []windows.SIDAndAttributes{{Sid: users, Attributes: windows.SE_GROUP_ENABLED}},
			want:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenCovered(tc.user, tc.groups, granted); got != tc.want {
				t.Errorf("tokenCovered = %v, want %v: %s", got, tc.want, tc.name)
			}
		})
	}
}

// A directory that is not there cannot be secured, and saying so is what
// makes the callers' warning reachable.
func TestSecureDirReportsAMissingDirectory(t *testing.T) {
	if err := SecureDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("SecureDir silently accepted a missing directory")
	}
}
