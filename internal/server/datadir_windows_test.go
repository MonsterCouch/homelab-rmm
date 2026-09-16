//go:build windows

package server

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// acl-01: the server created its data directory with a Unix mode, which is a
// no-op on Windows, so %ProgramData%\HomelabRMM and everything in it - rmm.db
// (sessions, password hashes, every script and baseline parameter) and
// server.key, the certificate every agent pins - inherited
// "BUILTIN\Users: read and execute" from %ProgramData%. The agent hardened the
// very same path for itself, so a co-installed box was protected by accident
// and a server-only host was not protected at all.
func TestServerDataDirectoryIsNotReadableByEveryLocalUser(t *testing.T) {
	dir := t.TempDir()
	newServerOnly(t, Config{DataDir: dir})
	t.Cleanup(func() {
		// Hand the directory back so the test's own cleanup can delete it.
		windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, nil, nil)
	})

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	acl := sd.String()
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("the data directory still inherits its parent's entries: %s", acl)
	}
	for _, deny := range []string{";BU)", ";WD)", ";AU)", ";IU)", ";S-1-5-32-545)", ";S-1-1-0)", ";S-1-5-11)", ";S-1-5-4)"} {
		if strings.Contains(acl, deny) {
			t.Errorf("rmm.db and server.key are readable beyond SYSTEM and Administrators: %s", acl)
		}
	}
	if !strings.Contains(acl, ";SY)") || !strings.Contains(acl, ";BA)") {
		t.Errorf("the service locked itself out of its own data directory: %s", acl)
	}
}
