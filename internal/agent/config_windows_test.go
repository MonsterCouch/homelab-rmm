//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// These run for real on Windows and are type-checked everywhere else by
// `GOOS=windows go vet ./...`, which is the only check the Linux build box can
// give a file full of x/sys/windows calls.

// sddl reads back the DACL Windows actually stored and renders it the way
// icacls /save would, so a failure names the entries instead of a bitmask.
func sddl(t *testing.T, path string) (*windows.SECURITY_DESCRIPTOR, string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	return sd, sd.String()
}

// unprotect drops the protection again so the test's own cleanup can delete
// the directory: secureDir hands ownership to Administrators, and a test
// running as a plain user keeps only the entry secureDir wrote for it.
func unprotect(t *testing.T, path string) {
	t.Helper()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, nil, nil); err != nil {
		t.Logf("could not reopen %s for cleanup: %v", path, err)
	}
}

// Nobody but SYSTEM and Administrators may read agent.json: it holds the
// device key and the enrollment token, and %ProgramData%'s inherited ACL grants
// BUILTIN\Users read-and-execute (acl-01). The Unix mode on Save() does
// nothing here, so the DACL is the whole of the fix - and it has to reach the
// file, not only the directory.
func TestConfigSaveLocksDownTheAgentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "HomelabRMM")
	t.Setenv("RMM_AGENT_DIR", dir)
	cfg := &Config{ServerURL: "https://rmm.lan:8443", AgentID: "a1", Key: "device-key", EnrollToken: "enroll"}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	t.Cleanup(func() { unprotect(t, dir) })

	sd, dirACL := sddl(t, dir)
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("DACL is not protected, so %%ProgramData%%'s entries are still inherited: %s", dirACL)
	}
	// (OI)(CI) full control for SYSTEM (SY) and Administrators (BA), so
	// every file created inside is born with the same two entries.
	for _, want := range []string{"(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)"} {
		if !strings.Contains(dirACL, want) {
			t.Errorf("directory DACL %s is missing %s", dirACL, want)
		}
	}
	for _, path := range []string{dir, ConfigPath()} {
		_, acl := sddl(t, path)
		// BU BUILTIN\Users, WD Everyone, AU Authenticated Users,
		// IU Interactive - and the raw SIDs, in case the local
		// language pack renders them differently.
		for _, deny := range []string{";BU)", ";WD)", ";AU)", ";IU)", ";S-1-5-32-545)", ";S-1-1-0)", ";S-1-5-11)", ";S-1-5-4)"} {
			if strings.Contains(acl, deny) {
				t.Errorf("%s is readable beyond SYSTEM and Administrators: %s", path, acl)
			}
		}
		if !strings.Contains(acl, ";SY)") || !strings.Contains(acl, ";BA)") {
			t.Errorf("%s locked the agent itself out: %s", path, acl)
		}
	}
}

// EnsureConfigDir is the only way the directory is created, and a failure to
// secure it must be visible: secureDir returning nil for a path it never
// touched would make the warning in EnsureConfigDir unreachable.
func TestSecureDirReportsFailure(t *testing.T) {
	if err := secureDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("secureDir silently accepted a missing directory")
	}
}

// The desktop helper never logs into the service's file: it cannot write
// ConfigDir under a user token, and rotating agent.log is the service's
// business alone (desk-04).
func TestHelperLogPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RMM_AGENT_DIR", dir)
	paths := HelperLogPaths()
	if len(paths) < 2 {
		t.Fatalf("no fallback for the helper: %v", paths)
	}
	if paths[0] != filepath.Join(dir, "helper.log") {
		t.Errorf("first candidate = %q, want helper.log inside the agent directory", paths[0])
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if p == LogPath() {
			t.Errorf("the helper would write the service's log: %q", p)
		}
		if seen[p] {
			t.Errorf("duplicate candidate %q", p)
		}
		seen[p] = true
	}
	// The last resort has to be somewhere a user token can always write.
	if last := paths[len(paths)-1]; filepath.Dir(last) != filepath.Clean(os.TempDir()) {
		t.Errorf("last candidate %q is not in the temp directory", last)
	}
}
