package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// The file browser had no path validation at all. These pin the rules the
// first real-Windows run showed were missing; each asserts an invariant, not
// an environment, so they hold on either platform.

func TestFsRejectsARelativePath(t *testing.T) {
	// A relative path is resolved against the agent's working directory. For a
	// Windows service that is C:\Windows\System32, so "..", "C:" and a bare
	// name all used to reach real files there.
	for _, p := range []string{"..", "C:", "relative/name.txt", "."} {
		if _, err := fsCheckPath(p); err == nil {
			t.Errorf("%q was accepted; a relative path must be refused", p)
		} else if !strings.Contains(err.Error(), "absolute") {
			t.Errorf("%q: the refusal should say why, got %v", p, err)
		}
	}
}

func TestFsRefusesItsOwnConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)

	// Reads too, not only writes: agent.json holds the device key, so being
	// able to download it is the whole problem.
	for _, p := range []string{
		filepath.Join(dir, "agent.json"),
		filepath.Join(dir, "nested", "deeper.txt"),
		dir,
	} {
		if _, err := fsCheckPath(p); err == nil {
			t.Errorf("%q was accepted; the agent's own config directory must be refused", p)
		}
	}
	if _, err := fsRead(protocol.FsRead{Path: filepath.Join(dir, "agent.json")}); err == nil {
		t.Error("fsRead served a file from the agent's own configuration directory")
	}
	if err := fsDelete(filepath.Join(dir, "agent.json")); err == nil {
		t.Error("fsDelete accepted the agent's own configuration directory")
	}

	// A sibling that merely shares a prefix is a legitimate target.
	if _, err := fsCheckPath(dir + "-notes.txt"); err != nil {
		t.Errorf("a path beside the config directory must stay reachable: %v", err)
	}
}

func TestFsRefusesAFilesystemRootForWrites(t *testing.T) {
	roots := []string{"/"}
	if runtime.GOOS == "windows" {
		roots = []string{`C:\`, `C:/`}
	}
	for _, r := range roots {
		if _, err := fsCheckWritePath(r); err == nil {
			t.Errorf("%q was accepted as a write target", r)
		}
	}
}

func TestFsDeleteReportsWhatHappened(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, filepath.Join(dir, "cfg"))

	// A path that does not exist used to answer ok, which produced a green
	// "Deleted X" toast and an audit row for a file that was never there.
	if err := fsDelete(filepath.Join(dir, "absent.txt")); err == nil {
		t.Error("deleting a path that does not exist reported success")
	}

	p := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsDelete(p); err != nil {
		t.Fatalf("deleting a real file failed: %v", err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Error("the file survived a delete that reported success")
	}
}

func TestFsRenameWillNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, filepath.Join(dir, "cfg"))
	from := filepath.Join(dir, "report.txt")
	to := filepath.Join(dir, "config.txt")
	if err := os.WriteFile(from, []byte("report"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("KEEP ME"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsRename(from, to); err == nil {
		t.Fatal("rename silently replaced an existing file")
	}
	if b, err := os.ReadFile(to); err != nil || string(b) != "KEEP ME" {
		t.Fatalf("the destination was destroyed: %q %v", b, err)
	}
	// Renaming onto a free name still works.
	fresh := filepath.Join(dir, "renamed.txt")
	if err := fsRename(from, fresh); err != nil {
		t.Fatalf("an ordinary rename failed: %v", err)
	}
}

func TestFsRenameRequiresTheSourceToExist(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, filepath.Join(dir, "cfg"))
	if err := fsRename(filepath.Join(dir, "nope.txt"), filepath.Join(dir, "x.txt")); err == nil {
		t.Error("renaming a path that does not exist reported success")
	}
}

func TestFsOSPathOnlyRewritesWindowsDriveePaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		if got := fsOSPath("/etc/hosts"); got != "/etc/hosts" {
			t.Errorf("a unix path must be untouched, got %q", got)
		}
		return
	}
	// Trailing dots and spaces are why this exists: Win32 strips them while
	// normalising, so the call landed on a different file than the listing
	// showed.
	if got := fsOSPath(`C:\tmp\report.txt.`); got != `\\?\C:\tmp\report.txt.` {
		t.Errorf("extended-length prefix missing, got %q", got)
	}
	// A UNC path is already prefixed differently, and a relative path cannot
	// carry the prefix at all.
	for _, p := range []string{`\\server\share\f.txt`, `relative.txt`, `\\?\C:\already`} {
		if got := fsOSPath(p); got != p {
			t.Errorf("%q must be untouched, got %q", p, got)
		}
	}
}

func TestFsListTruncatesInsteadOfDroppingTheSocket(t *testing.T) {
	// The whole listing goes into one agent frame and the server closes the
	// device's socket when a frame is too large, so a big directory took the
	// device offline. Proving the cap without creating 20k files: the flag and
	// the bound travel together, so assert the contract on a small directory
	// and the constant itself.
	if fsMaxEntries <= 0 {
		t.Fatal("fsMaxEntries must bound the listing")
	}
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, filepath.Join(dir, "cfg"))
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".txt"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := fsList(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated {
		t.Error("a three-entry directory was reported as truncated")
	}
	if len(res.Entries) != 3 {
		t.Errorf("want 3 entries, got %d", len(res.Entries))
	}
}
