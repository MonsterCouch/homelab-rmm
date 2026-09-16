package svc

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// The warning is the whole fix for a service image sitting in a directory the
// installing user can write, so it has to carry everything the operator needs
// to act: which directory, who can write it, and where the binary belongs.
func TestImagePathWarningNamesTheDirectoryTheWritersAndTheWayOut(t *testing.T) {
	got := imagePathWarning(`C:\Users\temp\Downloads`, []string{`DESKTOP-X\temp (S-1-5-21-1-2-3-1001)`}, `C:\Program Files\HomelabRMM`)
	for _, want := range []string{`C:\Users\temp\Downloads`, `DESKTOP-X\temp`, `C:\Program Files\HomelabRMM`} {
		if !strings.Contains(got, want) {
			t.Errorf("the warning does not mention %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, "WARNING") {
		t.Errorf("the warning is not recognisable as one:\n%s", got)
	}
}

// A location that cannot be inspected is not an accusation: `install` must not
// print a warning it cannot substantiate.
func TestImagePathWarningIsSilentAboutAMissingDirectory(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "no-such-dir", "rmm-agent")
	if got := ImagePathWarning(exe); got != "" {
		t.Fatalf("ImagePathWarning = %q, want nothing", got)
	}
}

func TestUnixWritersFlagsEveryAccountThatCanReplaceTheBinary(t *testing.T) {
	cases := []struct {
		name string
		mode fs.FileMode
		uid  int
		want []string
	}{
		{"root-owned and admin-only", 0o755, 0, nil},
		{"unpacked in a user's home", 0o755, 1000, []string{"uid 1000"}},
		{"group-writable", 0o775, 0, []string{"its group"}},
		{"world-writable", 0o777, 0, []string{"its group", "world-writable"}},
		{"downloaded and left open", 0o777, 1000, []string{"uid 1000", "its group", "world-writable"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(unixWriters(tc.mode, tc.uid), "; ")
			if len(tc.want) == 0 {
				if got != "" {
					t.Fatalf("unixWriters = %q, want nothing to report", got)
				}
				return
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("unixWriters = %q, want it to mention %q", got, want)
				}
			}
		})
	}
}
