package agent

import (
	"strings"
	"testing"
	"time"
)

// A mount is normalised to the platform's own spelling, and the normalisation
// never produces an empty name: "at least 10% free on " is a label no operator
// can read, and an empty mount sent blResolveMount probing a bare separator,
// which disk.Usage answers for whatever drive the agent happens to run from.
func TestMountNormalisationNeverEmpties(t *testing.T) {
	cases := []struct {
		goos, in, want string
	}{
		{"windows", "c:", "C:"},
		{"windows", `C:\`, "C:"},
		{"windows", "C:/", "C:"},
		{"windows", " d ", "D:"},
		{"windows", `D:\data`, `D:\DATA`},
		{"windows", "/mnt/data", `\MNT\DATA`},
		{"windows", "/", "/"},
		{"windows", `\`, `\`},
		{"linux", "srv", "/srv"},
		{"linux", "/srv/", "/srv"},
		{"linux", "/", "/"},
	}
	for _, tc := range cases {
		if got := blNormaliseMountOn(tc.goos, tc.in); got != tc.want {
			t.Errorf("%s %q normalised to %q, want %q", tc.goos, tc.in, got, tc.want)
		}
	}
	for _, in := range []string{"/", `\`, "c:", "/srv"} {
		for _, goos := range []string{"windows", "linux"} {
			if blNormaliseMountOn(goos, in) == "" {
				t.Errorf("%s %q normalised to nothing", goos, in)
			}
		}
	}
}

// A unix root on a Windows device is not a Windows mount. It has to be an
// error that names the mount, not a silent measurement of the system drive.
func TestMountNamedRefusesAUnixRootOnWindows(t *testing.T) {
	for _, m := range []string{"/", `\`} {
		err := blMountNamed("windows", blNormaliseMountOn("windows", m))
		if err == nil {
			t.Fatalf("%q must not name a Windows mount", m)
		}
		if !strings.Contains(err.Error(), m) || !strings.Contains(err.Error(), "not a mount point") {
			t.Fatalf("the refusal must name the mount: %v", err)
		}
		if blMountNamed("linux", blNormaliseMountOn("linux", m)) != nil {
			t.Fatalf("%q is the root filesystem on Linux", m)
		}
	}
	for _, m := range []string{"C:", `D:\data`, "/srv"} {
		if err := blMountNamed("windows", m); err != nil {
			t.Fatalf("%q is a mount worth probing on Windows: %v", m, err)
		}
	}
	if blMountNamed("windows", "  ") == nil || blMountNamed("linux", "") == nil {
		t.Fatal("an empty mount is refused before any disk is probed")
	}
}

// The script runner's deadline has to fire a clear second before the engine's,
// or probe abandons the check and the script's partial output - the only clue
// an operator gets about a check that timed out - is lost with it.
func TestScriptTimeoutKeepsASecondOfHeadroom(t *testing.T) {
	cases := []struct {
		remaining time.Duration
		want      int
	}{
		{5 * time.Second, 4},
		{4999 * time.Millisecond, 3},
		{20 * time.Second, 19},
		{600 * time.Second, 599},
		{1500 * time.Millisecond, 1},
		{0, 1},
		{-3 * time.Second, 1},
	}
	for _, tc := range cases {
		if got := blScriptTimeout(tc.remaining); got != tc.want {
			t.Errorf("%s left: runner timeout %d, want %d", tc.remaining, got, tc.want)
		}
	}
	for _, remaining := range []time.Duration{5 * time.Second, 7300 * time.Millisecond, 60 * time.Second} {
		headroom := remaining - time.Duration(blScriptTimeout(remaining))*time.Second
		if headroom < time.Second {
			t.Errorf("%s left: only %s of headroom, the engine deadline would win", remaining, headroom)
		}
	}
}
