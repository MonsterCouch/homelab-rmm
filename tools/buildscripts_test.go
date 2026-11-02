// Package tools holds tests for the build scripts that live beside it.
//
// They are checks on the text of the scripts on purpose. build.ps1 only runs on
// Windows (and on the validation machine not even there - the local antivirus
// quarantines PowerShell), build.sh only runs where bash does, and neither can
// be exercised from `go test` without cross-compiling the whole project first.
// What can be pinned cheaply is the handful of invariants the two scripts and
// the Makefile have to share, because a build that silently disagrees with its
// twin is exactly the failure that shipped a Windows release stamped "dev".
package tools

import (
	"os"
	"strings"
	"testing"
)

func readScript(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// Every build entry point stamps the version symbols (main.Version is the one
// rmm-signer prints), and defaults to the same
// git describe. A binary is otherwise indistinguishable from any other build:
// the version is what `rmm-agent --version`, GET /api/system.version and the
// console all report.
func TestEveryBuildEntryPointStampsEveryVersionSymbol(t *testing.T) {
	for _, f := range []string{"build.sh", "build.ps1", "../Makefile"} {
		src := readScript(t, f)
		for _, want := range []string{
			"internal/server.Version=",
			"internal/agent.Version=",
			"-X main.Version=",
			"git describe --tags --always",
		} {
			if !strings.Contains(src, want) {
				t.Errorf("%s does not contain %q", f, want)
			}
		}
	}
}

// The describe call must stand alone: piping a native command into
// Select-Object -First 1 stops the upstream pipeline as soon as it has its
// line, which kills git and leaves $LASTEXITCODE = -1 under Windows PowerShell
// 5.1. build.ps1 read that as failure and stamped every Windows build "dev"
// even on a tagged commit.
func TestBuildPs1ReadsTheDescribeExitCodeBeforeAnyPipeline(t *testing.T) {
	lines := strings.Split(readScript(t, "build.ps1"), "\n")
	calls := []int{}
	for i, l := range lines {
		if strings.Contains(l, "& git describe") {
			calls = append(calls, i)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("build.ps1 makes %d calls to git describe, want exactly 1", len(calls))
	}
	i := calls[0]
	if strings.Contains(lines[i], "|") {
		t.Errorf("build.ps1:%d pipes the git describe call:\n\t%s\n"+
			"a pipeline that stops early kills the native process and leaves $LASTEXITCODE = -1 "+
			"under Windows PowerShell 5.1, so the version is thrown away and the build is stamped 'dev'",
			i+1, strings.TrimSpace(lines[i]))
	}
	if i+1 >= len(lines) || !strings.Contains(lines[i+1], "$LASTEXITCODE") {
		t.Errorf("build.ps1:%d does not capture $LASTEXITCODE on the statement after the git describe call; "+
			"anything in between overwrites it", i+2)
	}
}

// `package` archives whatever `server` and `agents` last left in dist/: without
// this guard a run that skips them ships a binary built from different source
// than the docs beside it, and nothing about the archive looks wrong until
// someone runs it. Both packagers must refuse it, and both must take the same
// escape hatch.
func TestBothPackagersRefuseStaleBinaries(t *testing.T) {
	sh := readScript(t, "build.sh")
	for _, want := range []string{"ALLOW_STALE_BUILD", `fresh "$srv" server`, `fresh "$a" agents`} {
		if !strings.Contains(sh, want) {
			t.Errorf("build.sh does not contain %q", want)
		}
	}
	ps := readScript(t, "build.ps1")
	for _, want := range []string{"ALLOW_STALE_BUILD", "function Assert-Fresh", "Assert-Fresh $srv 'server'", "Assert-Fresh $a 'agents'"} {
		if !strings.Contains(ps, want) {
			t.Errorf("build.ps1 does not contain %q (the twin of fresh() in build.sh)", want)
		}
	}
}

// rmm-signer has to be built, packaged and checksummed the same way by both
// scripts, for windows/amd64 and windows/arm64 only: the WebAuthn API it signs
// with is part of Windows, so a linux binary would be shipped dead weight.
func TestBothScriptsBuildAndPackageTheSigner(t *testing.T) {
	sh := readScript(t, "build.sh")
	for _, want := range []string{
		`SIGNER_PLATFORMS="windows/amd64 windows/arm64"`,
		`signer)    build_platforms rmm-signer`,
		`fresh "$s" signer`,
		`"$DIST"/rmm-signer-*`,
	} {
		if !strings.Contains(sh, want) {
			t.Errorf("build.sh does not contain %q", want)
		}
	}
	ps := readScript(t, "build.ps1")
	for _, want := range []string{
		`$signerPlatforms = @('windows/amd64', 'windows/arm64')`,
		`'signer'    { Build-Signer }`,
		`Assert-Fresh $s 'signer'`,
		`rmm-(server|agent|signer)-`,
	} {
		if !strings.Contains(ps, want) {
			t.Errorf("build.ps1 does not contain %q", want)
		}
	}
}
