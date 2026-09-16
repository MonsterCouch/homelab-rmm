package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var uninstallAgentNamesRe = regexp.MustCompile(`(?s)\$agent(?:Names|Files)\s*=\s*@\(([^)]*)\)`)
var psQuotedRe = regexp.MustCompile(`'([^']+)'`)

// deploy/uninstall.ps1 -Purge deletes a fixed list of file names rather than the
// directory, because on Windows the agent shares %ProgramData%\HomelabRMM with a
// co-located server and the server's database must survive an agent uninstall.
// The cost of that design is this invariant: every file this package writes into
// ConfigDir has to be on the list, or it survives -Purge, keeps the directory
// from being removed, and is inherited by the next install. That is how a purged
// machine kept its baselines.json (stale desired state for the next enrolment)
// and its helper.log.
func TestUninstallScriptPurgesEveryFileTheAgentWritesIntoItsDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)

	// Derived from the paths themselves, so a new file under ConfigDir fails
	// here until deploy/uninstall.ps1 learns about it.
	want := []string{
		filepath.Base(ConfigPath()),                 // agent.json: identity and enrolment token
		filepath.Base(ConfigPath()) + ".tmp",        // SaveConfig writes then renames
		filepath.Base(LogPath()),                    // agent.log: the service's own log
		filepath.Base(LogPath()) + ".1",             // its one rotation (cmd/rmm-agent)
		filepath.Base(baselineStatePath()),          // baselines.json: cached desired state
		filepath.Base(baselineStatePath()) + ".tmp", // saved the same way
	}
	// The desktop helper prefers ConfigDir when it runs with the service's
	// rights, which is the case that leaves a file behind here.
	helper := HelperLogPaths()[0]
	if filepath.Dir(helper) != dir {
		t.Fatalf("HelperLogPaths()[0] = %q, expected it inside the config directory %q", helper, dir)
	}
	want = append(want, filepath.Base(helper))

	script := readRepoTextFile(t, filepath.Join("..", "..", "deploy", "uninstall.ps1"))
	m := uninstallAgentNamesRe.FindStringSubmatch(script)
	if m == nil {
		t.Fatal("deploy/uninstall.ps1 no longer defines the -Purge file list as $agentNames = @(...)")
	}
	listed := map[string]bool{}
	for _, q := range psQuotedRe.FindAllStringSubmatch(m[1], -1) {
		listed[strings.ToLower(q[1])] = true
	}
	for _, name := range want {
		if !listed[strings.ToLower(name)] {
			t.Errorf("deploy/uninstall.ps1 $agentNames does not list %q, so -Purge leaves it in the data directory", name)
		}
	}
}

// The Linux twin needs no such list: the agent owns /etc/homelab-rmm outright
// there, so --purge removes the whole directory. If that ever changes it needs
// the same enumeration as the Windows script.
func TestUninstallShellScriptPurgesTheWholeConfigDirectory(t *testing.T) {
	script := readRepoTextFile(t, filepath.Join("..", "..", "deploy", "uninstall.sh"))
	if !strings.Contains(script, `rm -rf "$cfg"`) {
		t.Error(`deploy/uninstall.sh no longer removes the agent's configuration directory with rm -rf "$cfg"`)
	}
}

func readRepoTextFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}
