//go:build windows

package agent

import (
	"github.com/MonsterCouch/homelab-rmm/internal/winsec"
	"golang.org/x/sys/windows/registry"
)

// secureDir locks %ProgramData%\HomelabRMM down to SYSTEM and Administrators:
// a protected DACL, and an owner that cannot hand the directory back to
// BUILTIN\Users. The server needs the very same thing for its data directory
// (the same path, when both are installed on one box), so the implementation
// lives in internal/winsec.
func secureDir(path string) error { return winsec.SecureDir(path) }

func saveRegistryClientInfo(serverURL, agentID string) {
	if serverURL == "" && agentID == "" {
		return
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\HomelabRMM`, registry.SET_VALUE|registry.WOW64_64KEY)
	if err == nil {
		if serverURL != "" {
			_ = k.SetStringValue("ServerURL", serverURL)
		}
		if agentID != "" {
			_ = k.SetStringValue("AgentID", agentID)
		}
		k.Close()
	}
}
