//go:build windows

package agent

import "github.com/MonsterCouch/homelab-rmm/internal/winsec"

// secureDir locks %ProgramData%\HomelabRMM down to SYSTEM and Administrators:
// a protected DACL, and an owner that cannot hand the directory back to
// BUILTIN\Users. The server needs the very same thing for its data directory
// (the same path, when both are installed on one box), so the implementation
// lives in internal/winsec.
func secureDir(path string) error { return winsec.SecureDir(path) }
