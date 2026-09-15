//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const noConsoleSession = 0xFFFFFFFF // WTSGetActiveConsoleSessionId: nobody at the console

// WTSQuerySessionInformation(WTSSessionInfoEx) is not wrapped by x/sys.
var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
)

const (
	wtsSessionInfoEx = 25 // WTS_INFO_CLASS.WTSSessionInfoEx

	// WTSINFOEXW is {DWORD Level; WTSINFOEX_LEVEL_W Data}. Data holds
	// LARGE_INTEGERs, so MSVC aligns it to 8 on x86 and x64 alike, which
	// puts SessionFlags (the third DWORD of Data) at byte 16.
	wtsInfoExFlagsOffset = 16
	wtsSessionStateLock  = 0 // WTS_SESSIONSTATE_LOCK
	wtsSessionStateUnlok = 1 // WTS_SESSIONSTATE_UNLOCK
)

// launch is the Windows service path: the agent lives in session 0, which
// has no desktop of its own, so the helper is created inside the console
// session with that session's token (or ours, re-homed into the session,
// when no one is logged in and only winlogon is on screen).
func launch(exe, serverURL, token, fingerprint string, quality int) (string, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		slog.Debug("desktop: cannot tell whether this is a service; assuming interactive", "err", err)
	}
	if !isService {
		serveInProcess(serverURL, token, fingerprint, quality)
		return "running in-process", nil
	}

	sid := windows.WTSGetActiveConsoleSessionId()
	if sid == noConsoleSession {
		return "", errors.New("no console session")
	}
	// Services hold these privileges but start with them disabled;
	// CreateProcessAsUser and TokenSessionId need them enabled.
	enablePrivileges("SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege")

	tok, note, err := sessionToken(sid)
	if err != nil {
		return "", err
	}
	defer tok.Close()

	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		return "", fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(env)

	exe16, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return "", fmt.Errorf("executable path: %w", err)
	}
	cmd16, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{exe}, helperArgs(serverURL, token, fingerprint, quality)...)))
	if err != nil {
		return "", fmt.Errorf("command line: %w", err)
	}
	dir16, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return "", fmt.Errorf("working directory: %w", err)
	}
	desktop16, _ := windows.UTF16PtrFromString(`winsta0\default`)

	si := windows.StartupInfo{Desktop: desktop16}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	err = windows.CreateProcessAsUser(tok, exe16, cmd16, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, env, dir16, &si, &pi)
	if err != nil {
		return "", fmt.Errorf("CreateProcessAsUser in session %d: %w", sid, err)
	}
	windows.CloseHandle(pi.Thread)
	slog.Info("desktop helper started", "pid", pi.ProcessId, "session", sid, "note", note)
	go reapHelper(pi.Process, pi.ProcessId)
	return note, nil
}

// reapHelper logs the helper's exit so a crash shows up in the agent log
// instead of only as "helper did not connect" in the viewer.
func reapHelper(h windows.Handle, pid uint32) {
	defer windows.CloseHandle(h)
	if _, err := windows.WaitForSingleObject(h, windows.INFINITE); err != nil {
		return
	}
	var code uint32
	windows.GetExitCodeProcess(h, &code)
	slog.Info("desktop helper exited", "pid", pid, "exit_code", code)
}

// sessionToken returns a primary token usable by CreateProcessAsUser for the
// console session, and the note describing whose desktop it will show.
//
// The user's own token is preferred (the helper then runs with the user's
// rights, and only the user's desktop is visible). Two situations need the
// SYSTEM token re-homed into the session instead: nobody is logged in, and
// the session is locked. In both the input desktop is winlogon's, which a
// user-token process cannot even open, so a user-token helper would stream
// a frozen image of the last unlocked desktop and the operator could never
// unlock the machine. SYSTEM can follow the input desktop wherever it
// goes, so the same helper keeps working after the unlock.
func sessionToken(sid uint32) (windows.Token, string, error) {
	if locked, known := sessionLocked(sid); known && locked {
		slog.Info("desktop: console session is locked, using SYSTEM", "session", sid)
		return systemSessionToken(sid, "the console session is locked; running as SYSTEM so the lock screen can be captured and unlocked")
	}
	var userTok windows.Token
	if err := windows.WTSQueryUserToken(sid, &userTok); err == nil {
		defer userTok.Close()
		var primary windows.Token
		if err := windows.DuplicateTokenEx(userTok, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
			return 0, "", fmt.Errorf("duplicate user token: %w", err)
		}
		return primary, fmt.Sprintf("attached to console session %d of %s", sid, tokenAccount(primary)), nil
	} else {
		slog.Info("desktop: no user token for the console session, using SYSTEM", "session", sid, "err", err)
	}
	return systemSessionToken(sid, "no user is logged in; showing the logon screen (as SYSTEM)")
}

// sessionLocked asks the session manager whether sid sits at the lock
// screen. known is false when the OS cannot say (the query failed, or it
// answered WTS_SESSIONSTATE_UNKNOWN), in which case the caller falls back
// to the user-token path.
func sessionLocked(sid uint32) (locked, known bool) {
	if err := procWTSQuerySessionInformationW.Find(); err != nil {
		return false, false
	}
	var (
		buf *uint16
		n   uint32
	)
	r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(sid), wtsSessionInfoEx, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return false, false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	if n < wtsInfoExFlagsOffset+4 || *(*uint32)(unsafe.Pointer(buf)) != 1 {
		return false, false // not the level-1 layout we know
	}
	flags := *(*int32)(unsafe.Add(unsafe.Pointer(buf), wtsInfoExFlagsOffset))
	// Windows 7 / Server 2008 R2 report the two values swapped (documented
	// in the WTSINFOEX_LEVEL1 remarks); everything since 8 is sane.
	if v := windows.RtlGetVersion(); v != nil && (v.MajorVersion < 6 || (v.MajorVersion == 6 && v.MinorVersion < 2)) {
		switch flags {
		case wtsSessionStateLock:
			flags = wtsSessionStateUnlok
		case wtsSessionStateUnlok:
			flags = wtsSessionStateLock
		}
	}
	switch flags {
	case wtsSessionStateLock:
		return true, true
	case wtsSessionStateUnlok:
		return false, true
	}
	return false, false
}

// systemSessionToken duplicates our own (SYSTEM) token as a primary token
// and moves it into session sid, so CreateProcessAsUser puts the helper on
// that session's window station where winlogon's desktop is reachable.
func systemSessionToken(sid uint32, note string) (windows.Token, string, error) {
	var self windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_SESSIONID | windows.TOKEN_ADJUST_DEFAULT)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &self); err != nil {
		return 0, "", fmt.Errorf("open process token: %w", err)
	}
	defer self.Close()
	var primary windows.Token
	if err := windows.DuplicateTokenEx(self, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return 0, "", fmt.Errorf("duplicate SYSTEM token: %w", err)
	}
	session := sid
	if err := windows.SetTokenInformation(primary, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), uint32(unsafe.Sizeof(session))); err != nil {
		primary.Close()
		return 0, "", fmt.Errorf("set token session %d: %w", sid, err)
	}
	return primary, note, nil
}

// tokenAccount renders DOMAIN\user for a token, or "unknown user".
func tokenAccount(tok windows.Token) string {
	u, err := tok.GetTokenUser()
	if err != nil || u == nil || u.User.Sid == nil {
		return "unknown user"
	}
	account, domain, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return u.User.Sid.String()
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}

// enablePrivileges turns on the named privileges in our own token. A
// privilege we do not hold at all is logged and skipped: the later API call
// then fails with a precise access-denied error of its own.
func enablePrivileges(names ...string) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		slog.Debug("desktop: open token for privileges", "err", err)
		return
	}
	defer tok.Close()
	for _, name := range names {
		name16, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, name16, &luid); err != nil {
			slog.Debug("desktop: lookup privilege", "name", name, "err", err)
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		if err := windows.AdjustTokenPrivileges(tok, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil); err != nil {
			slog.Debug("desktop: enable privilege", "name", name, "err", err)
		}
	}
}
