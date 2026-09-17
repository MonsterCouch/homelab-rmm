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

// Entry points x/sys does not wrap, or wraps in a way that loses what we
// need: WTSQuerySessionInformation(WTSSessionInfoEx) has no wrapper at all,
// and windows.AdjustTokenPrivileges only reports a FALSE return, dropping
// the ERROR_NOT_ALL_ASSIGNED that comes back with TRUE.
var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	advapi32                        = windows.NewLazySystemDLL("advapi32.dll")
	procAdjustTokenPrivileges       = advapi32.NewProc("AdjustTokenPrivileges")
)

const (
	wtsSessionInfoEx = 25 // WTS_INFO_CLASS.WTSSessionInfoEx

	// WTSINFOEXW is {DWORD Level; WTSINFOEX_LEVEL_W Data}. Data holds
	// LARGE_INTEGERs, so MSVC aligns it to 8 on x86 and x64 alike, which
	// puts SessionFlags (the third DWORD of Data) at byte 16.
	wtsInfoExFlagsOffset = 16
	wtsSessionStateLock  = 0 // WTS_SESSIONSTATE_LOCK
	wtsSessionStateUnlok = 1 // WTS_SESSIONSTATE_UNLOCK

	// TOKEN_ELEVATION_TYPE (winnt.h). x/sys names the info class but not
	// the values.
	tokenElevationTypeDefault = 1 // UAC off, or a standard user: one token only
	tokenElevationTypeFull    = 2 // already the elevated half of a split token
	tokenElevationTypeLimited = 3 // the filtered half: an elevated twin exists
)

// launch is the Windows service path: the agent lives in session 0, which
// has no desktop of its own, so the helper is created inside the console
// session with a token that can see everything on it.
func launch(exe, serverURL, token, fingerprint string, quality int) (string, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		slog.Debug("desktop: cannot tell whether this is a service; assuming interactive", "err", err)
	}
	// IsWindowsService answers "is my parent services.exe in session 0", which
	// is not the same question. An agent started by the Task Scheduler, by a
	// service wrapper such as NSSM or WinSW, or by PsExec -s is SYSTEM in
	// session 0 with a parent of svchost.exe, so it reported false and took
	// the in-process path - inside a session that has no desktop, where the
	// capture can only fail. What decides this is the session we are actually
	// in, so ask that; IsWindowsService stays as a hint for the normal case.
	if !isService && !inSessionZero() {
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
	// The one-time bridge token travels in the environment block, never on
	// the command line: any local user can read another process's command
	// line (Process Explorer, WMI Win32_Process), while the environment
	// block needs PROCESS_VM_READ, i.e. already-equal rights.
	block, blockErr := envBlockWithToken(env, token)
	windows.DestroyEnvironmentBlock(env)
	if blockErr != nil {
		return "", blockErr
	}

	exe16, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return "", fmt.Errorf("executable path: %w", err)
	}
	cmd16, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{exe}, helperArgs(serverURL, fingerprint, quality)...)))
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
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, &block[0], dir16, &si, &pi)
	if err != nil {
		return "", fmt.Errorf("CreateProcessAsUser in session %d: %w", sid, err)
	}
	windows.CloseHandle(pi.Thread)
	slog.Info("desktop helper started", "pid", pi.ProcessId, "session", sid, "note", note)
	go reapHelper(pi.Process, pi.ProcessId)
	return note, nil
}

// maxEnvBlock bounds the copy of the user's environment block (UTF-16 code
// units). A real block is a few thousand; anything near this is a corrupt
// pointer, and walking it forever would hang the agent.
const maxEnvBlock = 1 << 20

// envBlockWithToken copies the environment block CreateEnvironmentBlock
// produced and appends the bridge token, returning the
// double-NUL-terminated form CreateProcessAsUser wants. Any inherited
// variable of the same name is dropped so the value the helper reads is
// always ours.
func envBlockWithToken(env *uint16, token string) ([]uint16, error) {
	entries, err := envBlockStrings(env)
	if err != nil {
		return nil, err
	}
	out := make([]uint16, 0, 4096)
	for _, e := range envWithToken(entries, token) {
		u, err := windows.UTF16FromString(e)
		if err != nil {
			continue // an embedded NUL cannot survive the block format; skip it
		}
		out = append(out, u...) // UTF16FromString keeps the terminating NUL
	}
	return append(out, 0), nil // the block's own terminator
}

// envBlockStrings walks a double-NUL-terminated UTF-16 environment block.
func envBlockStrings(env *uint16) ([]string, error) {
	if env == nil {
		return nil, nil
	}
	var (
		out   []string
		total int
		p     = unsafe.Pointer(env)
	)
	for {
		n := 0
		for *(*uint16)(unsafe.Add(p, 2*n)) != 0 {
			n++
			if total+n > maxEnvBlock {
				return nil, errors.New("environment block is implausibly large")
			}
		}
		if n == 0 {
			return out, nil // the empty string that ends the block
		}
		out = append(out, windows.UTF16ToString(unsafe.Slice((*uint16)(p), n)))
		total += n + 1
		p = unsafe.Add(p, 2*(n+1))
	}
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
// The helper runs on OUR OWN (LocalSystem) token, re-homed into the console
// session, whenever we can make one. That is a deliberate choice over the
// logged-on user's token:
//
//   - The Winlogon desktop — the secure desktop behind every UAC prompt, the
//     lock screen and Ctrl+Alt+Del — has a DACL that grants access to
//     LocalSystem alone. A helper on a user token cannot OpenInputDesktop it,
//     so it would keep capturing the stale Default desktop: the operator sees
//     a frozen screen exactly when a UAC prompt needs answering, and cannot
//     unlock the machine at all.
//   - WTSQueryUserToken hands back the UAC-*filtered* token of an
//     administrator (medium integrity). UIPI then blocks SendInput into any
//     elevated window, so clicks silently do nothing in an admin console,
//     Task Manager or an elevated PowerShell.
//   - SendSAS is a no-op unless the caller is LocalSystem or the interactive
//     user with the SoftwareSASGeneration policy set; as SYSTEM it works with
//     AsUser=FALSE, which is what the injector passes.
//
// The user's token is still the fallback for an agent that is not
// LocalSystem (a service installed under a domain account): there the
// SYSTEM path cannot work, and a helper that sees the user's own desktop is
// far better than none. On that path the filtered token is swapped for its
// linked, elevated twin so at least UIPI and SendSAS behave.
func sessionToken(sid uint32) (windows.Token, string, error) {
	var userTok windows.Token
	userErr := windows.WTSQueryUserToken(sid, &userTok)
	if userErr == nil {
		defer userTok.Close()
	} else {
		slog.Info("desktop: no user token for the console session", "session", sid, "err", userErr)
	}

	sysTok, sysErr := systemSessionToken(sid)
	if sysErr == nil {
		return sysTok, systemNote(sid, userTok, userErr), nil
	}
	if userErr != nil {
		return 0, "", fmt.Errorf("console session %d has no user token (%v) and the SYSTEM token cannot be moved into it: %w", sid, userErr, sysErr)
	}
	slog.Warn("desktop: cannot run the helper as SYSTEM; falling back to the console user's token",
		"session", sid, "err", sysErr)

	primary, elevated, err := primaryUserToken(userTok)
	if err != nil {
		return 0, "", err
	}
	note := fmt.Sprintf("attached to console session %d of %s; the agent is not LocalSystem, so UAC prompts and the lock screen stay invisible", sid, tokenAccount(primary))
	if !elevated {
		slog.Info("desktop: helper runs on the user's own token", "session", sid)
	}
	return primary, note, nil
}

// systemNote says whose desktop the SYSTEM helper will end up showing.
func systemNote(sid uint32, userTok windows.Token, userErr error) string {
	if userErr != nil {
		return "no user is logged in; showing the logon screen (as SYSTEM)"
	}
	who := tokenAccount(userTok)
	if locked, known := sessionLocked(sid); known && locked {
		return fmt.Sprintf("console session %d of %s is locked; running as SYSTEM so the lock screen can be captured and unlocked", sid, who)
	}
	return fmt.Sprintf("attached to console session %d of %s (as SYSTEM, so UAC prompts and the lock screen stay visible)", sid, who)
}

// primaryUserToken turns the console session's user token into a primary
// token for CreateProcessAsUser. When the account is a UAC-split
// administrator, WTSQueryUserToken returns the filtered half; its linked
// (elevated) twin is used instead so the helper runs at high integrity and
// UIPI stops swallowing input into elevated windows. elevated reports
// whether the swap happened.
func primaryUserToken(userTok windows.Token) (tok windows.Token, elevated bool, err error) {
	src := userTok
	if linked, lerr := linkedElevatedToken(userTok); lerr == nil {
		defer linked.Close()
		src, elevated = linked, true
	} else {
		slog.Debug("desktop: no linked elevated token for the console user", "err", lerr)
	}
	var primary windows.Token
	if err := windows.DuplicateTokenEx(src, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return 0, false, fmt.Errorf("duplicate user token: %w", err)
	}
	return primary, elevated, nil
}

// linkedElevatedToken returns the elevated twin of a UAC-filtered token.
// Anything else (UAC off, a standard user, an already-elevated token) is
// reported as an error, because there is nothing to swap in.
func linkedElevatedToken(tok windows.Token) (windows.Token, error) {
	var (
		typ uint32
		n   uint32
	)
	if err := windows.GetTokenInformation(tok, windows.TokenElevationType, (*byte)(unsafe.Pointer(&typ)), uint32(unsafe.Sizeof(typ)), &n); err != nil {
		return 0, fmt.Errorf("query elevation type: %w", err)
	}
	switch typ {
	case tokenElevationTypeLimited:
	case tokenElevationTypeFull, tokenElevationTypeDefault:
		return 0, fmt.Errorf("token elevation type %d has no linked token", typ)
	default:
		return 0, fmt.Errorf("unknown token elevation type %d", typ)
	}
	linked, err := tok.GetLinkedToken()
	if err != nil {
		return 0, fmt.Errorf("linked token: %w", err)
	}
	return linked, nil
}

// sessionLocked asks the session manager whether sid sits at the lock
// screen. known is false when the OS cannot say (the query failed, or it
// answered WTS_SESSIONSTATE_UNKNOWN).
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
// that session's window station where winlogon's desktop is reachable. It
// fails when the agent is not LocalSystem: TOKEN_ADJUST_SESSIONID needs
// SeTcbPrivilege, which only SYSTEM holds.
func systemSessionToken(sid uint32) (windows.Token, error) {
	var self windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_SESSIONID | windows.TOKEN_ADJUST_DEFAULT)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &self); err != nil {
		return 0, fmt.Errorf("open process token: %w", err)
	}
	defer self.Close()
	var primary windows.Token
	if err := windows.DuplicateTokenEx(self, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return 0, fmt.Errorf("duplicate SYSTEM token: %w", err)
	}
	session := sid
	if err := windows.SetTokenInformation(primary, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), uint32(unsafe.Sizeof(session))); err != nil {
		primary.Close()
		return 0, fmt.Errorf("set token session %d: %w", sid, err)
	}
	return primary, nil
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

// enablePrivileges turns on the named privileges in our own token.
// AdjustTokenPrivileges is called through a LazyProc rather than the x/sys
// wrapper on purpose: the API returns TRUE *and* sets
// ERROR_NOT_ALL_ASSIGNED when a privilege is missing from the token, and
// the wrapper only looks at the return value, so a silently unprivileged
// service would be indistinguishable from a working one. Each failure is a
// warning naming the privilege, because the API call it was meant to enable
// (CreateProcessAsUser, TokenSessionId) will fail later with nothing but
// access denied to explain it.
func enablePrivileges(names ...string) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		slog.Warn("desktop: cannot open our own token to enable privileges", "err", err)
		return
	}
	defer tok.Close()
	if err := procAdjustTokenPrivileges.Find(); err != nil {
		slog.Warn("desktop: AdjustTokenPrivileges is unavailable", "err", err)
		return
	}
	for _, name := range names {
		name16, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, name16, &luid); err != nil {
			slog.Warn("desktop: privilege is unknown to this system", "name", name, "err", err)
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		r, _, err := procAdjustTokenPrivileges.Call(uintptr(tok), 0,
			uintptr(unsafe.Pointer(&tp)), unsafe.Sizeof(tp), 0, 0)
		switch {
		case r == 0:
			slog.Warn("desktop: cannot enable privilege", "name", name, "err", err)
		case errors.Is(err, windows.ERROR_NOT_ALL_ASSIGNED):
			// TRUE with this last error means "nothing was changed": the
			// account does not hold the privilege at all.
			slog.Warn("desktop: privilege not held by this account; the helper may not reach the console session",
				"name", name)
		}
	}
}

// inSessionZero reports whether this process lives in session 0, which has no
// desktop to capture whatever started the process. Session 0 is the only
// reliable signal: how the agent was launched varies, where it ended up does
// not.
func inSessionZero() bool {
	var sess uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sess); err != nil {
		slog.Debug("desktop: cannot read our own session id", "err", err)
		return false
	}
	return sess == 0
}
