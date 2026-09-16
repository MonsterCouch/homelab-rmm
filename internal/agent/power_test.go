package agent

import (
	"strings"
	"testing"
	"unicode/utf16"
)

// TestWinPowerAction pins F043: the server's allow-list
// (internal/server/api_agents.go) and the Linux agent both accept
// poweroff/halt and logout, so the Windows agent must too - otherwise the
// same destructive request powers a Linux device off and comes back as a 502
// from a Windows one.
func TestWinPowerAction(t *testing.T) {
	for in, want := range map[string]string{
		"reboot":     "reboot",
		"shutdown":   "shutdown",
		"poweroff":   "shutdown",
		"halt":       "shutdown",
		"lock":       "lock",
		"logoff":     "logoff",
		"logout":     "logoff",
		"  LogOut  ": "logoff",
		"PowerOff":   "shutdown",
		"":           "",
		"restart":    "",
		"suspend":    "",
	} {
		if got := winPowerAction(in); got != want {
			t.Errorf("winPowerAction(%q) = %q, want %q", in, got, want)
		}
	}
	// The canonical names are exactly the ones winShutdownArgs understands,
	// so an alias never picks the wrong shutdown.exe flag.
	if got := winShutdownArgs(winPowerAction("poweroff"), 0, ""); got[0] != "/s" {
		t.Errorf("poweroff must shut down, not reboot: %v", got)
	}
	if got := winShutdownArgs(winPowerAction("halt"), 0, ""); got[0] != "/s" {
		t.Errorf("halt must shut down, not reboot: %v", got)
	}
	if got := winShutdownArgs(winPowerAction("reboot"), 0, ""); got[0] != "/r" {
		t.Errorf("reboot args = %v", got)
	}
}

// TestWinClampPowerDelay covers F044's delay handling: the Windows logoff now
// waits the requested grace period out, and the clamp keeps a silly value
// from parking the timer years away or wrapping negative.
func TestWinClampPowerDelay(t *testing.T) {
	for in, want := range map[int]int{
		0:                    0,
		-1:                   0,
		-1 << 40:             0,
		300:                  300,
		winMaxPowerDelay:     winMaxPowerDelay,
		winMaxPowerDelay + 1: winMaxPowerDelay,
		1 << 40:              winMaxPowerDelay,
	} {
		if got := winClampPowerDelay(in); got != want {
			t.Errorf("winClampPowerDelay(%d) = %d, want %d", in, got, want)
		}
	}
}

// TestWinCleanMessageUTF16Cap is F052: shutdown.exe counts its /c comment in
// UTF-16 code units, so a cap applied per rune let an emoji-heavy message
// reach twice the documented maximum and be rejected.
func TestWinCleanMessageUTF16Cap(t *testing.T) {
	units := func(s string) int { return len(utf16.Encode([]rune(s))) }

	// Every astral-plane rune costs two units, so 512 of them must come back
	// as 256, not 512.
	emoji := strings.Repeat("\U0001F600", 512)
	got := winCleanMessage(emoji, 512)
	if n := units(got); n != 512 {
		t.Errorf("emoji message = %d UTF-16 units, want 512", n)
	}
	if r := []rune(got); len(r) != 256 {
		t.Errorf("emoji message = %d runes, want 256", len(r))
	}
	// A surrogate pair is never split in half.
	if strings.ContainsRune(got, '�') {
		t.Error("truncation broke a surrogate pair")
	}
	// BMP text is unaffected: one rune, one unit.
	if n := units(winCleanMessage(strings.Repeat("é", 600), 512)); n != 512 {
		t.Errorf("accented message = %d units, want 512", n)
	}
	// Short messages still pass through whole, and cleaning still happens.
	if got := winCleanMessage("line1\r\nline2\ttab", 512); got != "line1 line2 tab" {
		t.Errorf("clean = %q", got)
	}
	// A mixed message is cut on a rune boundary that keeps it within the cap.
	mixed := "ok \U0001F600\U0001F600"
	if got, want := winCleanMessage(mixed, 5), "ok \U0001F600"; got != want {
		t.Errorf("mixed = %q, want %q", got, want)
	}
	// And winShutdownArgs, the only caller, stays inside shutdown.exe's 512.
	args := winShutdownArgs("reboot", 60, emoji)
	if n := units(args[len(args)-1]); n > 512 {
		t.Errorf("/c comment = %d UTF-16 units, over shutdown.exe's 512", n)
	}
}
