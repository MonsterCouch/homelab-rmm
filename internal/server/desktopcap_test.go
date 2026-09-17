package server

import "testing"

// Each desktop session runs its own SYSTEM helper on the device, capturing and
// encoding the screen. Nothing bounded them, so reopening the tab stacked
// helpers up on the managed machine.
func TestDesktopSessionsAreCappedPerAgent(t *testing.T) {
	d := newDesktopCount()
	for i := 1; i <= maxDesktopsPerAgent; i++ {
		if got := d.acquire("a"); got != i {
			t.Fatalf("acquire %d returned %d", i, got)
		}
	}
	if got := d.acquire("a"); got != -1 {
		t.Fatalf("the cap did not hold: acquire returned %d", got)
	}
	// A different device is unaffected.
	if got := d.acquire("b"); got != 1 {
		t.Fatalf("one device's sessions must not limit another, got %d", got)
	}
	// Releasing frees a slot again.
	d.release("a")
	if got := d.acquire("a"); got != maxDesktopsPerAgent {
		t.Fatalf("a released slot was not reusable, got %d", got)
	}
}

// The map must not keep one key per agent ever seen.
func TestDesktopCountForgetsIdleAgents(t *testing.T) {
	d := newDesktopCount()
	d.acquire("a")
	d.release("a")
	d.mu.Lock()
	n := len(d.n)
	d.mu.Unlock()
	if n != 0 {
		t.Fatalf("want an empty map after the last release, got %d keys", n)
	}
}
