package desktop

import (
	"errors"
	"image"
	"testing"
	"time"
)

func TestNodeForMonitorMatchesMonitors(t *testing.T) {
	streams := []pwStream{
		{Node: 42, Bounds: image.Rect(0, 0, 1920, 1080)},
		{Node: 43}, // reports no size: not a monitor
		{Node: 44, Bounds: image.Rect(1920, 0, 3200, 1024)},
	}
	mons := monitorsFromStreams(streams)
	if len(mons) != 2 {
		t.Fatalf("monitors = %+v", mons)
	}
	want := map[int]uint32{0: 42, 1: 44}
	for _, m := range mons {
		node, ok := nodeForMonitor(streams, m.Index)
		if !ok || node != want[m.Index] {
			t.Fatalf("monitor %d -> node %d ok=%v, want %d", m.Index, node, ok, want[m.Index])
		}
	}
	if _, ok := nodeForMonitor(streams, 2); ok {
		t.Fatal("a monitor index past the end mapped to a node")
	}
	if _, ok := nodeForMonitor(streams, -1); ok {
		t.Fatal("a negative monitor index mapped to a node")
	}
}

func TestPortalEnabled(t *testing.T) {
	for env, want := range map[string]bool{"": true, "1": true, "0": false, " 0 ": false, "yes": true} {
		if got := portalEnabled(env); got != want {
			t.Errorf("portalEnabled(%q) = %v, want %v", env, got, want)
		}
	}
}

func TestChooseWaylandBackend(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name     string
		on       bool
		err      error
		display  string
		want     waylandBackend
		wantFail bool
	}{
		{"portal works", true, nil, ":0", backendPortal, false},
		{"portal works without display", true, nil, "", backendPortal, false},
		{"portal failed, display present", true, boom, ":0", backendScreenshot, false},
		{"portal failed, no display", true, boom, "", backendNone, true},
		{"kill switch, display present", false, nil, ":0", backendScreenshot, false},
		{"kill switch, no display", false, nil, "", backendNone, true},
	}
	for _, c := range cases {
		got, err := chooseWaylandBackend(c.on, c.err, c.display)
		if got != c.want || (err != nil) != c.wantFail {
			t.Errorf("%s: got %v, %v", c.name, got, err)
		}
	}
}

func TestWithFrameSizeFollowsTheStream(t *testing.T) {
	mons := []monitor{
		{Index: 0, Bounds: image.Rect(0, 0, 1280, 720), Primary: true},
		{Index: 1, Bounds: image.Rect(1280, 0, 2560, 720)},
	}
	got, changed := withFrameSize(mons, 0, 2560, 1440)
	if !changed || got[0].Bounds != image.Rect(0, 0, 2560, 1440) || !got[0].Primary {
		t.Fatalf("resized = %+v, changed %v", got, changed)
	}
	if mons[0].Bounds != image.Rect(0, 0, 1280, 720) {
		t.Fatal("the input slice was modified")
	}
	if got[1] != mons[1] {
		t.Fatal("another monitor changed")
	}
	if same, changed := withFrameSize(mons, 1, 1280, 720); changed || len(same) != 2 {
		t.Fatal("an equal size must not count as a change")
	}
	if _, changed := withFrameSize(mons, 7, 10, 10); changed {
		t.Fatal("an unknown monitor must not change anything")
	}
	if _, changed := withFrameSize(mons, 0, 0, 10); changed {
		t.Fatal("an empty frame must not change anything")
	}
}

func TestFallBackWanted(t *testing.T) {
	if fallBackWanted(nil) {
		t.Fatal("nil error")
	}
	if fallBackWanted(errCapturerClosed) {
		t.Fatal("an orderly Close is not a failure")
	}
	if fallBackWanted(noFrameYet(2 * time.Second)) {
		t.Fatal("an idle screen is not a failure")
	}
	if !fallBackWanted(errors.New("PipeWire stream ended")) {
		t.Fatal("a stream error must fall back")
	}
}

func TestWithFrameSize(t *testing.T) {
	mons := []monitor{
		{Index: 0, Bounds: image.Rect(0, 0, 960, 540), Primary: true},
		{Index: 1, Bounds: image.Rect(960, 0, 1920, 540)},
	}
	if out, changed := withFrameSize(mons, 0, 960, 540); changed || len(out) != 2 {
		t.Fatalf("same size: changed=%v", changed)
	}
	out, changed := withFrameSize(mons, 0, 1920, 1080)
	if !changed || out[0].Bounds != image.Rect(0, 0, 1920, 1080) || !out[0].Primary {
		t.Fatalf("HiDPI frame: changed=%v out=%+v", changed, out)
	}
	if mons[0].Bounds != image.Rect(0, 0, 960, 540) {
		t.Fatal("withFrameSize modified its input")
	}
	if out[1] != mons[1] {
		t.Fatalf("the other monitor changed: %+v", out[1])
	}
	for _, bad := range [][3]int{{0, 0, 10}, {0, 10, 0}, {5, 100, 100}} {
		if _, changed := withFrameSize(mons, bad[0], bad[1], bad[2]); changed && bad[0] == 5 {
			t.Fatalf("unknown monitor index changed something")
		} else if changed && bad[0] == 0 {
			t.Fatalf("empty frame size %v changed bounds", bad)
		}
	}
}

func TestStreamStale(t *testing.T) {
	now := time.Now()
	old := now.Add(-3 * time.Minute)
	recent := now.Add(-5 * time.Second)
	cases := []struct {
		name    string
		running bool
		last    time.Time
		want    bool
	}{
		{"running and silent for minutes", true, old, true},
		{"running with a recent frame", true, recent, false},
		{"paused stream is never stale", false, old, false},
		{"no frame yet is the first-frame wait's business", true, time.Time{}, false},
	}
	for _, c := range cases {
		if got := streamStale(c.running, c.last, now, staleFrameLimit); got != c.want {
			t.Errorf("%s: streamStale = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNextRetryDelay(t *testing.T) {
	d := time.Duration(0)
	var seen []time.Duration
	for i := 0; i < 8; i++ {
		d = nextRetryDelay(d)
		seen = append(seen, d)
	}
	if seen[0] != retryInitialDelay || seen[1] != 2*retryInitialDelay {
		t.Fatalf("delays start %v", seen)
	}
	if seen[len(seen)-1] != retryMaxDelay {
		t.Fatalf("delay did not settle at %v: %v", retryMaxDelay, seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] < seen[i-1] || seen[i] > retryMaxDelay {
			t.Fatalf("delays are not non-decreasing and capped: %v", seen)
		}
	}
	if !fallBackWanted(errStreamStalled) || !fallBackWanted(errPortalSessionClosed) {
		t.Fatal("a stalled stream or a closed session must trigger the fallback")
	}
}
