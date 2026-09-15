package desktop

import (
	"image"
	"math"
	"testing"
)

func TestWheelAccumulator(t *testing.T) {
	var a wheelAccumulator
	if nx, ny := a.add(0, 100); nx != 0 || ny != 1 {
		t.Fatalf("100px: %d,%d", nx, ny)
	}
	if nx, ny := a.add(0, -100); nx != 0 || ny != -1 {
		t.Fatalf("-100px: %d,%d", nx, ny)
	}
	// Chrome on Windows sends 120 per notch: five notches must scroll five
	// times, not six (the old remainder carry fired a bonus notch).
	a.reset()
	for i := 0; i < 5; i++ {
		if _, ny := a.add(0, 120); ny != 1 {
			t.Fatalf("120px notch %d fired %d", i, ny)
		}
	}
	// Firefox line mode scaled to ~57 px: one event is still one notch, and
	// none is swallowed.
	a.reset()
	if _, ny := a.add(0, 57); ny != 1 {
		t.Fatalf("57px fired %d", ny)
	}
	if _, ny := a.add(0, -57); ny != -1 {
		t.Fatalf("-57px fired %d", ny)
	}
	// Trackpad deltas below the window still accumulate.
	a.reset()
	if _, ny := a.add(0, 20); ny != 0 {
		t.Fatalf("20px fired %d", ny)
	}
	for i := 0; i < 3; i++ {
		a.add(0, 20)
	}
	if _, ny := a.add(0, 20); ny != 1 {
		t.Fatalf("5x20px fired %d", ny)
	}
	// A real notch discards a pending trackpad remainder instead of
	// riding on it.
	a.reset()
	a.add(0, 30)
	if _, ny := a.add(0, 100); ny != 1 {
		t.Fatalf("notch after remainder fired %d", ny)
	}
	if _, ny := a.add(0, 80); ny != 1 {
		t.Fatalf("remainder was carried: %d", ny)
	}
	// Above the window (page-mode deltas) the old arithmetic applies.
	a.reset()
	if nx, _ := a.add(250, 0); nx != 2 {
		t.Fatalf("250px horizontal: %d", nx)
	}
	if nx, _ := a.add(50, 0); nx != 1 {
		t.Fatalf("carry: %d", nx)
	}
	// The axes carry independently.
	a.reset()
	a.add(30, 0)
	if nx, ny := a.add(0, 100); nx != 0 || ny != 1 {
		t.Fatalf("cross-axis: %d,%d", nx, ny)
	}
	if nx, _ := a.add(80, 0); nx != 1 {
		t.Fatalf("x remainder lost: %d", nx)
	}
	// Hostile values neither panic nor scroll forever.
	a.reset()
	if nx, ny := a.add(math.NaN(), math.Inf(1)); nx != 0 || ny != 0 {
		t.Fatalf("NaN/Inf: %d,%d", nx, ny)
	}
	if _, ny := a.add(0, 1e9); ny > 20 {
		t.Fatalf("huge delta scrolled %d notches", ny)
	}
}

func TestClampPoint(t *testing.T) {
	b := image.Rect(100, 50, 100+640, 50+480)
	for _, c := range []struct {
		x, y   float64
		wx, wy int
	}{
		{0, 0, 0, 0}, {639, 479, 639, 479}, {640, 480, 639, 479}, {-5, -5, 0, 0},
		{10.4, 10.6, 10, 11}, {math.NaN(), math.Inf(-1), 0, 0}, {1e12, 1e12, 639, 479},
	} {
		x, y := clampPoint(c.x, c.y, b)
		if x != c.wx || y != c.wy {
			t.Errorf("clampPoint(%v,%v) = %d,%d want %d,%d", c.x, c.y, x, y, c.wx, c.wy)
		}
	}
	if x, y := clampPoint(5, 5, image.Rectangle{}); x != 0 || y != 0 {
		t.Errorf("empty bounds: %d,%d", x, y)
	}
}

func TestClampInt(t *testing.T) {
	if clampInt(2.5, 0, 10) != 3 || clampInt(-1, 0, 10) != 0 || clampInt(99, 0, 10) != 10 || clampInt(math.NaN(), 3, 10) != 3 {
		t.Fatal("clampInt")
	}
}
