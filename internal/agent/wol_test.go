package agent

import (
	"net"
	"testing"
)

func cidr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad CIDR %q: %v", s, err)
	}
	// net.Interface.Addrs hands out the interface's own address with the
	// subnet mask, not the masked network address; mirror that.
	return &net.IPNet{IP: ip, Mask: n.Mask}
}

func routeStrings(rs []wolRoute) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.local.String()+"->"+r.dst.String())
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestWolRoutesMultiHomed is the WoL half of F048: a relay with two connected
// NICs used to send every magic packet out whichever one held the default
// route, so a device on the other VLAN never saw its own packet.
func TestWolRoutesMultiHomed(t *testing.T) {
	wifi := wolIface{up: true, nets: []*net.IPNet{cidr(t, "192.168.1.12/24")}}
	eth := wolIface{up: true, nets: []*net.IPNet{cidr(t, "10.20.0.5/16")}}
	lo := wolIface{up: true, loopback: true, nets: []*net.IPNet{cidr(t, "127.0.0.1/8")}}
	down := wolIface{nets: []*net.IPNet{cidr(t, "172.16.3.4/24")}}
	ifaces := []wolIface{lo, wifi, eth, down}

	// No destination asked for: every up, non-loopback interface gets the
	// packet, addressed to its own subnet's broadcast rather than to the
	// limited broadcast on one wire.
	got := routeStrings(wolRoutes(ifaces, nil))
	want := []string{"192.168.1.12->192.168.1.255", "10.20.0.5->10.20.255.255"}
	if !equalStrings(got, want) {
		t.Fatalf("limited broadcast fan-out = %v, want %v", got, want)
	}
	// 255.255.255.255 means the same thing.
	if got := routeStrings(wolRoutes(ifaces, net.IPv4bcast)); !equalStrings(got, want) {
		t.Fatalf("explicit 255.255.255.255 = %v, want %v", got, want)
	}
	// A specific destination leaves on the interface whose subnet holds it,
	// not on the first one in the list.
	got = routeStrings(wolRoutes(ifaces, net.ParseIP("10.20.255.255")))
	if want := []string{"10.20.0.5->10.20.255.255"}; !equalStrings(got, want) {
		t.Fatalf("directed broadcast = %v, want %v", got, want)
	}
	// A destination on none of our subnets is nobody's to claim: the caller
	// falls back to the routing table.
	if got := wolRoutes(ifaces, net.ParseIP("203.0.113.9")); len(got) != 0 {
		t.Fatalf("off-subnet destination = %v, want no route", routeStrings(got))
	}
	// Loopback is never a candidate, so the existing loopback-based magic
	// packet test still goes out through the fallback path.
	if got := wolRoutes([]wolIface{lo}, net.ParseIP("127.0.0.1")); len(got) != 0 {
		t.Fatalf("loopback = %v, want no route", routeStrings(got))
	}
	if got := wolRoutes(nil, nil); len(got) != 0 {
		t.Fatalf("no interfaces = %v, want no route", routeStrings(got))
	}
}

// TestWolRoutesSkipsUnusable pins the address shapes that have no directed
// broadcast to aim at: IPv6, a point-to-point /32 and a /31 link.
func TestWolRoutesSkipsUnusable(t *testing.T) {
	ifaces := []wolIface{{up: true, nets: []*net.IPNet{
		cidr(t, "fe80::1/64"),
		cidr(t, "100.64.0.7/32"),
		cidr(t, "10.9.9.1/31"),
		cidr(t, "192.168.5.20/24"),
	}}}
	got := routeStrings(wolRoutes(ifaces, nil))
	if want := []string{"192.168.5.20->192.168.5.255"}; !equalStrings(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
}

func TestWolBroadcastOf(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"192.168.1.12/24", "192.168.1.255"},
		{"10.20.0.5/16", "10.20.255.255"},
		{"172.16.4.9/22", "172.16.7.255"},
		{"10.0.0.1/8", "10.255.255.255"},
	} {
		n := cidr(t, c.in)
		ip, mask := wol4(n)
		if got := wolBroadcastOf(&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String(); got != c.want {
			t.Errorf("broadcast of %s = %s, want %s", c.in, got, c.want)
		}
	}
}
