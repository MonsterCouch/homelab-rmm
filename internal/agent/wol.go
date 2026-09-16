package agent

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
)

// sendMagicPacket broadcasts a Wake-on-LAN frame for mac on UDP 9, on every
// interface that could carry it (or, when the caller names a destination, on
// the one whose subnet holds it). The server picks an agent on the target's
// subnet to call this, because directed broadcasts rarely cross routers - but
// that agent may itself sit on several subnets.
func sendMagicPacket(mac, broadcast string) error {
	return sendMagicPacketTo(mac, broadcast, "9")
}

// wolRoute is one place to put a magic packet: bind to local so the frame
// leaves the interface that owns the subnet, and send it to dst.
type wolRoute struct {
	local net.IP
	dst   net.IP
}

// wolIface is the part of a net.Interface wolRoutes needs, so the choice of
// wire can be unit-tested without the machine's real NICs.
type wolIface struct {
	up       bool
	loopback bool
	nets     []*net.IPNet
}

// wolRoutes decides where a magic packet goes. want is the destination the
// caller asked for, or nil when it asked for none.
//
// A limited broadcast (255.255.255.255, or no destination at all) is sent on
// every up interface that has an IPv4 subnet, addressed to that subnet's
// broadcast: dialling 255.255.255.255 with no local address lets the routing
// table pick one interface, so on a multi-homed relay every packet leaves the
// default-route NIC and a device on any other VLAN never sees its own.
// A specific destination goes out the interface whose subnet contains it.
// An empty result means no interface matched and the caller should fall back
// to letting the routing table decide.
func wolRoutes(ifaces []wolIface, want net.IP) []wolRoute {
	type candidate struct {
		local  net.IP
		subnet *net.IPNet
	}
	var cands []candidate
	for _, ifi := range ifaces {
		if !ifi.up || ifi.loopback {
			continue
		}
		for _, n := range ifi.nets {
			ip, mask := wol4(n)
			if ip == nil {
				continue
			}
			// /31 and /32 have no broadcast address to aim at.
			if ones, _ := mask.Size(); ones > 30 {
				continue
			}
			cands = append(cands, candidate{local: ip, subnet: &net.IPNet{IP: ip.Mask(mask), Mask: mask}})
		}
	}
	if want != nil && !want.Equal(net.IPv4bcast) {
		for _, c := range cands {
			if c.subnet.Contains(want) {
				return []wolRoute{{local: c.local, dst: want}}
			}
		}
		return nil
	}
	routes := make([]wolRoute, 0, len(cands))
	for _, c := range cands {
		routes = append(routes, wolRoute{local: c.local, dst: wolBroadcastOf(c.subnet)})
	}
	return routes
}

// wol4 reduces an interface address to a 4-byte IPv4 address and mask, or
// nil for anything that is not IPv4: Windows and Linux both hand out IPv6
// addresses here, and either half may be stored in 16-byte form.
func wol4(n *net.IPNet) (net.IP, net.IPMask) {
	if n == nil {
		return nil, nil
	}
	ip := n.IP.To4()
	mask := n.Mask
	if len(mask) == 16 {
		mask = mask[12:]
	}
	if ip == nil || len(mask) != 4 {
		return nil, nil
	}
	return ip, mask
}

// wolBroadcastOf is the subnet's directed broadcast address (192.168.1.0/24
// -> 192.168.1.255).
func wolBroadcastOf(n *net.IPNet) net.IP {
	b := make(net.IP, net.IPv4len)
	for i := range b {
		b[i] = n.IP[i] | ^n.Mask[i]
	}
	return b
}

// localWolIfaces snapshots this machine's interfaces in the form wolRoutes
// consumes.
func localWolIfaces() []wolIface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]wolIface, 0, len(ifs))
	for _, ifi := range ifs {
		w := wolIface{up: ifi.Flags&net.FlagUp != 0, loopback: ifi.Flags&net.FlagLoopback != 0}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				w.nets = append(w.nets, n)
			}
		}
		out = append(out, w)
	}
	return out
}

func sendMagicPacketTo(mac, broadcast, port string) error {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil {
		return err
	}
	if len(hw) != 6 {
		return errors.New("MAC must be 48-bit")
	}
	var buf bytes.Buffer
	buf.Write(bytes.Repeat([]byte{0xff}, 6))
	for i := 0; i < 16; i++ {
		buf.Write(hw)
	}
	var want net.IP
	if b := strings.TrimSpace(broadcast); b != "" {
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(b, port))
		if err != nil {
			return err
		}
		want = addr.IP
	}
	routes := wolRoutes(localWolIfaces(), want)
	if len(routes) == 0 {
		// Nothing to choose between (no usable interface, or a destination
		// that is on none of them): let the routing table decide, which is
		// what this always did.
		dst := want
		if dst == nil {
			dst = net.IPv4bcast
		}
		return sendUDPFrom(nil, dst, port, buf.Bytes())
	}
	var errs []error
	sent := 0
	for _, r := range routes {
		if err := sendUDPFrom(r.local, r.dst, port, buf.Bytes()); err != nil {
			errs = append(errs, fmt.Errorf("%s via %s: %w", r.dst, r.local, err))
			continue
		}
		sent++
	}
	// One wire reaching the target is a success; a relay always has
	// interfaces the sleeping device is not on.
	if sent > 0 {
		return nil
	}
	return errors.Join(errs...)
}

// sendUDPFrom writes payload to dst:port, bound to local when one is given.
func sendUDPFrom(local, dst net.IP, port string, payload []byte) error {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(dst.String(), port))
	if err != nil {
		return err
	}
	var laddr *net.UDPAddr
	if local != nil {
		laddr = &net.UDPAddr{IP: local}
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(payload)
	return err
}
