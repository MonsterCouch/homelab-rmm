package agent

import (
	"bytes"
	"errors"
	"net"
	"strings"
)

// sendMagicPacket broadcasts a Wake-on-LAN frame for mac on UDP 9. The server
// picks an agent on the target's subnet to call this, because directed
// broadcasts rarely cross routers.
func sendMagicPacket(mac, broadcast string) error {
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
	if broadcast == "" {
		broadcast = "255.255.255.255"
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(broadcast, "9"))
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(buf.Bytes())
	return err
}
