//go:build windows

package netscan

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var (
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP = modiphlpapi.NewProc("SendARP")
)

func resolveMAC(ipStr string) string {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return ""
	}
	dstIP := binary.LittleEndian.Uint32(ip)
	var mac [6]byte
	macLen := uint32(len(mac))
	ret, _, _ := procSendARP.Call(
		uintptr(dstIP),
		0,
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if ret == 0 && macLen == 6 {
		return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}
	return ""
}
