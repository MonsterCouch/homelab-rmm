package netscan

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type SNMPResult struct {
	SysDescr  string `json:"sys_descr"`
	SysName   string `json:"sys_name"`
	SysUpTime int64  `json:"sys_uptime"`
}

// encodeOID converts dotted decimal OID string to ASN.1 BER bytes.
func encodeOID(oidStr string) ([]byte, error) {
	parts := strings.Split(strings.Trim(oidStr, "."), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID: %s", oidStr)
	}

	first, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}
	second, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}

	out := []byte{byte(first*40 + second)}

	for _, p := range parts[2:] {
		val, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, err
		}
		if val < 128 {
			out = append(out, byte(val))
		} else {
			var sub []byte
			for val > 0 {
				sub = append([]byte{byte(val & 0x7F)}, sub...)
				val >>= 7
			}
			for i := 0; i < len(sub)-1; i++ {
				sub[i] |= 0x80
			}
			out = append(out, sub...)
		}
	}
	return out, nil
}

// buildSNMPv2GetRequest creates an SNMPv2c GetRequest packet for given OIDs with community.
func buildSNMPv2GetRequest(community string, reqID int32, oids []string) ([]byte, error) {
	var varbinds []byte
	for _, oidStr := range oids {
		oidBytes, err := encodeOID(oidStr)
		if err != nil {
			continue
		}
		// VarBind: SEQUENCE { OID, NULL }
		vbSeq := []byte{0x06, byte(len(oidBytes))}
		vbSeq = append(vbSeq, oidBytes...)
		vbSeq = append(vbSeq, 0x05, 0x00) // NULL

		varbinds = append(varbinds, 0x30, byte(len(vbSeq)))
		varbinds = append(varbinds, vbSeq...)
	}

	// VarBindList: SEQUENCE OF VarBind
	var vbList []byte
	vbList = append(vbList, 0x30, byte(len(varbinds)))
	vbList = append(vbList, varbinds...)

	// PDU: GetRequest [0]
	// RequestID (INTEGER), ErrorStatus (INTEGER 0), ErrorIndex (INTEGER 0), VarBindList
	reqIDBytes := []byte{0x02, 0x04, byte(reqID >> 24), byte(reqID >> 16), byte(reqID >> 8), byte(reqID)}
	errStatus := []byte{0x02, 0x01, 0x00}
	errIndex := []byte{0x02, 0x01, 0x00}

	pduPayload := append(reqIDBytes, errStatus...)
	pduPayload = append(pduPayload, errIndex...)
	pduPayload = append(pduPayload, vbList...)

	var pdu []byte
	pdu = append(pdu, 0xA0, byte(len(pduPayload)))
	pdu = append(pdu, pduPayload...)

	// Message: SEQUENCE { version (INTEGER 1 for v2c), community (OCTET STRING), PDU }
	commBytes := []byte(community)
	commPayload := []byte{0x04, byte(len(commBytes))}
	commPayload = append(commPayload, commBytes...)

	versionBytes := []byte{0x02, 0x01, 0x01} // SNMP v2c = 1

	msgPayload := append(versionBytes, commPayload...)
	msgPayload = append(msgPayload, pdu...)

	var msg []byte
	msg = append(msg, 0x30, byte(len(msgPayload)))
	msg = append(msg, msgPayload...)

	return msg, nil
}

// ParseSNMPStrings searches response for printable strings and uptime integers.
func ParseSNMPStrings(data []byte) (stringsFound []string, uptime int64) {
	var parseTLV func(d []byte, depth int)
	parseTLV = func(d []byte, depth int) {
		if depth > 32 {
			return
		}
		i := 0
		for i < len(d) {
			tag := d[i]
			i++
			if i >= len(d) {
				break
			}
			length := int(d[i])
			i++
			if length&0x80 != 0 {
				numOctets := length & 0x7F
				if numOctets == 0 || numOctets > 4 || i+numOctets > len(d) {
					break
				}
				length = 0
				for j := 0; j < numOctets; j++ {
					length = (length << 8) | int(d[i])
					i++
				}
			}
			if length < 0 || i+length > len(d) {
				break
			}
			val := d[i : i+length]

			// Descend into constructed ASN.1 containers (SEQUENCE 0x30, 0x20, context PDUs 0xA0-0xA5)
			if tag == 0x30 || tag == 0x20 || (tag >= 0xA0 && tag <= 0xA5) {
				parseTLV(val, depth+1)
				i += length
				continue
			}
			i += length

			// OCTET STRING (tag 0x04)
			if tag == 0x04 && length > 0 {
				printable := true
				for _, b := range val {
					if b < 32 || b > 126 {
						printable = false
						break
					}
				}
				if printable {
					str := string(val)
					if len(str) > 1 && !strings.Contains(str, "public") {
						stringsFound = append(stringsFound, str)
					}
				}
			}
			// TimeTicks (tag 0x43 in Application class)
			if tag == 0x43 && length <= 8 {
				var ut uint64
				for _, b := range val {
					ut = (ut << 8) | uint64(b)
				}
				uptime = int64(ut / 100) // Convert hundredths of a second to seconds
			}
		}
	}
	parseTLV(data, 0)
	return stringsFound, uptime
}

// QuerySNMP probes a host via SNMPv2c on port 161.
func QuerySNMP(targetIP, community string, timeout time.Duration) (*SNMPResult, error) {
	if community == "" {
		community = "public"
	}
	addr := net.JoinHostPort(targetIP, "161")
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// OIDs: sysDescr (1.3.6.1.2.1.1.1.0), sysUpTime (1.3.6.1.2.1.1.3.0), sysName (1.3.6.1.2.1.1.5.0)
	oids := []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"}
	reqID := int32(time.Now().UnixNano() & 0x7FFFFFFF)
	reqPacket, err := buildSNMPv2GetRequest(community, reqID, oids)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(reqPacket); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	strs, uptime := ParseSNMPStrings(buf[:n])
	res := &SNMPResult{
		SysUpTime: uptime,
	}
	if len(strs) > 0 {
		res.SysDescr = strs[0]
	}
	if len(strs) > 1 {
		res.SysName = strs[1]
	} else if res.SysDescr != "" {
		res.SysName = res.SysDescr
	}
	return res, nil
}
