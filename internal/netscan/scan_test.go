package netscan

import (
	"context"
	"testing"
)

func TestGenerateSubnetIPs(t *testing.T) {
	// Valid /30 has 4 IPs: network, 2 hosts, broadcast -> 2 usable hosts
	ips, err := GenerateSubnetIPs("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 usable hosts for /30, got %d", len(ips))
	}
	if ips[0] != "192.168.1.1" || ips[1] != "192.168.1.2" {
		t.Errorf("unexpected IPs: %v", ips)
	}

	// Range larger than /22 should fail
	_, err = GenerateSubnetIPs("10.0.0.0/21")
	if err == nil {
		t.Error("expected error for /21 subnet (> 1024 hosts), got nil")
	}

	// Public IP should fail
	_, err = GenerateSubnetIPs("8.8.8.0/24")
	if err == nil {
		t.Error("expected error for public IP subnet, got nil")
	}

	// Link-local range should fail
	_, err = GenerateSubnetIPs("169.254.0.0/16")
	if err == nil {
		t.Error("expected error for link-local subnet, got nil")
	}

	// Invalid CIDR should fail
	_, err = GenerateSubnetIPs("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR, got nil")
	}
}

func TestSNMPOIDEncoding(t *testing.T) {
	oidBytes, err := encodeOID("1.3.6.1.2.1.1.1.0")
	if err != nil {
		t.Fatalf("encodeOID failed: %v", err)
	}
	if len(oidBytes) == 0 {
		t.Fatal("expected non-empty bytes for encoded OID")
	}
	// First byte should be 1*40 + 3 = 43 (0x2B)
	if oidBytes[0] != 43 {
		t.Errorf("expected first byte 43, got %d", oidBytes[0])
	}

	// Invalid OID
	_, err = encodeOID("1")
	if err == nil {
		t.Error("expected error for single element OID, got nil")
	}
}

func TestScanSubnetContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	res, err := ScanSubnet(ctx, "192.168.100.0/24", 8)
	if err != nil {
		t.Fatalf("ScanSubnet failed: %v", err)
	}
	if len(res) > 0 {
		t.Errorf("expected 0 results with cancelled context, got %d", len(res))
	}
}

func TestBuildSNMPPacket(t *testing.T) {
	pkt, err := buildSNMPv2GetRequest("public", 12345, []string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		t.Fatalf("buildSNMPv2GetRequest failed: %v", err)
	}
	if len(pkt) < 20 {
		t.Errorf("SNMP packet too short: %d bytes", len(pkt))
	}
	// Verify ASN.1 sequence start (0x30)
	if pkt[0] != 0x30 {
		t.Errorf("expected sequence byte 0x30, got 0x%02X", pkt[0])
	}
}

func TestParseSNMPStrings(t *testing.T) {
	// Build a mock SNMP response packet with nested containers:
	// SEQUENCE (0x30)
	//   GET-RESPONSE PDU (0xA2)
	//     SEQUENCE (VarBindList: 0x30)
	//       SEQUENCE (VarBind: 0x30)
	//         OCTET STRING (0x04): "Cisco IOS Switch"
	//         TimeTicks (0x43): 1234500 (12345 seconds in hundredths)
	octetStr := []byte("Cisco IOS Switch")
	strTLV := append([]byte{0x04, byte(len(octetStr))}, octetStr...)
	// TimeTicks: 1234500 = 0x0012D644
	ticksTLV := []byte{0x43, 0x04, 0x00, 0x12, 0xD6, 0x44}

	varBindPayload := append(strTLV, ticksTLV...)
	varBind := append([]byte{0x30, byte(len(varBindPayload))}, varBindPayload...)

	varBindList := append([]byte{0x30, byte(len(varBind))}, varBind...)

	pdu := append([]byte{0xA2, byte(len(varBindList))}, varBindList...)

	outerSeq := append([]byte{0x30, byte(len(pdu))}, pdu...)

	strs, uptime := ParseSNMPStrings(outerSeq)
	if len(strs) != 1 || strs[0] != "Cisco IOS Switch" {
		t.Fatalf("expected ['Cisco IOS Switch'], got %v", strs)
	}
	if uptime != 12345 {
		t.Fatalf("expected uptime 12345, got %d", uptime)
	}

	// Malformed payloads should not panic
	malformedCases := [][]byte{
		{},
		{0x30},
		{0x30, 0xFF, 0x01},
		{0x30, 0x82, 0xFF, 0xFF},
		{0xA2, 0x05, 0x04, 0x10, 0x41}, // length claims 16 bytes, but only 1 byte given
	}
	for i, mc := range malformedCases {
		_, _ = ParseSNMPStrings(mc) // ensure no panic
		_ = i
	}
}

