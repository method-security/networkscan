// Package plugins provides SNMP service fingerprinting
package plugins

import (
	"context"
	"encoding/asn1"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type SNMPFingerprinter struct{}

func (SNMPFingerprinter) Name() string { return "snmp" }

func (SNMPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// Create UDP connection
	conn, err := net.DialTimeout("udp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return nil, err
	}

	// Build SNMP v1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)
	// This is a basic SNMP probe
	snmpRequest := buildSNMPGetRequest("public", "1.3.6.1.2.1.1.1.0")

	// Send the request
	if _, err := conn.Write(snmpRequest); err != nil {
		return nil, err
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}

	// Check if we got a valid SNMP response
	if n < 10 {
		return nil, fmt.Errorf("response too short: %d bytes", n)
	}

	// Verify it starts with SEQUENCE tag (0x30)
	if buffer[0] != 0x30 {
		return nil, fmt.Errorf("invalid SNMP response: expected SEQUENCE tag, got 0x%02x", buffer[0])
	}

	// Parse basic SNMP response structure
	// We use RawValue for Community because SNMP servers may return different ASN.1 types
	var snmpMsg struct {
		Version   int
		Community asn1.RawValue
		PDU       asn1.RawValue
	}

	_, err = asn1.Unmarshal(buffer[:n], &snmpMsg)
	if err != nil {
		return nil, fmt.Errorf("asn1 unmarshal error (got %d bytes): %w", n, err)
	}

	// Extract community string from RawValue
	var community string
	if snmpMsg.Community.Tag == 4 { // OCTET STRING
		community = string(snmpMsg.Community.Bytes)
	} else if snmpMsg.Community.Tag == 19 { // PrintableString
		community = string(snmpMsg.Community.Bytes)
	}

	// SNMP service detected
	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSnmp,
		Metadata:  make(map[string]string),
	}

	// Map SNMP version
	var versionStr string
	switch snmpMsg.Version {
	case 0:
		versionStr = "SNMPv1"
	case 1:
		versionStr = "SNMPv2c"
	case 3:
		versionStr = "SNMPv3"
	default:
		versionStr = fmt.Sprintf("SNMP (version %d)", snmpMsg.Version)
	}

	result.Version = &versionStr
	result.Metadata["snmp_version"] = versionStr
	result.Metadata["community"] = community

	return result, nil
}

// buildSNMPGetRequest creates a simple SNMP v1 GetRequest packet
func buildSNMPGetRequest(community, oid string) []byte {
	// This is a simplified SNMP GetRequest packet for sysDescr
	// SNMP v1, community "public", GetRequest for 1.3.6.1.2.1.1.1.0
	snmpPacket := []byte{
		0x30, 0x29, // SEQUENCE (41 bytes)
		0x02, 0x01, 0x00, // INTEGER version (SNMPv1 = 0)
		0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // OCTET STRING "public"
		0xa0, 0x1c, // GetRequest PDU
		0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id = 1
		0x02, 0x01, 0x00, // error-status = 0
		0x02, 0x01, 0x00, // error-index = 0
		0x30, 0x0e, // variable-bindings SEQUENCE
		0x30, 0x0c, // variable SEQUENCE
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID 1.3.6.1.2.1.1.1.0
		0x05, 0x00, // NULL value
	}

	return snmpPacket
}
