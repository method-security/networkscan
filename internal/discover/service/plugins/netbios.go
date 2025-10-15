// Package plugins provides NetBIOS Name Service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type NetBIOSFingerprinter struct{}

func (NetBIOSFingerprinter) Name() string { return "netbios-ns" }

func (NetBIOSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// Build NetBIOS Name Query for "*" (wildcard)
	// This is a status query that requests all NetBIOS names
	nbnsQuery := buildNetBIOSStatusQuery()

	// Send the request
	if _, err := conn.Write(nbnsQuery); err != nil {
		return nil, err
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	// Check if we got a valid NetBIOS response (minimum header size is 12 bytes)
	if n < 12 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify it's a NetBIOS response by checking the header
	// Transaction ID should match (we use 0x1337)
	transID := binary.BigEndian.Uint16(buffer[0:2])
	if transID != 0x1337 {
		return nil, fmt.Errorf("invalid NetBIOS response")
	}

	// NetBIOS service detected
	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeNetbios,
		Metadata:  make(map[string]string),
	}

	version := "NetBIOS Name Service"
	result.Version = &version
	result.Metadata["service"] = "NetBIOS-NS"

	// Try to parse NetBIOS names from response
	if n > 56 {
		// NetBIOS name response format has names starting at offset 56
		names := parseNetBIOSNames(buffer[56:n])
		if len(names) > 0 {
			result.Metadata["netbios_names"] = fmt.Sprintf("%v", names)
		}
	}

	return result, nil
}

// buildNetBIOSStatusQuery creates a NetBIOS Name Query packet for status
func buildNetBIOSStatusQuery() []byte {
	query := make([]byte, 50)

	// Transaction ID
	binary.BigEndian.PutUint16(query[0:2], 0x1337)

	// Flags: Standard query
	binary.BigEndian.PutUint16(query[2:4], 0x0000)

	// Questions: 1
	binary.BigEndian.PutUint16(query[4:6], 0x0001)

	// Answer RRs: 0
	binary.BigEndian.PutUint16(query[6:8], 0x0000)

	// Authority RRs: 0
	binary.BigEndian.PutUint16(query[8:10], 0x0000)

	// Additional RRs: 0
	binary.BigEndian.PutUint16(query[10:12], 0x0000)

	// Query Name: "*" encoded in NetBIOS format
	// Length of first label
	query[12] = 0x20

	// Encode "*" (0x2A) in NetBIOS half-ASCII format
	// Each byte is split into two 4-bit nibbles and added to 'A' (0x41)
	for i := 0; i < 32; i++ {
		query[13+i] = 'A' // 'A' is the base for NetBIOS encoding
	}
	// First two characters encode the actual name "*"
	query[13] = 'C' // High nibble of '*' (0x2)
	query[14] = 'K' // Low nibble of '*' (0xA)

	// End of name
	query[45] = 0x00

	// Query Type: NBSTAT (0x21)
	binary.BigEndian.PutUint16(query[46:48], 0x0021)

	// Query Class: IN (0x0001)
	binary.BigEndian.PutUint16(query[48:50], 0x0001)

	return query
}

// parseNetBIOSNames attempts to extract NetBIOS names from the response
func parseNetBIOSNames(data []byte) []string {
	var names []string

	// Each NetBIOS name entry is 18 bytes
	for i := 0; i+18 <= len(data); i += 18 {
		// First 15 bytes are the name (padded with spaces)
		// 16th byte is the name type
		name := string(data[i : i+15])
		// Trim spaces
		name = trimSpaces(name)
		if len(name) > 0 {
			names = append(names, name)
		}
	}

	return names
}

// trimSpaces removes trailing spaces from a string
func trimSpaces(s string) string {
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}
