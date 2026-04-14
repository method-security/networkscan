// Package plugins provides DHCP service fingerprinting
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

type DHCPFingerprinter struct{}

func (DHCPFingerprinter) Name() string { return "dhcp" }

func (DHCPFingerprinter) DefaultPorts() []int { return []int{67} }

func (DHCPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// Build DHCP DISCOVER packet
	dhcpDiscover := buildDHCPDiscover()

	// Send the request
	if _, err := conn.Write(dhcpDiscover); err != nil {
		return nil, err
	}

	// Read response
	buffer := make([]byte, 1500)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	// DHCP response must be at least 236 bytes (minimum DHCP packet size)
	if n < 236 {
		return nil, fmt.Errorf("response too short: %d bytes", n)
	}

	// Verify it's a DHCP response (op = 2 for BOOTREPLY)
	op := buffer[0]
	if op != 2 {
		return nil, fmt.Errorf("not a DHCP response (op=%d)", op)
	}

	// Verify DHCP magic cookie (0x63825363)
	if n < 240 {
		return nil, fmt.Errorf("packet too short for DHCP")
	}
	magicCookie := binary.BigEndian.Uint32(buffer[236:240])
	if magicCookie != 0x63825363 {
		return nil, fmt.Errorf("invalid DHCP magic cookie")
	}

	// DHCP service detected - build metadata map first
	meta := make(map[string]string)

	// Parse offered IP address (yiaddr field at bytes 16-19)
	offeredIP := net.IPv4(buffer[16], buffer[17], buffer[18], buffer[19])
	meta["offered_ip"] = offeredIP.String()

	// Parse server identifier (siaddr field at bytes 20-23)
	serverIP := net.IPv4(buffer[20], buffer[21], buffer[22], buffer[23])
	meta["server_ip"] = serverIP.String()

	// Try to parse DHCP options
	if n > 240 {
		options := parseDHCPOptions(buffer[240:n])
		for k, v := range options {
			meta[k] = v
		}
	}

	version := "DHCP Server"
	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeDhcp,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Generic: &discoverfern.GenericServiceMetadata{Metadata: meta}},
	}

	return result, nil
}

// buildDHCPDiscover creates a DHCP DISCOVER packet
func buildDHCPDiscover() []byte {
	packet := make([]byte, 300)

	// op: BOOTREQUEST (1)
	packet[0] = 1

	// htype: Ethernet (1)
	packet[1] = 1

	// hlen: MAC address length (6)
	packet[2] = 6

	// hops: 0
	packet[3] = 0

	// xid: transaction ID (random)
	binary.BigEndian.PutUint32(packet[4:8], 0x12345678)

	// secs: 0
	binary.BigEndian.PutUint16(packet[8:10], 0)

	// flags: 0
	binary.BigEndian.PutUint16(packet[10:12], 0)

	// ciaddr: 0.0.0.0
	// yiaddr: 0.0.0.0
	// siaddr: 0.0.0.0
	// giaddr: 0.0.0.0
	// (all zeros, already set)

	// chaddr: client hardware address (fake MAC)
	packet[28] = 0x00
	packet[29] = 0x11
	packet[30] = 0x22
	packet[31] = 0x33
	packet[32] = 0x44
	packet[33] = 0x55

	// sname and file: all zeros (already set)

	// DHCP magic cookie
	binary.BigEndian.PutUint32(packet[236:240], 0x63825363)

	// DHCP options
	offset := 240

	// Option 53: DHCP Message Type = DISCOVER (1)
	packet[offset] = 53
	offset++
	packet[offset] = 1 // length
	offset++
	packet[offset] = 1 // DHCPDISCOVER
	offset++

	// Option 55: Parameter Request List
	packet[offset] = 55
	offset++
	packet[offset] = 4 // length
	offset++
	packet[offset] = 1 // Subnet Mask
	offset++
	packet[offset] = 3 // Router
	offset++
	packet[offset] = 6 // DNS
	offset++
	packet[offset] = 15 // Domain Name
	offset++

	// Option 255: End
	packet[offset] = 255

	return packet[:offset+1]
}

// parseDHCPOptions parses DHCP options from the packet
func parseDHCPOptions(options []byte) map[string]string {
	result := make(map[string]string)

	for i := 0; i < len(options); {
		optionType := options[i]
		i++

		// Check for end option
		if optionType == 255 {
			break
		}

		// Check for pad option
		if optionType == 0 {
			continue
		}

		// Check if we have enough data for length
		if i >= len(options) {
			break
		}

		optionLen := int(options[i])
		i++

		// Check if we have enough data for the option value
		if i+optionLen > len(options) {
			break
		}

		optionData := options[i : i+optionLen]
		i += optionLen

		// Parse specific options
		switch optionType {
		case 53: // DHCP Message Type
			if optionLen == 1 {
				msgType := getDHCPMessageType(optionData[0])
				result["dhcp_message_type"] = msgType
			}
		case 54: // Server Identifier
			if optionLen == 4 {
				serverIP := net.IPv4(optionData[0], optionData[1], optionData[2], optionData[3])
				result["dhcp_server_id"] = serverIP.String()
			}
		}
	}

	return result
}

// getDHCPMessageType returns a human-readable DHCP message type
func getDHCPMessageType(msgType byte) string {
	switch msgType {
	case 1:
		return "DHCPDISCOVER"
	case 2:
		return "DHCPOFFER"
	case 3:
		return "DHCPREQUEST"
	case 4:
		return "DHCPDECLINE"
	case 5:
		return "DHCPACK"
	case 6:
		return "DHCPNAK"
	case 7:
		return "DHCPRELEASE"
	case 8:
		return "DHCPINFORM"
	default:
		return fmt.Sprintf("Unknown (%d)", msgType)
	}
}
