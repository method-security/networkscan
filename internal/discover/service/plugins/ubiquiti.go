// Package plugins provides Ubiquiti Discovery Protocol fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type UbiquitiFingerprinter struct{}

func (UbiquitiFingerprinter) Name() string { return "ubiquiti" }

func (UbiquitiFingerprinter) DefaultPorts() []int { return []int{10001} }

func (UbiquitiFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Ubiquiti Discovery Protocol uses UDP port 10001
	// Send discovery packet: Version 1, Command 0 (discovery request)
	// Packet format: [version:1 byte][command:1 byte][payload_length:2 bytes][payload...]

	// Create UDP connection
	hostPort := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := net.Dial("udp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Set read deadline
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Build Ubiquiti Discovery request packet
	// Version 1, Command 0 (discovery), no payload
	discoveryPacket := []byte{0x01, 0x00, 0x00, 0x00}

	// Send discovery request
	_, err = conn.Write(discoveryPacket)
	if err != nil {
		return nil, fmt.Errorf("failed to send discovery packet: %w", err)
	}

	// Read response (max 1500 bytes for UDP)
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if n < 4 {
		return nil, fmt.Errorf("response too short: %d bytes", n)
	}

	response = response[:n]

	// Parse response header
	// [version:1 byte][command:1 byte][payload_length:2 bytes][TLV data...]
	version := response[0]
	command := response[1]
	payloadLen := binary.BigEndian.Uint16(response[2:4])

	// Validate response (version should be 1, command should be 0 for discovery response)
	if version != 0x01 {
		return nil, fmt.Errorf("unexpected protocol version: %d", version)
	}

	// Parse TLV (Type-Length-Value) data from payload
	metadata := make(map[string]string)
	metadata["protocol_version"] = fmt.Sprintf("%d", version)
	metadata["command"] = fmt.Sprintf("%d", command)
	metadata["payload_length"] = fmt.Sprintf("%d", payloadLen)

	// Parse TLV fields from payload (starting at byte 4)
	tlvData := response[4:]
	parseTLVFields(tlvData, metadata)

	// Extract device model/version if available
	deviceVersion := "Ubiquiti Device"
	if model, ok := metadata["model"]; ok {
		deviceVersion = fmt.Sprintf("Ubiquiti %s", model)
		if fw, ok := metadata["firmware"]; ok {
			deviceVersion = fmt.Sprintf("Ubiquiti %s (FW: %s)", model, fw)
		}
	} else if hostname, ok := metadata["hostname"]; ok {
		deviceVersion = fmt.Sprintf("Ubiquiti %s", hostname)
	}

	// Build typed metadata structure
	ubiquitiInfo := &protocol.UbiquitiServerInfo{
		ProtocolVersion: stringPtr(metadata["protocol_version"]),
		Command:         stringPtr(metadata["command"]),
		MacAddress:      stringPtr(metadata["mac_address"]),
		MacAddressAlt:   stringPtr(metadata["mac_address_alt"]),
		Hostname:        stringPtr(metadata["hostname"]),
		Model:           stringPtr(metadata["model"]),
		Essid:           stringPtr(metadata["essid"]),
		Firmware:        stringPtr(metadata["firmware"]),
		Uptime:          stringPtr(metadata["uptime"]),
		Default:         stringPtr(metadata["default"]),
		Locating:        stringPtr(metadata["locating"]),
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Version:   &deviceVersion,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeUbiquiti,
		Metadata:  &discoverfern.ServiceMetadata{Ubiquiti: ubiquitiInfo},
	}, nil
}

// parseTLVFields parses Type-Length-Value encoded fields from Ubiquiti Discovery Protocol
func parseTLVFields(data []byte, metadata map[string]string) {
	offset := 0
	for offset+4 <= len(data) {
		fieldType := data[offset]
		fieldLen := binary.BigEndian.Uint16(data[offset+1 : offset+3])
		offset += 3

		if offset+int(fieldLen) > len(data) {
			break
		}

		fieldValue := data[offset : offset+int(fieldLen)]
		offset += int(fieldLen)

		// Map common field types to names
		// Based on Ubiquiti Discovery Protocol specification
		switch fieldType {
		case 0x01:
			metadata["mac_address"] = formatMAC(fieldValue)
		case 0x02:
			metadata["mac_address_alt"] = formatMAC(fieldValue)
		case 0x03:
			metadata["uptime"] = fmt.Sprintf("%d", binary.BigEndian.Uint32(fieldValue))
		case 0x0a:
			metadata["hostname"] = string(fieldValue)
		case 0x0b:
			metadata["model"] = string(fieldValue)
		case 0x0c:
			metadata["essid"] = string(fieldValue)
		case 0x14:
			metadata["firmware"] = string(fieldValue)
		case 0x15:
			metadata["default"] = fmt.Sprintf("%d", fieldValue[0])
		case 0x16:
			metadata["locating"] = fmt.Sprintf("%d", fieldValue[0])
		default:
			// Store unknown fields as hex
			metadata[fmt.Sprintf("field_0x%02x", fieldType)] = fmt.Sprintf("%x", fieldValue)
		}
	}
}

// formatMAC formats a byte slice as a MAC address
func formatMAC(mac []byte) string {
	if len(mac) != 6 {
		return fmt.Sprintf("%x", mac)
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// stringPtr returns a pointer to a string if the string is not empty
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
