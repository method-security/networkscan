// Package plugins provides SLP (Service Location Protocol) service fingerprinting
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

type SlpFingerprinter struct{}

func (SlpFingerprinter) Name() string { return "slp" }

func (SlpFingerprinter) DefaultPorts() []int { return []int{427} }

func (SlpFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// Try both TCP and UDP (SLP supports both)
	// Try UDP first (more common)
	conn, err := net.DialTimeout("udp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		// Try TCP if UDP fails
		conn, err = net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = conn.Close() }()

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return nil, err
	}

	// Build SLP Service Request (SrvRqst) message
	// SLP v2 format
	slpRequest := buildSLPServiceRequest()

	// Send the request
	if _, err := conn.Write(slpRequest); err != nil {
		return nil, err
	}

	// Read response
	buffer := make([]byte, 1500)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	// SLP response must be at least 14 bytes (SLP header)
	if n < 14 {
		return nil, fmt.Errorf("response too short: %d bytes", n)
	}

	// Verify SLP version (byte 0)
	slpVersion := buffer[0]
	if slpVersion != 2 {
		return nil, fmt.Errorf("unsupported SLP version: %d", slpVersion)
	}

	// Verify function ID (byte 1) - should be SrvRply (2)
	functionID := buffer[1]
	if functionID != 2 {
		return nil, fmt.Errorf("unexpected SLP function ID: %d", functionID)
	}

	// Extract information from response
	var version *string
	var services []string
	var scopes []string

	versionStr := fmt.Sprintf("SLPv%d", slpVersion)
	version = &versionStr

	// Parse message length
	messageLen := binary.BigEndian.Uint32(buffer[2:5])
	if messageLen > uint32(n) {
		return nil, fmt.Errorf("invalid message length")
	}

	// Parse flags (bytes 5-6)
	// Parse XID (bytes 7-8)
	// Parse language tag length (bytes 9-10)

	// Skip to URL entries section (after header + language tag)
	offset := 14
	langTagLen := binary.BigEndian.Uint16(buffer[12:14])
	offset += int(langTagLen)

	if offset+2 <= n {
		// Parse error code
		errorCode := binary.BigEndian.Uint16(buffer[offset : offset+2])
		if errorCode != 0 {
			return nil, fmt.Errorf("SLP error code: %d", errorCode)
		}
		offset += 2

		// Parse URL entry count
		if offset+2 <= n {
			urlEntryCount := binary.BigEndian.Uint16(buffer[offset : offset+2])
			offset += 2

			// Extract service URLs
			for i := 0; i < int(urlEntryCount) && offset+8 <= n; i++ {
				// Skip reserved byte and lifetime
				offset += 6

				// Get URL length
				urlLen := binary.BigEndian.Uint16(buffer[offset : offset+2])
				offset += 2

				if offset+int(urlLen) <= n {
					serviceURL := string(buffer[offset : offset+int(urlLen)])
					services = append(services, serviceURL)
					offset += int(urlLen)

					// Skip auth blocks (1 byte count + blocks)
					if offset < n {
						authBlockCount := buffer[offset]
						offset++
						// Skip auth blocks (simplified - just skip to next entry)
						offset += int(authBlockCount) * 10 // Approximate
					}
				}
			}
		}
	}

	metadata := &protocol.SlpServerInfo{
		Version:  version,
		Services: services,
		Scopes:   scopes,
	}

	// Determine transport based on connection type
	transport := common.TransportTypeUdp
	if _, ok := conn.(*net.TCPConn); ok {
		transport = common.TransportTypeTcp
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: transport,
		Protocol:  common.ProtocolTypeSlp,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Slp: metadata},
	}

	return result, nil
}

// buildSLPServiceRequest creates an SLP Service Request message
func buildSLPServiceRequest() []byte {
	// SLP v2 Service Request
	packet := make([]byte, 0, 100)

	// Version: 2
	packet = append(packet, 0x02)

	// Function: SrvRqst (1)
	packet = append(packet, 0x01)

	// Length (will be updated later) - 3 bytes
	packet = append(packet, 0x00, 0x00, 0x00)

	// Flags: 0x0000 (no special flags)
	packet = append(packet, 0x00, 0x00)

	// Next Extension Offset: 0x000000 (no extensions)
	packet = append(packet, 0x00, 0x00, 0x00)

	// XID: Transaction ID (0x1234)
	packet = append(packet, 0x12, 0x34)

	// Language Tag Length: 2 ("en")
	packet = append(packet, 0x00, 0x02)

	// Language Tag: "en"
	packet = append(packet, 'e', 'n')

	// PR list length: 0 (no previous responders)
	packet = append(packet, 0x00, 0x00)

	// Service Type: "service:service-agent" (request all services)
	serviceType := "service:service-agent"
	packet = append(packet, 0x00, byte(len(serviceType)))
	packet = append(packet, []byte(serviceType)...)

	// Scope list length: 0 (default scope)
	packet = append(packet, 0x00, 0x00)

	// Predicate length: 0 (no predicate)
	packet = append(packet, 0x00, 0x00)

	// SLP SPI length: 0 (no SPI)
	packet = append(packet, 0x00, 0x00)

	// Update length field (bytes 2-4) - 24-bit big-endian
	length := uint32(len(packet))
	packet[2] = byte(length >> 16)
	packet[3] = byte(length >> 8)
	packet[4] = byte(length)

	return packet
}
