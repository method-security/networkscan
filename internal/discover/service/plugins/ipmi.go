// Package plugins provides IPMI (Intelligent Platform Management Interface) service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type IPMIFingerprinter struct{}

func (IPMIFingerprinter) Name() string { return "ipmi" }

func (IPMIFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	// IPMI "Get Channel Authentication Capabilities" request
	// Based on IPMI v1.5/2.0 RMCP specification
	ipmiRequest := []byte{
		// RMCP Header
		0x06, // RMCP Version 1.0
		0x00, // Reserved
		0xFF, // Sequence number (0xFF = no RMCP ACK)
		0x07, // Message Class: IPMI
		// IPMI Session Header
		0x00,                   // Authentication Type: None
		0x00, 0x00, 0x00, 0x00, // Session Sequence Number
		0x00, 0x00, 0x00, 0x00, // Session ID
		// IPMI Message
		0x09, // Message Length
		0x20, // Responder Address
		0x18, // NetFn/LUN
		0xC8, // Checksum
		0x81, // Requester Address
		0x00, // Sequence Number
		0x38, // Command: Get Channel Auth Capabilities
		0x8E, // Channel Number
		0x04, // Privilege Level
		0xB5, // Checksum
	}

	conn, err := net.DialTimeout("udp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return nil, err
	}

	// Send IPMI request
	if _, err := conn.Write(ipmiRequest); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Minimum IPMI response should be at least 13 bytes (RMCP + Session header)
	if n < 13 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify IPMI/RMCP response header
	// Byte 0: RMCP Version (0x06)
	// Byte 1: Reserved (0x00)
	// Byte 2: Sequence (0xFF for no ACK)
	// Byte 3: Message Class (0x07 for IPMI)
	if response[0] != 0x06 || response[3] != 0x07 {
		return nil, fmt.Errorf("not an IPMI response")
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeIpmi,
		Metadata:  make(map[string]string),
	}

	// Parse IPMI version if available
	authType := response[4]
	result.Metadata["auth_type"] = fmt.Sprintf("0x%02x", authType)

	// Check if IPMI 2.0 is supported (indicated in response)
	if n >= 20 && response[19]&0x02 != 0 {
		version := "IPMI 2.0"
		result.Version = &version
		result.Metadata["version"] = "2.0"
	} else {
		version := "IPMI 1.5"
		result.Version = &version
		result.Metadata["version"] = "1.5"
	}

	return result, nil
}
