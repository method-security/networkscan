// Package plugins provides IPMI (Intelligent Platform Management Interface) service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"github.com/Method-Security/networkscan/utils"
)

type IPMIFingerprinter struct{}

func (IPMIFingerprinter) Name() string { return "ipmi" }

func (IPMIFingerprinter) DefaultPorts() []int { return []int{623} }

func (IPMIFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := utils.FormatHostPort(ip.String(), port)

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

	conn, err := helpers.Dial(ctx, "udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := helpers.SetDeadline(conn, timeout); err != nil {
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

	// Parse IPMI version and authentication type
	authType := response[4]
	authTypeStr := fmt.Sprintf("0x%02x", authType)

	var version string
	// Check if IPMI 2.0 is supported (indicated in response)
	if n >= 20 && response[19]&0x02 != 0 {
		version = "2.0"
	} else {
		version = "1.5"
	}

	metadata := &protocol.IpmiServerInfo{
		Version:  &version,
		AuthType: &authTypeStr,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeIpmi,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Ipmi: metadata},
	}

	return result, nil
}
