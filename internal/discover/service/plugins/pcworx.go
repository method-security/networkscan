// Package plugins provides PCWORX service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type PcworxFingerprinter struct{}

func (PcworxFingerprinter) Name() string { return "pcworx" }

func (PcworxFingerprinter) DefaultPorts() []int { return []int{1962} }

func (PcworxFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// Create connection with timeout
	dialer := net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	// PCWORX identification request
	// This is a minimal probe to identify a PCWORX device
	// PCWORX uses a proprietary protocol over TCP port 1962
	identificationRequest := []byte{
		0x01, 0x01, 0x00, 0x1a, // Header with length
		0x00, 0x00, 0x00, 0x01, // Request type: identification
		0x00, 0x00, 0x00, 0x00, // Sequence number
	}

	// Send identification request
	if _, err := conn.Write(identificationRequest); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// PCWORX responses typically start with specific header bytes
	// Check for PCWORX protocol markers
	if n < 4 {
		return nil, fmt.Errorf("response too short")
	}

	// Parse response header to validate PCWORX protocol
	// Real PCWORX devices respond with 0x81 0x01 (not 0x01 0x01)
	if response[0] != 0x81 || response[1] != 0x01 {
		return nil, fmt.Errorf("invalid PCWORX response header")
	}

	// Extract device information from response
	var deviceType, deviceName, projectName *string

	// Parse response payload (after 4-byte header)
	if n > 8 {
		payload := response[8:n]

		// Try to extract device information
		// PCWORX responses contain device type and name information
		if len(payload) > 0 {
			// Look for ASCII strings in response that might indicate device info
			payloadStr := string(payload)
			if idx := strings.Index(payloadStr, "\x00"); idx > 0 {
				deviceInfo := payloadStr[:idx]
				if len(deviceInfo) > 0 && isPrintable(deviceInfo) {
					deviceType = &deviceInfo
				}
			}
		}
	}

	// Extract version from response if available
	var version *string
	if n >= 4 {
		responseLen := binary.BigEndian.Uint16(response[2:4])
		if responseLen > 0 && int(responseLen) <= n-4 {
			versionStr := fmt.Sprintf("Protocol v%d.%d", response[0], response[1])
			version = &versionStr
		}
	}

	metadata := &protocol.PcworxServerInfo{
		Version:     version,
		DeviceType:  deviceType,
		DeviceName:  deviceName,
		ProjectName: projectName,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypePcworx,
		Version:   version,
		Metadata:  discoverfern.NewServiceMetadataFromPcworx(metadata),
	}

	return result, nil
}

// isPrintable checks if a string contains mostly printable ASCII characters
func isPrintable(s string) bool {
	printableCount := 0
	for _, c := range s {
		if c >= 32 && c <= 126 {
			printableCount++
		}
	}
	return printableCount > len(s)/2
}
