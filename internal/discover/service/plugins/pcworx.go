// Package plugins provides PCWORX service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type PcworxFingerprinter struct{}

func (PcworxFingerprinter) Name() string { return "pcworx" }

func (PcworxFingerprinter) DefaultPorts() []int { return []int{1962} }

func (PcworxFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := helpers.Dial(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := helpers.SetDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// PCWORX identification request
	// This mirrors Nmap's high-confidence Phoenix Contact PCWorx probe for
	// TCP/1962. A generic/short probe causes many real devices to stay silent.
	identificationRequest := []byte{
		0x01, 0x01, 0x00, 0x1a,
		0x00, 0x00, 0x00, 0x00,
		0x78, 0x80, 0x00, 0x03,
		0x00, 0x0c,
		'I', 'B', 'E', 'T', 'H', '0', '1', 'N', '0', '_', 'M', 0x00,
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

	if n < 20 {
		return nil, fmt.Errorf("response too short")
	}

	if !looksLikePcworxResponse(response[:n]) {
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
		Metadata:  &discoverfern.ServiceMetadata{Pcworx: metadata},
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

func looksLikePcworxResponse(response []byte) bool {
	if len(response) < 20 {
		return false
	}
	return response[0] == 0x81 &&
		response[1] == 0x01 &&
		response[2] == 0x00 &&
		response[3] == 0x14 &&
		response[4] == 0x00 &&
		response[5] == 0x00 &&
		response[6] == 0x00 &&
		response[7] == 0x01 &&
		response[8] == 0x00 &&
		response[9] == 0x00 &&
		response[10] == 0x00 &&
		response[11] == 0x00 &&
		response[12] == 0x00 &&
		response[13] == 0x02 &&
		response[14] == 0x00 &&
		response[15] == 0x00 &&
		response[18] == 0x00 &&
		response[19] == 0x00
}
