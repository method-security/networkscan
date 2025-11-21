// Package plugins provides Unitronics PCOM service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type PcomFingerprinter struct{}

func (PcomFingerprinter) Name() string { return "pcom" }

func (PcomFingerprinter) DefaultPorts() []int { return []int{20256} }

func (PcomFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// Try multiple PCOM identification requests
	// PCOM protocol can vary between models, so try different approaches

	var response []byte
	var n int
	var lastErr error

	// Approach 1: Standard PCOM ID command
	pcomRequests := [][]byte{
		// Standard ID command
		{0x2F, 0x49, 0x44, 0x02, 0x30, 0x30, 0x4D, 0x03, 0x6A, 0x0D}, // /ID with checksum
		// Alternative ID command format
		{0x2F, 0x5F, 0x49, 0x44, 0x02, 0x30, 0x30, 0x4D, 0x03, 0x6E, 0x0D}, // /_ID variant
		// Simple identification
		{0x2F, 0x49, 0x44, 0x0D}, // /ID simple
		// PCOM info request
		{0x2F, 0x49, 0x4E, 0x46, 0x4F, 0x0D}, // /INFO
	}

	responseBuffer := make([]byte, 1024)

	for _, req := range pcomRequests {
		// Send request
		if _, err := conn.Write(req); err != nil {
			lastErr = err
			continue
		}

		// Set a shorter read timeout for each attempt
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			lastErr = err
			continue
		}

		// Read response
		n, err = conn.Read(responseBuffer)
		if err != nil {
			lastErr = err
			continue
		}

		if n > 0 {
			response = responseBuffer[:n]
			break
		}
	}

	// If no response from any request, return the last error
	if n == 0 || response == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no response from PCOM requests")
	}

	// PCOM responses can vary, but typically contain readable text
	if n < 3 {
		return nil, fmt.Errorf("response too short")
	}

	// Convert response to string for pattern matching
	responseStr := string(response[:n])

	// Check for PCOM indicators in response (be more flexible)
	isPcomResponse := false

	// Check for common PCOM response patterns
	if strings.Contains(responseStr, "PCOM") ||
		strings.Contains(responseStr, "Unitronics") ||
		strings.Contains(responseStr, "PLC") ||
		strings.Contains(responseStr, "Vision") ||
		(response[0] == 0x2F && (response[1] == 0x41 || response[1] == 0x49)) { // "/A" or "/I" response
		isPcomResponse = true
	}

	// Also check for binary response patterns that might indicate PCOM
	if !isPcomResponse {
		// Look for structured binary data that might be PCOM
		for i := 0; i < n-3; i++ {
			if response[i] == 0x02 && response[i+1] != 0x00 { // STX followed by data
				// Look for ETX
				for j := i + 2; j < n && j < i+50; j++ {
					if response[j] == 0x03 { // Found ETX
						isPcomResponse = true
						break
					}
				}
				if isPcomResponse {
					break
				}
			}
		}
	}

	if !isPcomResponse {
		return nil, fmt.Errorf("not a PCOM response")
	}

	// Extract PLC information from response using regex patterns
	var plcModel, plcName, firmwareVersion, hardwareVersion, osVersion, osBuild, uniqueID *string

	// Define patterns to extract information from PCOM response
	patterns := map[string]**string{
		`Model:\s*([^\r\n]+)`:            &plcModel,
		`PLC Name:\s*([^\r\n]+)`:         &plcName,
		`Hardware Version:\s*([^\r\n]+)`: &hardwareVersion,
		`OS Version:\s*([^\r\n]+)`:       &osVersion,
		`OS Build:\s*([^\r\n]+)`:         &osBuild,
		`PLC Unique ID:\s*([^\r\n]+)`:    &uniqueID,
	}

	for pattern, field := range patterns {
		if re := regexp.MustCompile(pattern); re != nil {
			if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
				value := strings.TrimSpace(matches[1])
				if value != "" {
					*field = &value
				}
			}
		}
	}

	// If we have OS Version and Build, combine them for firmware version
	if osVersion != nil && osBuild != nil {
		combined := *osVersion + " Build " + *osBuild
		firmwareVersion = &combined
	} else if osVersion != nil {
		firmwareVersion = osVersion
	}

	// Set version based on detection
	var version *string
	if plcModel != nil || strings.Contains(responseStr, "PCOM") || strings.Contains(responseStr, "Unitronics") {
		versionStr := "PCOM"
		version = &versionStr
	}

	metadata := &protocol.PcomServerInfo{
		Version:         version,
		PlcModel:        plcModel,
		PlcName:         plcName,
		FirmwareVersion: firmwareVersion,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypePcom,
		Version:   version,
		Metadata:  discoverfern.NewServiceMetadataFromPcom(metadata),
	}

	return result, nil
}
