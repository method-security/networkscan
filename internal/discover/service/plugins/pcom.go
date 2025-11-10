// Package plugins provides Unitronics PCOM service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
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

	// PCOM identification request
	// PCOM protocol structure: /ID + command code
	// Command 0x4D (ID request) to identify the PLC
	pcomRequest := []byte{
		0x2F, 0x5F, // ASCII "/_" - PCOM header
		0x49, 0x44, // ASCII "ID" - Identification command
		0x02,       // STX (Start of Text)
		0x30, 0x30, // Unit ID "00"
		0x4D, // Command: Get PLC Name
		0x03, // ETX (End of Text)
	}

	// Calculate and append checksum (XOR of all bytes between STX and ETX)
	checksum := byte(0)
	for i := 4; i < len(pcomRequest)-1; i++ {
		checksum ^= pcomRequest[i]
	}
	pcomRequest = append(pcomRequest, checksum)
	pcomRequest = append(pcomRequest, 0x0D) // CR (Carriage Return)

	// Send identification request
	if _, err := conn.Write(pcomRequest); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// PCOM responses typically start with "/_"
	if n < 6 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify PCOM response header
	if response[0] != 0x2F || response[1] != 0x41 { // "/A" for acknowledgment
		return nil, fmt.Errorf("invalid PCOM response header")
	}

	// Extract PLC information from response
	var plcModel, plcName, firmwareVersion *string

	// Parse response payload (after header)
	if n > 10 && response[2] == 0x02 { // STX found
		// Find ETX to determine payload length
		etxPos := -1
		for i := 3; i < n; i++ {
			if response[i] == 0x03 {
				etxPos = i
				break
			}
		}

		if etxPos > 3 {
			payload := response[3:etxPos]
			// Try to extract ASCII strings that might indicate PLC model
			if len(payload) > 0 {
				plcInfo := string(payload)
				if len(plcInfo) > 0 && isPrintableString(plcInfo) {
					plcModel = &plcInfo
				}
			}
		}
	}

	// Extract version from response if available
	var version *string
	if plcModel != nil {
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

// isPrintableString checks if a string contains mostly printable ASCII characters
func isPrintableString(s string) bool {
	if len(s) == 0 {
		return false
	}
	printableCount := 0
	for _, c := range s {
		if c >= 32 && c <= 126 {
			printableCount++
		}
	}
	return printableCount > len(s)/2
}
