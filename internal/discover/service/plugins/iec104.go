// Package plugins provides IEC 60870-5-104 service fingerprinting
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

type Iec104Fingerprinter struct{}

func (Iec104Fingerprinter) Name() string { return "iec104" }

func (Iec104Fingerprinter) DefaultPorts() []int { return []int{2404} }

func (Iec104Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// IEC 60870-5-104 STARTDT (Start Data Transfer) command
	// U-format APDU: 0x68 (start byte), length, control fields
	startdtRequest := []byte{
		0x68,                   // Start byte
		0x04,                   // Length
		0x07, 0x00, 0x00, 0x00, // STARTDT act
	}

	// Send STARTDT request
	if _, err := conn.Write(startdtRequest); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 255)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// IEC 104 responses start with 0x68
	if n < 2 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify IEC 104 start byte
	if response[0] != 0x68 {
		return nil, fmt.Errorf("invalid IEC 104 response header")
	}

	// Check response length field
	responseLen := int(response[1])
	if n < responseLen+2 {
		return nil, fmt.Errorf("incomplete IEC 104 response")
	}

	// Parse control fields for STARTDT confirmation (0x0B 0x00 0x00 0x00)
	if n >= 6 {
		if response[2] != 0x0B {
			return nil, fmt.Errorf("unexpected IEC 104 response type")
		}
	}

	// Extract protocol information
	var version, asduAddress, causeOfTransmission, commonAddress *string

	// IEC 104 version
	versionStr := "IEC 60870-5-104"
	version = &versionStr

	// Try to send an INTERROGATION command to get more details
	// This is optional and may not work on all systems
	interrogationCmd := []byte{
		0x68, // Start byte
		0x0E, // Length (14 bytes)
		// I-format frame with interrogation command
		0x00, 0x00, 0x00, 0x00, // Send/Receive sequence numbers
		0x64,       // Type ID: C_IC_NA_1 (Interrogation command)
		0x01,       // Variable Structure Qualifier: SQ=0, Number=1
		0x06,       // Cause of Transmission: Activation
		0x00,       // Originator Address
		0x01, 0x00, // Common Address of ASDU
		0x00, 0x00, 0x00, // Information Object Address
		0x14, // QOI: Station interrogation
	}

	if _, err := conn.Write(interrogationCmd); err == nil {
		interrogationResp := make([]byte, 255)
		if n, err := conn.Read(interrogationResp); err == nil && n > 10 {
			// Try to extract ASDU address and common address
			if interrogationResp[0] == 0x68 && n >= 14 {
				// Common Address at bytes 10-11
				commonAddrValue := binary.LittleEndian.Uint16(interrogationResp[10:12])
				commonAddrStr := fmt.Sprintf("%d", commonAddrValue)
				commonAddress = &commonAddrStr

				// Cause of transmission at byte 8
				cotStr := fmt.Sprintf("%d", interrogationResp[8])
				causeOfTransmission = &cotStr
			}
		}
	}

	metadata := &protocol.Iec104ServerInfo{
		Version:             version,
		AsduAddress:         asduAddress,
		CauseOfTransmission: causeOfTransmission,
		CommonAddress:       commonAddress,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeIec104,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Iec104: metadata},
	}

	return result, nil
}
