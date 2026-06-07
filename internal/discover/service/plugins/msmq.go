// Package plugins provides MSMQ (Microsoft Message Queuing) service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type MsmqFingerprinter struct{}

func (MsmqFingerprinter) Name() string { return "msmq" }

func (MsmqFingerprinter) DefaultPorts() []int { return []int{1801, 2103, 2105} }

func (MsmqFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := dialService(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := setServiceDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// MSMQ uses a proprietary binary protocol over TCP
	// Send a basic MSMQ connection probe
	msmqProbe := buildMSMQProbe()

	// Send the probe
	if _, err := conn.Write(msmqProbe); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// MSMQ response should be at least 16 bytes
	if n < 16 {
		return nil, fmt.Errorf("response too short: %d bytes", n)
	}

	// Parse MSMQ response header
	// MSMQ protocol has specific signature patterns
	// Check for MSMQ packet signature (varies by version)
	signature := binary.LittleEndian.Uint32(response[0:4])

	// Common MSMQ signatures:
	// 0x4D534D51 = "MSMQ" (ASCII)
	// 0x00000001 = Session packet
	// Other version-specific signatures
	isMSMQ := false
	if signature == 0x4D534D51 || signature == 0x00000001 {
		isMSMQ = true
	} else {
		// Check for other MSMQ patterns
		// MSMQ packets often have specific length fields and structure
		packetLen := binary.LittleEndian.Uint32(response[4:8])
		if packetLen > 0 && packetLen < 65536 && int(packetLen) <= n {
			// Potential MSMQ packet with valid length
			// Check for additional MSMQ markers
			if n >= 12 {
				packetType := binary.LittleEndian.Uint16(response[8:10])
				// MSMQ packet types: 0x01 (Session), 0x02 (User), etc.
				if packetType >= 0x01 && packetType <= 0x0A {
					isMSMQ = true
				}
			}
		}
	}

	if !isMSMQ {
		return nil, fmt.Errorf("not an MSMQ response")
	}

	// Extract MSMQ server information
	var version *string
	var queueManager *string
	var machineID *string

	// Try to determine MSMQ version
	// MSMQ 2.0 (Windows 2000), 3.0 (Windows XP/2003), 4.0 (Windows Vista+), 5.0 (Windows 10+)
	if signature == 0x4D534D51 {
		versionStr := "MSMQ"
		version = &versionStr
	} else {
		// Try to extract version from response
		if n >= 20 {
			versionField := binary.LittleEndian.Uint16(response[16:18])
			if versionField > 0 {
				versionStr := fmt.Sprintf("MSMQ v%d.0", versionField)
				version = &versionStr
			}
		}
	}

	// Try to extract queue manager information
	// Queue manager name may be in the response payload
	if n > 50 {
		// Look for printable strings that might be queue manager names
		payload := response[20:n]
		qmName := extractPrintableASCII(payload, 32)
		if qmName != "" {
			queueManager = &qmName
		}
	}

	// Try to extract machine GUID if present
	if n >= 40 {
		// MSMQ machine IDs are typically GUIDs
		// Format: 16 bytes at various offsets depending on packet type
		guidBytes := response[24:40]
		// Check if it looks like a valid GUID (not all zeros or all FFs)
		isValidGUID := false
		for _, b := range guidBytes {
			if b != 0x00 && b != 0xFF {
				isValidGUID = true
				break
			}
		}
		if isValidGUID {
			guidStr := fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
				binary.LittleEndian.Uint32(guidBytes[0:4]),
				binary.LittleEndian.Uint16(guidBytes[4:6]),
				binary.LittleEndian.Uint16(guidBytes[6:8]),
				binary.BigEndian.Uint16(guidBytes[8:10]),
				binary.BigEndian.Uint32(guidBytes[10:14]),
			)
			machineID = &guidStr
		}
	}

	if version == nil {
		versionStr := "MSMQ"
		version = &versionStr
	}

	metadata := &protocol.MsmqServerInfo{
		Version:      version,
		QueueManager: queueManager,
		MachineId:    machineID,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeMsmq,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Msmq: metadata},
	}

	return result, nil
}

// buildMSMQProbe creates an MSMQ connection probe packet
func buildMSMQProbe() []byte {
	probe := make([]byte, 64)

	// MSMQ Session Packet
	// Signature (4 bytes)
	binary.LittleEndian.PutUint32(probe[0:4], 0x00000001)

	// Packet Length (4 bytes)
	binary.LittleEndian.PutUint32(probe[4:8], 64)

	// Packet Type: Session (2 bytes)
	binary.LittleEndian.PutUint16(probe[8:10], 0x01)

	// Flags (2 bytes)
	binary.LittleEndian.PutUint16(probe[10:12], 0x00)

	// Version (4 bytes) - MSMQ 3.0
	binary.LittleEndian.PutUint32(probe[12:16], 0x00030000)

	// Session ID (8 bytes) - random
	binary.LittleEndian.PutUint64(probe[16:24], 0x0123456789ABCDEF)

	// Remaining bytes are padding/reserved
	return probe
}

// extractPrintableASCII extracts printable ASCII characters from a byte slice
func extractPrintableASCII(data []byte, maxLen int) string {
	if len(data) > maxLen {
		data = data[:maxLen]
	}

	result := ""
	consecutivePrintable := 0

	for _, b := range data {
		if b >= 32 && b <= 126 {
			result += string(b)
			consecutivePrintable++
		} else {
			if consecutivePrintable >= 4 {
				// Found a reasonable string
				return result
			}
			result = ""
			consecutivePrintable = 0
		}
	}

	if consecutivePrintable >= 4 {
		return result
	}
	return ""
}
