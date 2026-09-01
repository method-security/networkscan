// Package plugins provides GE SRTP service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type GesrtpFingerprinter struct{}

func (GesrtpFingerprinter) Name() string { return "gesrtp" }

func (GesrtpFingerprinter) DefaultPorts() []int { return []int{18245, 18246} }

func (GesrtpFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// GE SRTP identification request
	// SRTP uses a proprietary binary protocol
	// Send a basic identity request
	srtpRequest := []byte{
		0x01, 0x00, // Protocol version
		0x00, 0x01, // Message type: Identity request
		0x00, 0x08, // Length: 8 bytes payload
		0x00, 0x00, 0x00, 0x00, // Sequence number
		0x00, 0x00, 0x00, 0x00, // Session ID
	}

	// Send identification request
	if _, err := conn.Write(srtpRequest); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// GE SRTP responses should have at least header (8 bytes)
	if n < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify SRTP response header (check protocol version and message type)
	protocolVersion := binary.BigEndian.Uint16(response[0:2])
	messageType := binary.BigEndian.Uint16(response[2:4])

	// Response message type should be 0x8001 (Identity response)
	if messageType != 0x8001 {
		return nil, fmt.Errorf("invalid GE SRTP response type: 0x%04X", messageType)
	}

	// Extract device information from response
	var deviceType, firmwareVersion, deviceID *string
	var version *string

	// Version from protocol version
	versionStr := fmt.Sprintf("SRTP v%d.%d", protocolVersion>>8, protocolVersion&0xFF)
	version = &versionStr

	// Parse response payload (after 8-byte header)
	if n > 16 {
		messageLen := binary.BigEndian.Uint16(response[4:6])
		if int(messageLen) <= n-8 {
			payload := response[8 : 8+messageLen]

			// Try to extract device type (typically starts at offset 0 of payload)
			if len(payload) > 4 {
				deviceTypeCode := binary.BigEndian.Uint16(payload[0:2])
				deviceTypeStr := fmt.Sprintf("0x%04X", deviceTypeCode)
				deviceType = &deviceTypeStr
			}

			// Try to extract firmware version (typically at offset 4)
			if len(payload) > 8 {
				fwMajor := payload[4]
				fwMinor := payload[5]
				fwBuild := binary.BigEndian.Uint16(payload[6:8])
				fwVersionStr := fmt.Sprintf("%d.%d.%d", fwMajor, fwMinor, fwBuild)
				firmwareVersion = &fwVersionStr
			}

			// Try to extract device ID (may be at various offsets)
			if len(payload) > 12 {
				deviceIDValue := binary.BigEndian.Uint32(payload[8:12])
				deviceIDStr := fmt.Sprintf("%08X", deviceIDValue)
				deviceID = &deviceIDStr
			}
		}
	}

	metadata := &protocol.GesrtpServerInfo{
		Version:         version,
		DeviceType:      deviceType,
		FirmwareVersion: firmwareVersion,
		DeviceId:        deviceID,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeGesrtp,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Gesrtp: metadata},
	}

	return result, nil
}
