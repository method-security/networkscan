// Package plugins provides HART-IP (Highway Addressable Remote Transducer) service fingerprinting
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

type HartFingerprinter struct{}

func (HartFingerprinter) Name() string { return "hart" }

func (HartFingerprinter) DefaultPorts() []int { return []int{5094, 20004} }

func (HartFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// HART-IP uses UDP primarily, but also supports TCP
	// Try UDP first
	conn, err := dialService(ctx, "udp", addr, timeout)
	if err != nil {
		// Try TCP if UDP fails
		conn, err = dialService(ctx, "tcp", addr, timeout)
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = conn.Close() }()

	// Set read deadline
	if err := setServiceReadDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// HART-IP Discovery Request (Session Initiate)
	hartDiscovery := buildHARTDiscoveryRequest()

	// Send discovery request
	if _, err := conn.Write(hartDiscovery); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// HART-IP message format:
	// Version (1), Message Type (1), Message ID (1), Status (1),
	// Sequence Number (2), Byte Count (2), Data (variable)
	if n < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify HART-IP header
	version := response[0]
	messageType := response[1]

	// HART-IP version should be 1 or 2
	if version < 1 || version > 2 {
		return nil, fmt.Errorf("invalid HART-IP version: %d", version)
	}

	// Message type for response should be > 0x80 (response bit set)
	if messageType < 0x80 {
		return nil, fmt.Errorf("not a HART-IP response")
	}

	// Extract device information
	var deviceType, manufacturer, deviceID *string
	var versionStr *string

	hartVersion := fmt.Sprintf("HART-IP v%d", version)
	versionStr = &hartVersion

	// Parse response data if available
	byteCount := binary.BigEndian.Uint16(response[6:8])
	if n >= 8+int(byteCount) && byteCount > 0 {
		data := response[8 : 8+byteCount]

		// Try to extract device type (typically at start of data)
		if len(data) >= 3 {
			deviceTypeCode := binary.BigEndian.Uint16(data[0:2])
			deviceTypeStr := fmt.Sprintf("0x%04X", deviceTypeCode)
			deviceType = &deviceTypeStr

			// Manufacturer code
			mfgCode := data[2]
			mfgStr := getHARTManufacturer(mfgCode)
			manufacturer = &mfgStr
		}

		// Try to extract device ID (if present)
		if len(data) >= 8 {
			deviceIDValue := binary.BigEndian.Uint32(data[4:8])
			deviceIDStr := fmt.Sprintf("%08X", deviceIDValue)
			deviceID = &deviceIDStr
		}
	}

	metadata := &protocol.HartServerInfo{
		Version:      versionStr,
		DeviceType:   deviceType,
		Manufacturer: manufacturer,
		DeviceId:     deviceID,
	}

	// Determine transport
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
		Protocol:  common.ProtocolTypeHart,
		Version:   versionStr,
		Metadata:  &discoverfern.ServiceMetadata{Hart: metadata},
	}

	return result, nil
}

// buildHARTDiscoveryRequest creates a HART-IP discovery/session initiate request
func buildHARTDiscoveryRequest() []byte {
	request := make([]byte, 12)

	// HART-IP Header
	request[0] = 0x01 // Version 1
	request[1] = 0x00 // Message Type: Session Initiate
	request[2] = 0x00 // Message ID
	request[3] = 0x00 // Status

	// Sequence Number (2 bytes)
	binary.BigEndian.PutUint16(request[4:6], 0x0001)

	// Byte Count (2 bytes) - 4 bytes of data
	binary.BigEndian.PutUint16(request[6:8], 0x0004)

	// Data: Master Type (1), Inactivity Close Timer (3)
	request[8] = 0x01  // Master Type: Primary
	request[9] = 0x00  // Timer (unused in discovery)
	request[10] = 0x00 // Timer
	request[11] = 0x1E // Timer (30 seconds)

	return request
}

// getHARTManufacturer returns manufacturer name from HART manufacturer code
func getHARTManufacturer(code byte) string {
	manufacturers := map[byte]string{
		0x01: "Rosemount",
		0x02: "Foxboro",
		0x03: "Fischer & Porter",
		0x04: "Yokogawa",
		0x05: "Honeywell",
		0x06: "ABB",
		0x07: "Endress+Hauser",
		0x08: "Siemens",
		0x09: "Emerson",
	}

	if name, ok := manufacturers[code]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%02X)", code)
}
