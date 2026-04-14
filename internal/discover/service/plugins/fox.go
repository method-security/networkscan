// Package plugins provides FOX (Tridium Niagara Framework) service fingerprinting
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

type FoxFingerprinter struct{}

func (FoxFingerprinter) Name() string { return "fox" }

func (FoxFingerprinter) DefaultPorts() []int { return []int{1911, 4911} }

func (FoxFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// FOX protocol hello message
	// FOX uses a binary protocol with message framing
	foxHello := buildFOXHelloMessage()

	// Send FOX hello
	if _, err := conn.Write(foxHello); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 2048)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// FOX message format:
	// Magic (4 bytes: "fox\x00"), Version (1), Message Type (1), Length (2)
	if n < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify FOX magic header
	if response[0] != 'f' || response[1] != 'o' || response[2] != 'x' {
		return nil, fmt.Errorf("invalid FOX magic header")
	}

	// Parse FOX version
	foxVersion := response[4]
	versionStr := fmt.Sprintf("FOX v%d", foxVersion)

	// Parse message type
	messageType := response[5]

	// Response to hello should be a hello response (type varies by version)
	if messageType < 0x80 {
		return nil, fmt.Errorf("not a FOX response message")
	}

	// Parse message length
	messageLen := binary.BigEndian.Uint16(response[6:8])

	// Extract station information from payload
	var stationName, hostID, hostAddress *string
	version := &versionStr

	if n >= 8+int(messageLen) && messageLen > 0 {
		payload := response[8 : 8+messageLen]

		// FOX hello response contains station info as key-value pairs
		// Parse the payload for station name and other metadata
		stationInfo := parseFOXPayload(payload)

		if name, ok := stationInfo["stationName"]; ok {
			stationName = &name
		}
		if id, ok := stationInfo["hostId"]; ok {
			hostID = &id
		}
		if addr, ok := stationInfo["hostAddress"]; ok {
			hostAddress = &addr
		}
	}

	metadata := &protocol.FoxServerInfo{
		Version:     version,
		StationName: stationName,
		HostId:      hostID,
		HostAddress: hostAddress,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeFox,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Fox: metadata},
	}

	return result, nil
}

// buildFOXHelloMessage creates a FOX protocol hello message
func buildFOXHelloMessage() []byte {
	message := make([]byte, 12)

	// FOX Magic
	message[0] = 'f'
	message[1] = 'o'
	message[2] = 'x'
	message[3] = 0x00

	// Version (2 for FOX 2.0)
	message[4] = 0x02

	// Message Type: Hello (0x01)
	message[5] = 0x01

	// Length (4 bytes of minimal payload)
	binary.BigEndian.PutUint16(message[6:8], 0x0004)

	// Minimal payload: client capabilities
	binary.BigEndian.PutUint32(message[8:12], 0x00000001)

	return message
}

// parseFOXPayload extracts key-value pairs from FOX message payload
func parseFOXPayload(payload []byte) map[string]string {
	result := make(map[string]string)

	// FOX uses a simple TLV (Type-Length-Value) encoding
	offset := 0
	for offset+3 < len(payload) {
		// Type (1 byte), Length (2 bytes), Value (variable)
		tagType := payload[offset]
		tagLen := binary.BigEndian.Uint16(payload[offset+1 : offset+3])
		offset += 3

		if offset+int(tagLen) > len(payload) {
			break
		}

		value := payload[offset : offset+int(tagLen)]
		offset += int(tagLen)

		// Common FOX tags
		switch tagType {
		case 0x01: // Station Name
			if isPrintableBytes(value) {
				result["stationName"] = string(value)
			}
		case 0x02: // Host ID
			if len(value) == 4 {
				result["hostId"] = fmt.Sprintf("%08X", binary.BigEndian.Uint32(value))
			}
		case 0x03: // Host Address
			if isPrintableBytes(value) {
				result["hostAddress"] = string(value)
			}
		}
	}

	return result
}

// isPrintableBytes checks if byte slice contains mostly printable characters
func isPrintableBytes(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printableCount := 0
	for _, b := range data {
		if b >= 32 && b <= 126 {
			printableCount++
		}
	}
	return printableCount > len(data)*2/3
}
