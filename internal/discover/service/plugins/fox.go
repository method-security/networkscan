// Package plugins provides FOX (Tridium Niagara Framework) service fingerprinting
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

type FoxFingerprinter struct{}

func (FoxFingerprinter) Name() string { return "fox" }

func (FoxFingerprinter) DefaultPorts() []int { return []int{1911, 4911} }

func (FoxFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// Niagara FOX is an ASCII framed protocol. This mirrors Nmap's
	// high-confidence probe for TCP/1911 and TLS/4911.
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

	if n < 7 {
		return nil, fmt.Errorf("response too short")
	}

	text := string(response[:n])
	if !strings.HasPrefix(text, "fox a 0") || !strings.Contains(text, "fox hello") {
		return nil, fmt.Errorf("invalid FOX magic header")
	}

	var stationName, hostID, hostAddress *string
	versionStr := "FOX"
	stationInfo := parseFOXTextPayload(text)

	if foxVersion, ok := stationInfo["fox.version"]; ok && foxVersion != "" {
		versionStr = "FOX " + foxVersion
	}
	if appVersion, ok := stationInfo["app.version"]; ok && appVersion != "" {
		versionStr = appVersion
	}
	if name, ok := stationInfo["station.name"]; ok && name != "" {
		stationName = &name
	} else if name, ok := stationInfo["stationName"]; ok && name != "" {
		stationName = &name
	}
	if id, ok := stationInfo["id"]; ok && id != "" {
		hostID = &id
	}
	if addr, ok := stationInfo["hostAddress"]; ok && addr != "" {
		hostAddress = &addr
	}
	version := &versionStr

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
	return []byte("fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n")
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

func parseFOXTextPayload(text string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "{" || line == "};;" || !strings.Contains(line, "=") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[1] == ':' {
			value = value[2:]
		}
		result[strings.TrimSpace(key)] = value
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
