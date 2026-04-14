// Package plugins provides XDMCP service fingerprinting
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

type XdmcpFingerprinter struct{}

func (XdmcpFingerprinter) Name() string { return "xdmcp" }

func (XdmcpFingerprinter) DefaultPorts() []int { return []int{177} }

func (XdmcpFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// XDMCP uses UDP
	conn, err := net.DialTimeout("udp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read deadline
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	// XDMCP Query packet
	// Format: version(2) + opcode(2) + length(2) + data
	// Opcode 2 = Query
	queryPacket := []byte{
		0x00, 0x01, // Version 1
		0x00, 0x02, // Opcode: Query
		0x00, 0x01, // Length: 1 (minimal query)
		0x00, // Authentication names count: 0
	}

	// Send query
	if _, err := conn.Write(queryPacket); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	if n < 6 {
		return nil, fmt.Errorf("response too short")
	}

	// Parse XDMCP response
	// Check version (should be 0x0001)
	version := binary.BigEndian.Uint16(response[0:2])
	if version != 1 {
		return nil, fmt.Errorf("invalid XDMCP version: %d", version)
	}

	// Check opcode
	opcode := binary.BigEndian.Uint16(response[2:4])

	// Valid XDMCP response opcodes:
	// 3 = Willing
	// 4 = Unwilling
	// Other opcodes might be valid depending on the query
	var status *string
	var authenticationNames []string

	switch opcode {
	case 3: // Willing
		statusStr := "Willing"
		status = &statusStr

		// Parse Willing packet
		// Format after opcode: length(2) + authentication-name(string) + hostname(string) + status(string)
		if n >= 8 {
			// Parse authentication names
			offset := 6
			if offset < n {
				authNameLen := int(binary.BigEndian.Uint16(response[offset : offset+2]))
				offset += 2
				if offset+authNameLen <= n && authNameLen > 0 {
					authName := string(response[offset : offset+authNameLen])
					authenticationNames = append(authenticationNames, authName)
				}
			}
		}

	case 4: // Unwilling
		statusStr := "Unwilling"
		status = &statusStr

	default:
		// Other opcodes indicate XDMCP response
		statusStr := fmt.Sprintf("Response opcode %d", opcode)
		status = &statusStr
	}

	versionStr := fmt.Sprintf("Version %d", version)

	metadata := &protocol.XdmcpServerInfo{
		Version:            &versionStr,
		AuthenticationName: authenticationNames,
		Status:             status,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeXdmcp,
		Version:   &versionStr,
		Metadata:  &discoverfern.ServiceMetadata{Xdmcp: metadata},
	}

	return result, nil
}
