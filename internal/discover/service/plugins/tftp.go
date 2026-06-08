// Package plugins provides TFTP (Trivial File Transfer Protocol) service fingerprinting
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
	"github.com/Method-Security/networkscan/utils"
)

type TFTPFingerprinter struct{}

func (TFTPFingerprinter) Name() string { return "tftp" }

func (TFTPFingerprinter) DefaultPorts() []int { return []int{69} }

func (TFTPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := utils.FormatHostPort(ip.String(), port)

	// Create TFTP Read Request (RRQ) packet
	// Opcode: 1 (RRQ), Filename: "test", Mode: "octet"
	rrqPacket := []byte{
		0x00, 0x01, // Opcode: RRQ (1)
	}
	rrqPacket = append(rrqPacket, []byte("test")...)  // Filename
	rrqPacket = append(rrqPacket, 0x00)               // Null terminator
	rrqPacket = append(rrqPacket, []byte("octet")...) // Mode
	rrqPacket = append(rrqPacket, 0x00)               // Null terminator

	conn, err := helpers.Dial(ctx, "udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := helpers.SetDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// Send RRQ packet
	if _, err := conn.Write(rrqPacket); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	if n < 2 {
		return nil, fmt.Errorf("response too short")
	}

	// Parse TFTP opcode
	opcode := binary.BigEndian.Uint16(response[0:2])

	// Valid TFTP responses:
	// Opcode 3 = DATA (file exists and sending data)
	// Opcode 5 = ERROR (file not found or other error - this is what we expect)
	// Opcode 4 = ACK (unlikely for RRQ)
	if opcode != 3 && opcode != 5 {
		return nil, fmt.Errorf("not a TFTP response, opcode: %d", opcode)
	}

	metadata := &protocol.TftpServerInfo{}

	// Parse response details
	switch opcode {
	case 3: // DATA
		opcodeStr := "DATA"
		metadata.Opcode = &opcodeStr
		if n >= 4 {
			blockNum := binary.BigEndian.Uint16(response[2:4])
			blockNumStr := fmt.Sprintf("%d", blockNum)
			metadata.BlockNumber = &blockNumStr
		}
	case 5: // ERROR
		opcodeStr := "ERROR"
		metadata.Opcode = &opcodeStr
		if n >= 4 {
			errorCode := binary.BigEndian.Uint16(response[2:4])
			errorCodeStr := fmt.Sprintf("%d", errorCode)
			metadata.ErrorCode = &errorCodeStr

			// Extract error message (null-terminated string starting at byte 4)
			if n > 4 {
				errorMsg := ""
				for i := 4; i < n; i++ {
					if response[i] == 0 {
						break
					}
					errorMsg += string(response[i])
				}
				if errorMsg != "" {
					metadata.ErrorMessage = &errorMsg
				}
			}
		}
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeTftp,
		Version:   nil, // TFTP has no version field
		Metadata:  &discoverfern.ServiceMetadata{Tftp: metadata},
	}

	return result, nil
}
