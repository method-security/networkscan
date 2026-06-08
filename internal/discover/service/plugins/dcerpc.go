// Package plugins provides DCERPC service fingerprinting
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

type DCERPCFingerprinter struct{}

func (DCERPCFingerprinter) Name() string { return "dcerpc" }

func (DCERPCFingerprinter) DefaultPorts() []int { return []int{135} }

func (DCERPCFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	conn, err := helpers.Dial(ctx, "tcp", utils.FormatHostPort(ip.String(), port), timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Build and send DCE/RPC bind request
	bindRequest := buildDCERPCBindRequest()

	// Set deadline
	if err := helpers.SetDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// Send bind request
	if _, err := conn.Write(bindRequest); err != nil {
		return nil, err
	}

	// Read response
	reply := make([]byte, 4096)
	n, err := conn.Read(reply)
	if err != nil || n < 16 {
		return nil, err
	}
	reply = reply[:n]

	// Check DCE/RPC response signature
	// Version should be 5, packet type should be Bind_ack (12) or Bind_nak (13)
	if reply[0] != 0x05 { // Version 5
		return nil, nil
	}

	packetType := reply[2]
	if packetType != 0x0c && packetType != 0x0d { // Bind_ack or Bind_nak
		return nil, nil
	}

	version := fmt.Sprintf("%d.%d", reply[0], reply[1])

	var packetTypeStr string
	if packetType == 0x0c {
		packetTypeStr = "bind_ack"
	} else if packetType == 0x0d {
		packetTypeStr = "bind_nak"
	} else {
		packetTypeStr = "unknown"
	}

	// Extract fragment length
	var fragmentLength string
	if len(reply) >= 10 {
		fragmentLength = fmt.Sprintf("%d", binary.LittleEndian.Uint16(reply[8:10]))
	}

	metadata := &protocol.DcerpcServerInfo{
		Version:        &version,
		PacketType:     &packetTypeStr,
		FragmentLength: &fragmentLength,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeDcerpc,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Dcerpc: metadata},
	}

	return result, nil
}

/* ---------- helper ---------- */

func buildDCERPCBindRequest() []byte {
	// DCE/RPC Bind PDU
	// This is a simplified bind request to EPM (Endpoint Mapper)
	return []byte{
		// PDU Header
		0x05,                   // Version (5)
		0x00,                   // Version minor (0)
		0x0b,                   // Packet type: Bind (11)
		0x03,                   // Packet flags
		0x10, 0x00, 0x00, 0x00, // Data representation (little-endian)
		0x48, 0x00, // Fragment length (72 bytes)
		0x00, 0x00, // Auth length
		0x01, 0x00, 0x00, 0x00, // Call ID

		// Bind data
		0xb8, 0x10, // Max xmit frag
		0xb8, 0x10, // Max recv frag
		0x00, 0x00, 0x00, 0x00, // Assoc group
		0x01, 0x00, 0x00, 0x00, // Num ctx items (1)

		// Context item
		0x00, 0x00, // Context ID
		0x01, 0x00, // Num trans items

		// Abstract syntax (EPM interface UUID)
		0xe1, 0xaf, 0x80, 0x34, 0x5d, 0xc1, 0xce, 0x11,
		0xa8, 0x97, 0x08, 0x00, 0x2b, 0x2e, 0x9c, 0x6d,
		0x03, 0x00, 0x00, 0x00, // Version (3.0)

		// Transfer syntax (NDR UUID)
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		0x02, 0x00, 0x00, 0x00, // Version (2.0)
	}
}
