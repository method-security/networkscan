// Package fingerprintx provides DCERPC service fingerprinting for fingerprintx
package fingerprintx

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	plugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/* ---------- metadata ---------- */

type DCERPCMetadata struct {
	Version        string `json:"version"`
	PacketType     string `json:"packet_type"`
	FragmentLength uint16 `json:"fragment_length,omitempty"`
}

func (DCERPCMetadata) Type() string { return "dcerpc" }

/* ---------- plugin ---------- */

type DCERPCPlugin struct{}

func (p *DCERPCPlugin) Name() string                  { return "dcerpc" }
func (p *DCERPCPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *DCERPCPlugin) PortPriority(port uint16) bool { return port == 135 }
func (p *DCERPCPlugin) Priority() int                 { return 90 }

func init() {
	plugins.RegisterPlugin(&DCERPCPlugin{})
}

/* ---------- runtime ---------- */

func (p *DCERPCPlugin) Run(conn net.Conn, t time.Duration, tgt plugins.Target) (*plugins.Service, error) {
	// Build and send DCE/RPC bind request
	bindRequest := buildDCERPCBindRequest()

	reply, err := utils.SendRecv(conn, bindRequest, t)
	if err != nil || len(reply) < 16 {
		return nil, nil
	}

	// Check DCE/RPC response signature
	// Version should be 5, packet type should be Bind_ack (12) or Bind_nak (13)
	if reply[0] != 0x05 { // Version 5
		return nil, nil
	}

	packetType := reply[2]
	if packetType != 0x0c && packetType != 0x0d { // Bind_ack or Bind_nak
		return nil, nil
	}

	meta := DCERPCMetadata{
		Version: fmt.Sprintf("DCE/RPC %d.%d", reply[0], reply[1]),
	}

	// Packet type
	if packetType == 0x0c {
		meta.PacketType = "bind_ack"
	} else if packetType == 0x0d {
		meta.PacketType = "bind_nak"
	} else {
		meta.PacketType = "unknown"
	}

	// Extract fragment length
	if len(reply) >= 10 {
		meta.FragmentLength = binary.LittleEndian.Uint16(reply[8:10])
	}

	return plugins.CreateServiceFrom(tgt, meta, false, "", plugins.TCP), nil
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
