// Package fingerprintx provides BGP service fingerprinting for fingerprintx
package fingerprintx

import (
	"encoding/binary"
	"net"
	"time"

	plugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/* ---------- metadata ---------- */

type BGPMetadata struct {
	MessageType string `json:"message_type,omitempty"`
	Version     string `json:"version,omitempty"`
}

func (BGPMetadata) Type() string { return "bgp" }

/* ---------- plugin ---------- */

type BGPPlugin struct{}

func (p *BGPPlugin) Name() string                  { return "bgp" }
func (p *BGPPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *BGPPlugin) PortPriority(port uint16) bool { return port == 179 }
func (p *BGPPlugin) Priority() int                 { return 90 }

func init() {
	plugins.RegisterPlugin(&BGPPlugin{})
}

/* ---------- runtime ---------- */

func (p *BGPPlugin) Run(conn net.Conn, t time.Duration, tgt plugins.Target) (*plugins.Service, error) {
	// Build BGP OPEN message
	openMsg := buildBGPOpenMessage()

	// Set deadline
	if err := conn.SetDeadline(time.Now().Add(t)); err != nil {
		return nil, nil
	}

	// Send BGP OPEN and wait for response
	reply, err := utils.SendRecv(conn, openMsg, t)
	if err != nil || len(reply) < 19 {
		return nil, nil
	}

	// Verify BGP marker (16 bytes of 0xFF)
	for i := 0; i < 16; i++ {
		if reply[i] != 0xFF {
			return nil, nil
		}
	}

	// Parse message header
	msgLength := binary.BigEndian.Uint16(reply[16:18])
	msgType := reply[18]

	// Valid BGP message types: OPEN(1), UPDATE(2), NOTIFICATION(3), KEEPALIVE(4), ROUTE-REFRESH(5)
	if msgType < 1 || msgType > 5 {
		return nil, nil
	}

	// Validate message length
	if msgLength < 19 || msgLength > 4096 {
		return nil, nil
	}

	meta := BGPMetadata{
		Version: "BGP-4",
	}

	// Determine message type
	switch msgType {
	case 1:
		meta.MessageType = "OPEN"
		// Try to extract version from OPEN message
		if len(reply) >= 20 {
			version := reply[19]
			if version == 4 {
				meta.Version = "BGP-4"
			}
		}
	case 2:
		meta.MessageType = "UPDATE"
	case 3:
		meta.MessageType = "NOTIFICATION"
	case 4:
		meta.MessageType = "KEEPALIVE"
	case 5:
		meta.MessageType = "ROUTE-REFRESH"
	}

	return plugins.CreateServiceFrom(tgt, meta, false, "", plugins.TCP), nil
}

/* ---------- helper ---------- */

func buildBGPOpenMessage() []byte {
	// BGP OPEN message
	marker := make([]byte, 16)
	for i := range marker {
		marker[i] = 0xFF
	}

	// OPEN message payload
	version := byte(4)          // BGP version 4
	myAS := uint16(65000)       // Our ASN
	holdTime := uint16(90)      // Hold time
	bgpID := []byte{1, 1, 1, 1} // BGP Identifier
	optParamLen := byte(0)      // No optional parameters

	// Build OPEN payload
	openPayload := []byte{version}
	openPayload = append(openPayload, byte(myAS>>8), byte(myAS))
	openPayload = append(openPayload, byte(holdTime>>8), byte(holdTime))
	openPayload = append(openPayload, bgpID...)
	openPayload = append(openPayload, optParamLen)

	// Calculate total message length
	msgLength := uint16(16 + 2 + 1 + len(openPayload)) // marker + length + type + payload

	// Build complete message
	packet := make([]byte, 0, msgLength)
	packet = append(packet, marker...)
	packet = append(packet, byte(msgLength>>8), byte(msgLength))
	packet = append(packet, 1) // Message type: OPEN
	packet = append(packet, openPayload...)

	return packet
}
