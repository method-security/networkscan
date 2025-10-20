// Package plugins provides BGP service fingerprinting
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

type BGPFingerprinter struct{}

func (BGPFingerprinter) Name() string { return "bgp" }

func (BGPFingerprinter) DefaultPorts() []int { return []int{179} }

func (BGPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip.String(), port), time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Build BGP OPEN message
	openMsg := buildBGPOpenMessage()

	// Set deadline
	if err := conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return nil, err
	}

	// Send BGP OPEN
	if _, err := conn.Write(openMsg); err != nil {
		return nil, err
	}

	// Read response
	reply := make([]byte, 4096)
	n, err := conn.Read(reply)
	if err != nil || n < 19 {
		return nil, err
	}
	reply = reply[:n]

	// Verify BGP marker (16 bytes of 0xFF)
	for i := 0; i < 16; i++ {
		if reply[i] != 0xFF {
			return nil, nil // Not BGP
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

	bgpVersion := "4"
	var messageType string

	// Determine message type
	switch msgType {
	case 1:
		messageType = "OPEN"
		// Try to extract version from OPEN message
		if len(reply) >= 20 {
			version := reply[19]
			if version == 4 {
				bgpVersion = "4"
			}
		}
	case 2:
		messageType = "UPDATE"
	case 3:
		messageType = "NOTIFICATION"
	case 4:
		messageType = "KEEPALIVE"
	case 5:
		messageType = "ROUTE-REFRESH"
	}

	metadata := &protocol.BgpServerInfo{
		Version:     &bgpVersion,
		MessageType: &messageType,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeBgp,
		Version:   &bgpVersion,
		Metadata:  discoverfern.NewServiceMetadataFromBgp(metadata),
	}

	return result, nil
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
