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
	"github.com/Method-Security/networkscan/utils"
)

type BGPFingerprinter struct{}

func (BGPFingerprinter) Name() string { return "bgp" }

func (BGPFingerprinter) DefaultPorts() []int { return []int{179} }

func (BGPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	conn, err := net.DialTimeout("tcp", utils.FormatHostPort(ip.String(), port), time.Duration(timeout)*time.Second)
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

	// Read initial response - BGP servers may immediately close connection or send NOTIFICATION
	reply := make([]byte, 4096)
	n, err := conn.Read(reply)

	// Handle different response scenarios
	if err != nil {
		// For NMAP -sV equivalent behavior, only detect as BGP if we get actual BGP responses
		// Timeouts and other generic errors should be handled by other fingerprinters
		return nil, err
	}

	if n < 19 {
		// Got some data but not enough for BGP header
		// This is likely not BGP - let other fingerprinters handle it
		return nil, nil
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

	// Validate message length - be more restrictive
	if msgLength < 19 || msgLength > 4096 || int(msgLength) > len(reply) {
		return nil, nil
	}

	// Additional validation: for NOTIFICATION messages, ensure proper structure
	if msgType == 3 && msgLength != 21 {
		// NOTIFICATION messages should be exactly 21 bytes (19 header + 2 error codes)
		return nil, nil
	}

	// For KEEPALIVE messages, ensure they're exactly 19 bytes (header only)
	if msgType == 4 && msgLength != 19 {
		return nil, nil
	}

	bgpVersion := "4"
	var messageType string
	var asn *int
	var routerID *string
	var holdTime *int

	// Determine message type and extract details
	switch msgType {
	case 1:
		messageType = "OPEN"
		// Parse OPEN message details - validate minimum OPEN message length
		if int(msgLength) < 29 {
			// OPEN messages must be at least 29 bytes (19 header + 10 minimum OPEN data)
			return nil, nil
		}
		if parsedData := parseBGPOpenMessage(reply[19:]); parsedData != nil {
			// Validate BGP version
			if parsedData.version != 4 {
				return nil, nil
			}
			bgpVersion = fmt.Sprintf("%d", parsedData.version)
			asn = &parsedData.asn
			routerIDStr := fmt.Sprintf("%d.%d.%d.%d", parsedData.routerID[0], parsedData.routerID[1], parsedData.routerID[2], parsedData.routerID[3])
			routerID = &routerIDStr
			holdTime = &parsedData.holdTime
		}
	case 2:
		messageType = "UPDATE"
	case 3:
		messageType = "NOTIFICATION"
		// Try to read notification error codes for better fingerprinting
		if len(reply) >= 21 {
			errorCode := reply[19]
			errorSubcode := reply[20]
			messageType = fmt.Sprintf("NOTIFICATION (Error: %d/%d)", errorCode, errorSubcode)
		}
	case 4:
		messageType = "KEEPALIVE"
	case 5:
		messageType = "ROUTE-REFRESH"
	}

	// Try to read additional messages for better fingerprinting
	if msgType == 1 {
		// After OPEN, we might receive KEEPALIVE or NOTIFICATION
		additionalReply := make([]byte, 256)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := conn.Read(additionalReply); err == nil && n >= 19 {
			// Verify BGP marker
			valid := true
			for i := 0; i < 16; i++ {
				if additionalReply[i] != 0xFF {
					valid = false
					break
				}
			}
			if valid {
				additionalMsgType := additionalReply[18]
				switch additionalMsgType {
				case 4:
					messageType += " -> KEEPALIVE"
				case 3:
					messageType += " -> NOTIFICATION"
				}
			}
		}
	}

	return createBGPServiceDetails(ip, port, host, bgpVersion, messageType, asn, routerID, holdTime), nil
}

/* ---------- helper ---------- */

type bgpOpenData struct {
	version  uint8
	asn      int
	holdTime int
	routerID []byte
}

func parseBGPOpenMessage(data []byte) *bgpOpenData {
	if len(data) < 10 {
		return nil
	}

	version := data[0]
	asn := int(binary.BigEndian.Uint16(data[1:3]))
	holdTime := int(binary.BigEndian.Uint16(data[3:5]))
	routerID := make([]byte, 4)
	copy(routerID, data[5:9])

	// Validate optional parameter length
	if len(data) < 10 {
		return nil
	}
	optParamLen := data[9]

	// Ensure we have enough data for optional parameters
	if len(data) < int(10+optParamLen) {
		return nil
	}

	// Validate hold time - should be 0 or >= 3 seconds
	if holdTime != 0 && holdTime < 3 {
		return nil
	}

	return &bgpOpenData{
		version:  version,
		asn:      asn,
		holdTime: holdTime,
		routerID: routerID,
	}
}

func createBGPServiceDetails(ip net.IP, port int, host, version, messageType string, asn *int, routerID *string, holdTime *int) *discoverfern.ServiceDetails {
	metadata := &protocol.BgpServerInfo{
		Version:     &version,
		MessageType: &messageType,
		Asn:         asn,
		RouterId:    routerID,
		HoldTime:    holdTime,
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeBgp,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Bgp: metadata},
	}
}

func buildBGPOpenMessage() []byte {
	// BGP OPEN message
	marker := make([]byte, 16)
	for i := range marker {
		marker[i] = 0xFF
	}

	// OPEN message payload with more realistic values
	version := byte(4)              // BGP version 4
	myAS := uint16(64512)           // Private ASN range
	holdTime := uint16(180)         // Standard hold time
	bgpID := []byte{192, 168, 1, 1} // More realistic BGP ID
	optParamLen := byte(0)          // No optional parameters

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
