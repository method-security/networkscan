// Package plugins provides BGP service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
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

	// Read initial response - BGP servers may immediately close connection or send NOTIFICATION
	reply := make([]byte, 4096)
	n, err := conn.Read(reply)
	
	// Handle different response scenarios
	if err != nil {
		// Connection reset by peer is common for BGP - indicates BGP service is running
		// but rejecting our connection (wrong AS, not configured peer, etc.)
		errStr := err.Error()
		if n == 0 && (errStr == "EOF" || 
						   strings.Contains(errStr, "connection reset by peer") ||
						   strings.Contains(errStr, "reset by peer")) {
			// This is actually a positive BGP detection - service is there but rejecting us
			return createBGPServiceDetails(ip, port, host, "4", "CONNECTION_REJECTED", nil, nil, nil), nil
		}
		return nil, err
	}
	
	if n < 19 {
		// Got some data but not enough for BGP header
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

	// Validate message length
	if msgLength < 19 || msgLength > 4096 || int(msgLength) > len(reply) {
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
		// Parse OPEN message details
		if parsedData := parseBGPOpenMessage(reply[19:]); parsedData != nil {
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
		Metadata:  discoverfern.NewServiceMetadataFromBgp(metadata),
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
