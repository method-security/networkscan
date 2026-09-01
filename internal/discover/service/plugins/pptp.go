// Package plugins provides PPTP (Point-to-Point Tunneling Protocol) service fingerprinting
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
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type PptpFingerprinter struct{}

func (PptpFingerprinter) Name() string { return "pptp" }

func (PptpFingerprinter) DefaultPorts() []int { return []int{1723} }

func (PptpFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	if response, err := readPPTPInitialControlMessage(ctx, ip, port, timeout); err == nil {
		if result, err := buildPPTPResultFromResponse(host, ip, port, response); err == nil {
			return result, nil
		}
	}

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

	// Build PPTP Start-Control-Connection-Request
	pptpRequest := buildPPTPStartControlRequest()

	// Send the request
	if _, err := conn.Write(pptpRequest); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	return buildPPTPResultFromResponse(host, ip, port, response[:n])
}

func buildPPTPResultFromResponse(host string, ip net.IP, port int, response []byte) (*discoverfern.ServiceDetails, error) {
	if len(response) < 16 {
		return nil, fmt.Errorf("response too short: %d bytes", len(response))
	}
	// Parse PPTP header
	length := binary.BigEndian.Uint16(response[0:2])
	messageType := binary.BigEndian.Uint16(response[2:4])
	magicCookie := binary.BigEndian.Uint32(response[4:8])
	controlMessageType := binary.BigEndian.Uint16(response[8:10])

	// Verify PPTP magic cookie (0x1A2B3C4D)
	if magicCookie != 0x1A2B3C4D {
		return nil, fmt.Errorf("invalid PPTP magic cookie: 0x%X", magicCookie)
	}

	// Verify message type (1 = Control Message)
	if messageType != 1 {
		return nil, fmt.Errorf("invalid PPTP message type: %d", messageType)
	}

	// Verify control message type (2 = Start-Control-Connection-Reply)
	if controlMessageType != 2 && controlMessageType != 5 {
		return nil, fmt.Errorf("unexpected PPTP control message type: %d", controlMessageType)
	}

	// Extract PPTP server information
	var version *string
	var hostname *string
	var vendor *string

	// Parse protocol version (bytes 12-13)
	if length >= 16 && len(response) >= 16 {
		protocolVersion := binary.BigEndian.Uint16(response[12:14])
		major := protocolVersion >> 8
		minor := protocolVersion & 0xFF
		versionStr := fmt.Sprintf("PPTP v%d.%d", major, minor)
		version = &versionStr
	}

	// Parse framing capabilities (bytes 16-19)
	// Parse bearer capabilities (bytes 20-23)

	// Parse firmware revision (bytes 24-25)
	if len(response) >= 26 {
		firmwareRevision := binary.BigEndian.Uint16(response[24:26])
		if firmwareRevision > 0 {
			fwStr := fmt.Sprintf("0x%04X", firmwareRevision)
			vendor = &fwStr
		}
	}

	// Parse hostname (bytes 26-89, null-terminated string)
	if len(response) >= 90 {
		hostnameBytes := response[26:90]
		hostnameStr := extractNullTerminatedString(hostnameBytes)
		if hostnameStr != "" {
			hostname = &hostnameStr
		}
	}

	// Parse vendor string (bytes 90-153, null-terminated string)
	if len(response) >= 154 {
		vendorBytes := response[90:154]
		vendorStr := extractNullTerminatedString(vendorBytes)
		if vendorStr != "" {
			vendor = &vendorStr
		}
	}

	metadata := &protocol.PptpServerInfo{
		Version:  version,
		Hostname: hostname,
		Vendor:   vendor,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypePptp,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Pptp: metadata},
	}

	return result, nil
}

func readPPTPInitialControlMessage(ctx context.Context, ip net.IP, port int, timeout int) ([]byte, error) {
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	readTimeout := 1500 * time.Millisecond
	if helpers.HasTimeout(timeout) && helpers.Timeout(timeout) > 0 && helpers.Timeout(timeout) < readTimeout {
		readTimeout = helpers.Timeout(timeout)
	}
	if err := helpers.SetReadDeadlineDuration(conn, readTimeout); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

// buildPPTPStartControlRequest creates a PPTP Start-Control-Connection-Request
func buildPPTPStartControlRequest() []byte {
	request := make([]byte, 156)

	// Length (156 bytes)
	binary.BigEndian.PutUint16(request[0:2], 156)

	// Message Type (1 = Control Message)
	binary.BigEndian.PutUint16(request[2:4], 1)

	// Magic Cookie (0x1A2B3C4D)
	binary.BigEndian.PutUint32(request[4:8], 0x1A2B3C4D)

	// Control Message Type (1 = Start-Control-Connection-Request)
	binary.BigEndian.PutUint16(request[8:10], 1)

	// Reserved (0)
	binary.BigEndian.PutUint16(request[10:12], 0)

	// Protocol Version (0x0100 = 1.0)
	binary.BigEndian.PutUint16(request[12:14], 0x0100)

	// Reserved (0)
	binary.BigEndian.PutUint16(request[14:16], 0)

	// Framing Capabilities (3 = Async + Sync)
	binary.BigEndian.PutUint32(request[16:20], 3)

	// Bearer Capabilities (3 = Analog + Digital)
	binary.BigEndian.PutUint32(request[20:24], 3)

	// Maximum Channels (0 = no limit)
	binary.BigEndian.PutUint16(request[24:26], 0)

	// Firmware Revision (0x0001)
	binary.BigEndian.PutUint16(request[26:28], 1)

	// Hostname (null-terminated string, max 64 bytes)
	hostname := "scanner"
	copy(request[28:92], hostname)

	// Vendor String (null-terminated string, max 64 bytes)
	vendor := "networkscan"
	copy(request[92:156], vendor)

	return request
}

// extractNullTerminatedString extracts a null-terminated string from a byte slice
func extractNullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			if i > 0 {
				return string(data[:i])
			}
			return ""
		}
	}
	return string(data)
}
