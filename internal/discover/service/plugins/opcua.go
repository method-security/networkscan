// Package plugins provides OPC UA service fingerprinting
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
)

type OpcuaFingerprinter struct{}

func (OpcuaFingerprinter) Name() string { return "opcua" }

func (OpcuaFingerprinter) DefaultPorts() []int { return []int{4840} }

func (OpcuaFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := dialService(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := setServiceDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// OPC UA Hello message
	// This establishes the secure channel
	endpointURL := fmt.Sprintf("opc.tcp://%s", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	helloMsg := buildOpcuaHelloMessage(endpointURL)

	// Send Hello message
	if _, err := conn.Write(helloMsg); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Check for OPC UA ACK message
	if n < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// OPC UA ACK message starts with "ACK" (0x41 0x43 0x4B)
	if response[0] != 0x41 || response[1] != 0x43 || response[2] != 0x4B {
		// Try to detect OPC UA error responses
		if response[0] == 0x45 && response[1] == 0x52 && response[2] == 0x52 {
			// ERR message - still an OPC UA server
			return buildOpcuaResult(host, ip, port, nil, nil, nil, nil, nil, nil), nil
		}
		return nil, fmt.Errorf("invalid OPC UA response")
	}

	// Parse ACK message
	messageSize := binary.LittleEndian.Uint32(response[4:8])
	var protocolVersion, serverName *string

	if messageSize > 8 && n >= int(messageSize) {
		// Extract protocol version (bytes 8-11)
		if n >= 12 {
			protoVer := binary.LittleEndian.Uint32(response[8:12])
			version := fmt.Sprintf("%d", protoVer)
			protocolVersion = &version
		}

		// Try to extract server information from endpoint description
		// by sending a GetEndpoints request
		endpointsReq := buildOpcuaGetEndpointsRequest(endpointURL)
		if _, err := conn.Write(endpointsReq); err == nil {
			endpointsResp := make([]byte, 8192)
			if n, err := conn.Read(endpointsResp); err == nil && n > 0 {
				// Parse endpoint information
				serverInfo := parseOpcuaEndpoints(endpointsResp[:n])
				if serverInfo != nil {
					serverName = serverInfo
				}
			}
		}
	}

	return buildOpcuaResult(host, ip, port, protocolVersion, serverName, nil, nil, &endpointURL, nil), nil
}

// buildOpcuaHelloMessage creates an OPC UA Hello message
func buildOpcuaHelloMessage(endpointURL string) []byte {
	// OPC UA Binary Protocol Hello message structure
	msg := []byte{
		0x48, 0x45, 0x4C, 0x46, // "HELF" message type (Hello)
	}

	endpointBytes := []byte(endpointURL)

	// Message size (will be filled later)
	msgSize := make([]byte, 4)

	// Protocol version (0)
	protocolVersion := make([]byte, 4)
	binary.LittleEndian.PutUint32(protocolVersion, 0)

	// Receive buffer size
	receiveBufferSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(receiveBufferSize, 65535)

	// Send buffer size
	sendBufferSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(sendBufferSize, 65535)

	// Max message size
	maxMessageSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(maxMessageSize, 0)

	// Max chunk count
	maxChunkCount := make([]byte, 4)
	binary.LittleEndian.PutUint32(maxChunkCount, 0)

	// Endpoint URL length
	endpointLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(endpointLen, uint32(len(endpointBytes)))

	// Build complete message
	msg = append(msg, msgSize...)
	msg = append(msg, protocolVersion...)
	msg = append(msg, receiveBufferSize...)
	msg = append(msg, sendBufferSize...)
	msg = append(msg, maxMessageSize...)
	msg = append(msg, maxChunkCount...)
	msg = append(msg, endpointLen...)
	msg = append(msg, endpointBytes...)

	// Update message size
	binary.LittleEndian.PutUint32(msg[4:8], uint32(len(msg)))

	return msg
}

// buildOpcuaGetEndpointsRequest creates a GetEndpoints request
func buildOpcuaGetEndpointsRequest(endpointURL string) []byte {
	// Simplified GetEndpoints request
	// This is a minimal implementation for fingerprinting
	msg := []byte{
		0x4D, 0x53, 0x47, 0x46, // "MSGF" message type
		0x00, 0x00, 0x00, 0x00, // Message size (placeholder)
	}
	// Add minimal GetEndpoints request payload
	// This would normally be much more complex
	return msg
}

// parseOpcuaEndpoints extracts server information from GetEndpoints response
func parseOpcuaEndpoints(response []byte) *string {
	// Look for application name or server information in the response
	// OPC UA uses UTF-8 strings with length prefix
	if len(response) > 20 {
		// Try to find printable strings that might be server names
		responseStr := string(response)
		if idx := strings.Index(responseStr, "urn:"); idx >= 0 && idx < len(responseStr)-4 {
			endIdx := strings.IndexByte(responseStr[idx:], 0)
			if endIdx > 0 {
				serverInfo := responseStr[idx : idx+endIdx]
				if len(serverInfo) > 0 && len(serverInfo) < 200 {
					return &serverInfo
				}
			}
		}
	}
	return nil
}

// buildOpcuaResult constructs the service details result
func buildOpcuaResult(host string, ip net.IP, port int, version, serverName, applicationURI, productURI, endpointURL, securityMode *string) *discoverfern.ServiceDetails {
	metadata := &protocol.OpcuaServerInfo{
		Version:        version,
		ServerName:     serverName,
		ApplicationUri: applicationURI,
		ProductUri:     productURI,
		EndpointUrl:    endpointURL,
		SecurityMode:   securityMode,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeOpcua,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Opcua: metadata},
	}

	return result
}
