package remoteaccess

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	addressfern "github.com/Method-Security/networkscan/generated/go/address"
)

var bufferSize = 4096

type WindowsRDPLibrary struct{}

func (r *WindowsRDPLibrary) StandardPorts() []int {
	return []int{3389, 3388, 443, 8443}
}

func (r *WindowsRDPLibrary) Name() *addressfern.AddressFingerprintResourceModule {
	return addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(addressfern.RemoteAccessModuleWindowsrdp)
}

func (r *WindowsRDPLibrary) TryProtocols(address string, timeout time.Duration) addressfern.TryProtocols {
	tryProtocolsFunction := addressfern.TryProtocols{
		Protocol: "RDP",
	}
	errs := []string{}

	// Check RDP protocol
	successRDP, dataRDP, errRDP := CheckRDPProtocol(address, timeout)
	if len(errRDP) > 0 {
		errs = append(errs, fmt.Sprintf("error checking RDP protocol: %s", errRDP))
		tryProtocolsFunction.Errors = errs
		return tryProtocolsFunction
	}
	if successRDP && (dataRDP != nil) {
		tryProtocolsFunction.ConnectionData = dataRDP
		tryProtocolsFunction.Errors = errRDP
	}

	tryProtocolsFunction.Errors = errs
	return tryProtocolsFunction
}

func CheckRDPProtocol(address string, timeout time.Duration) (bool, *string, []string) {
	errs := []string{}

	// Create dialer with timeout
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting to RDP port: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// Set write timeout
	err = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		errStr := fmt.Sprintf("Error setting write deadline: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// Enhanced RDP Connection Request with comprehensive negotiation
	// This includes support for all security protocols and adds required fields
	rdpConnectionRequest := []byte{
		// TPKT Header (4 bytes)
		0x03, 0x00, // Version 3
		0x00, 0x2b, // Length: 43 bytes

		// X.224 Connection Request TPDU (7 bytes)
		0x26,       // Length indicator (38 bytes)
		0xe0,       // CR TPDU code
		0x00, 0x00, // Dst reference (0)
		0x00, 0x00, // Src reference (0)
		0x00, // Class option

		// RDP Negotiation Request (8 bytes)
		0x01,       // Type: RDP_NEG_REQ (1)
		0x00,       // Flags: 0
		0x08, 0x00, // Length: 8 bytes
		0x03, 0x00, 0x00, 0x00, // requestedProtocols:
		// PROTOCOL_HYBRID | PROTOCOL_SSL (3) - supports both SSL and CredSSP

		// Cookie (24 bytes) - "Cookie: mstshash=admin"
		0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20, // "Cookie: "
		0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, // "mstshash"
		0x3d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x0d, 0x0a, // "=admin\r\n"
	}

	// Send the connection request
	_, err = conn.Write(rdpConnectionRequest)
	if err != nil {
		errStr := fmt.Sprintf("Error sending RDP probe: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// Set read timeout
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		errStr := fmt.Sprintf("Error setting read deadline: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// Read response
	buffer := make([]byte, bufferSize)
	n, err := conn.Read(buffer)

	// Handle read errors
	if err != nil {
		// Only for timeout errors, try an alternative negotiation method
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, nil, []string{}
		} else if err != io.EOF {
			errStr := fmt.Sprintf("Error reading RDP response: %s", err)
			errs = append(errs, errStr)
			return true, nil, errs
		}
	}

	// If we got a response, return it
	if n > 0 {
		responseData := string(buffer[:n])
		return true, &responseData, nil
	}

	err = conn.Close()
	if err != nil {
		errStr := fmt.Sprintf("Error closing connection: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	return false, nil, []string{}
}

func (r *WindowsRDPLibrary) AnalyzeResponse(data string) bool {
	if len(data) == 0 {
		return false
	}

	raw := []byte(data)

	// Common RDP signature: TPKT header with sequence indicator
	if len(raw) >= 2 && raw[0] == 0x03 && raw[1] == 0x00 {
		log.Printf("[INFO] RDP TPKT header detected")
		return true
	}

	// Binary protocol signatures with improved patterns
	binaryPatterns := [][]byte{
		{0x02, 0xf0, 0x80}, // RDP Negotiation Response
		{0x02, 0x0f},       // RDP Security Exchange PDU
	}
	for _, pattern := range binaryPatterns {
		if bytes.Contains(raw, pattern) {
			log.Printf("[INFO] RDP binary protocol signature detected: %x", pattern)
			return true
		}
	}

	// Text-based markers specific to Microsoft RDP
	textMarkers := []string{
		"microsoft-rdp",
		"msrdp",
		"termsrv",
		"ms-rdpbcgr",
		"rdpwd.sys",
		"rdpwsx.dll",
		"mstscax",
		"rdclientax",
	}
	dataLower := strings.ToLower(data)
	for _, marker := range textMarkers {
		if strings.Contains(dataLower, marker) {
			log.Printf("[INFO] RDP text marker detected: %s", marker)
			return true
		}
	}

	return false
}
