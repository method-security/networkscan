package remoteaccess

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	addressfern "github.com/Method-Security/networkscan/generated/go/address"
)

type RDPLibrary struct{}

func (r *RDPLibrary) StandardPorts() []int {
	return []int{3389, 3388, 443, 8443}
}

func (r *RDPLibrary) Name() *addressfern.AddressFingerprintResourceModule {
	return addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(addressfern.RemoteAccessModuleMicrosoftRdp)
}

func (r *RDPLibrary) ModuleRun(ctx context.Context, target string, timeout int) ([]*addressfern.AddressFingerprintAttemptInfo, []string) {
	var (
		attempts []*addressfern.AddressFingerprintAttemptInfo
		errors   []string
		portList []int
	)

	// Get standard ports for the current module
	ports := r.StandardPorts()

	log.Printf("[INFO] Running RDP detection on %s", target)

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portList = ports
	} else if portInt, convErr := strconv.Atoi(port); convErr == nil {
		portList = []int{portInt}
	} else {
		errors = append(errors, fmt.Sprintf("Error converting port from string to int: %s", convErr))
	}

	for _, port := range portList {
		attempt := &addressfern.AddressFingerprintAttemptInfo{
			Module:  r.Name(),
			Host:    host,
			Port:    port,
			Finding: false,
		}

		targetAddress := net.JoinHostPort(host, strconv.Itoa(port))
		log.Printf("[INFO] Attempting to connect to %s for RDP detection", targetAddress)

		// Use RDP protocol detection
		connectionSuccessful, responseData, protocol, errString := CheckRDPProtocol(targetAddress, time.Duration(timeout)*time.Second)
		if errString != nil {
			errors = append(errors, *errString)
			continue
		}

		connectionDataString := ""
		if responseData != nil {
			connectionDataString = string(responseData)
			attempt.ConnectionData = &connectionDataString
			log.Printf("[INFO] Response data received (%d bytes)", len(responseData))
		}

		if connectionSuccessful {
			attempt.ConnectedSuccessfully = &connectionSuccessful
			attempt.Protocol = protocol
			log.Printf("[INFO] Successfully connected to %s", targetAddress)
			if r.AnalyzeResponse(connectionDataString) {
				attempt.Finding = true
				log.Printf("[INFO] RDP service detected on %s", targetAddress)
			}
		} else {
			log.Printf("[INFO] Failed to connect to %s", targetAddress)
		}
		attempts = append(attempts, attempt)
	}
	return attempts, errors
}

// CheckRDPProtocol tests for Microsoft RDP protocol
func CheckRDPProtocol(address string, timeout time.Duration) (bool, []byte, *string, *string) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting to RDP port: %s", err)
		return false, nil, nil, &errStr
	}
	defer conn.Close()

	// Set read/write timeouts
	conn.SetDeadline(time.Now().Add(timeout))

	// RDP Connection Request (X.224 Connection Request PDU)
	// This is a standard RDP client connection request with:
	// - TPKT Header (version 3)
	// - X.224 Connection Request
	// - RDP Negotiation Request
	rdpConnectionRequest := []byte{
		// TPKT Header
		0x03, 0x00, // Version
		0x00, 0x2b, // Length (43 bytes)

		// X.224 Connection Request
		0x26,       // Length
		0xe0,       // Connection Request
		0x00, 0x00, // Destination reference
		0x00, 0x00, // Source reference
		0x00, // Class

		// RDP Negotiation Request
		0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,

		// Cookie: "Cookie: mstshash=user"
		0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20,
		0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68,
		0x3d, 0x75, 0x73, 0x65, 0x72, 0x0d, 0x0a,
	}

	_, err = conn.Write(rdpConnectionRequest)
	if err != nil {
		errStr := fmt.Sprintf("Error sending RDP probe: %s", err)
		return false, nil, nil, &errStr
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		errStr := fmt.Sprintf("Error reading RDP response: %s", err)
		return false, nil, nil, &errStr
	}

	protocol := "RDP"
	return true, buffer[:n], &protocol, nil
}

func (r *RDPLibrary) AnalyzeResponse(data string) bool {
	if len(data) == 0 {
		return false
	}

	// Check for TPKT header (version 3)
	if strings.Contains(data, "\x03\x00") {
		log.Printf("[INFO] RDP TPKT header detected")

		// Check for X.224 Connection Confirm (0xd0) or Error (0x70)
		if len(data) >= 5 && (data[4] == '\xd0' || data[4] == '\x70') {
			log.Printf("[INFO] RDP X.224 Connection Confirm/Error detected")
			return true
		}

		// General TPKT header is a good indicator
		return true
	}

	// Binary protocol signatures
	binaryPatterns := []string{
		"\x30\x37\xa0\x03", // CredSSP
		"\x02\xf0\x80",     // RDP Negotiation Response
	}
	for _, pattern := range binaryPatterns {
		if strings.Contains(data, pattern) {
			log.Printf("[INFO] RDP binary protocol signature detected")
			return true
		}
	}

	// Text-based markers specific to Microsoft RDP
	textMarkers := []string{
		"microsoft-rdp",
		"msrdp",
		"msrdp",
		"termsrv",
		"ms-rdpbcgr",
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
