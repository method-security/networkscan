package remoteaccess

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	addressfern "github.com/Method-Security/networkscan/generated/go/address"
)

type CitrixGatewayLibrary struct{}

func (c *CitrixGatewayLibrary) Name() *addressfern.AddressFingerprintResourceModule {
	return addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(addressfern.RemoteAccessModuleCitrixGateway)
}

func (c *CitrixGatewayLibrary) StandardPorts() []int {
	return []int{1494, 2598, 443, 8443}
}

func (c *CitrixGatewayLibrary) ModuleRun(ctx context.Context, target string, timeout int) ([]*addressfern.AddressFingerprintAttemptInfo, []string) {
	var (
		attempts []*addressfern.AddressFingerprintAttemptInfo
		errors   []string
		portList []int
	)

	// Get standard ports for the current module
	ports := c.StandardPorts()

	log.Printf("[INFO] Running port scan on %s for %s", target, c.Name())

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
			Module:  c.Name(),
			Host:    host,
			Port:    port,
			Finding: false,
		}

		targetAddress := net.JoinHostPort(host, strconv.Itoa(port))
		log.Printf("[INFO] Attempting to connect to %s:%d for %s", host, port, c.Name())

		// Try ICA protocol
		connectionSuccessful, responseData, protocol, errString := CheckICAProtocol(targetAddress, time.Duration(timeout)*time.Second)
		if errString != nil {
			log.Printf("[INFO] ICA protocol check failed: %s", *errString)
			// Try CGP protocol if ICA fails
			connectionSuccessful, responseData, protocol, errString = CheckCGPProtocol(targetAddress, time.Duration(timeout)*time.Second)
			if errString != nil {
				log.Printf("[INFO] CGP protocol check failed: %s", *errString)
				errors = append(errors, *errString)
				continue
			}
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
			log.Printf("[INFO] Successfully connected to %s:%d", host, port)
			if c.AnalyzeResponse(connectionDataString) {
				attempt.Finding = true
				log.Printf("[INFO] %s service fingerprint detected on %s:%d", c.Name(), host, port)
			}
		} else {
			log.Printf("[INFO] Failed to connect to %s:%d", host, port)
		}
		attempts = append(attempts, attempt)
	}
	return attempts, errors
}

// CheckICAProtocol tests for Citrix ICA protocol
func CheckICAProtocol(address string, timeout time.Duration) (bool, []byte, *string, *string) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting for ICA check: %s", err)
		return false, nil, nil, &errStr
	}
	defer conn.Close()

	// Set read/write timeouts
	conn.SetDeadline(time.Now().Add(timeout))

	// Send ICA client packet
	// Client initialization packet for ICA
	icaInitPacket := []byte{
		0x7f, 0x7f, 0x49, 0x43, 0x41, // ICA signature
		0x00, 0x01, 0x00, 0x00, 0x01, // Version info
		0x00, 0x00, 0x00, // Additional fields
	}

	_, err = conn.Write(icaInitPacket)
	if err != nil {
		errStr := fmt.Sprintf("Error sending ICA probe: %s", err)
		return false, nil, nil, &errStr
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		errStr := fmt.Sprintf("Error reading ICA response: %s", err)
		return false, nil, nil, &errStr
	}

	protocol := "ICA"
	return true, buffer[:n], &protocol, nil
}

// CheckCGPProtocol tests for Citrix CGP protocol
func CheckCGPProtocol(address string, timeout time.Duration) (bool, []byte, *string, *string) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting for CGP check: %s", err)
		return false, nil, nil, &errStr
	}
	defer conn.Close()

	// Set read/write timeouts
	conn.SetDeadline(time.Now().Add(timeout))

	// CGP client initialization packet
	cgpInitPacket := []byte{
		0x43, 0x47, 0x50, 0x2f, 0x31, // "CGP/1"
		0x2e, 0x30, 0x20, 0x30, 0x31, // ".0 01"
	}

	_, err = conn.Write(cgpInitPacket)
	if err != nil {
		errStr := fmt.Sprintf("Error sending CGP probe: %s", err)
		return false, nil, nil, &errStr
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		errStr := fmt.Sprintf("Error reading CGP response: %s", err)
		return false, nil, nil, &errStr
	}

	protocol := "CGP"
	return true, buffer[:n], &protocol, nil
}

func (c *CitrixGatewayLibrary) AnalyzeResponse(data string) bool {
	if len(data) == 0 {
		return false
	}

	// Detect ICA protocol handshake
	if strings.Contains(data, "\x03\x00") || strings.Contains(data, "\x05\x00") {
		log.Printf("[INFO] Citrix ICA protocol handshake detected")
		return true
	}

	// Binary protocol signatures
	binaryPatterns := []string{
		"\x7F\x7F\x43\x47\x50", // Citrix CGP
		"\x45\x44\x49",         // Citrix EDI
		"\x01\x30\x01\x01",     // Citrix protocol version
		"\x01\x30\x01\x02",     // Citrix protocol version
		"\xC0\x01\x09\x01",     // Citrix binary protocol
	}
	for _, pattern := range binaryPatterns {
		if strings.Contains(data, pattern) {
			log.Printf("[INFO] Citrix binary protocol signature detected")
			return true
		}
	}

	// Text-based markers
	textMarkers := []string{"citrix", "ica", "cgp", "nsc_"}
	dataLower := strings.ToLower(data)
	for _, marker := range textMarkers {
		if strings.Contains(dataLower, marker) {
			log.Printf("[INFO] Citrix text marker detected")
			return true
		}
	}

	return false
}
