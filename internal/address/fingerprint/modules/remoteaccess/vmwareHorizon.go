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

type VMwareHorizonLibrary struct{}

func (v *VMwareHorizonLibrary) StandardPorts() []int {
	return []int{443, 8443, 4172, 22443}
}

func (v *VMwareHorizonLibrary) Name() *addressfern.AddressFingerprintResourceModule {
	return addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(addressfern.RemoteAccessModuleVmwareHorizon)
}

func (v *VMwareHorizonLibrary) ModuleRun(ctx context.Context, target string, timeout int) ([]*addressfern.AddressFingerprintAttemptInfo, []string) {
	var (
		attempts []*addressfern.AddressFingerprintAttemptInfo
		errors   []string
		portList []int
	)

	// Get standard ports for the current module
	ports := v.StandardPorts()

	log.Printf("[INFO] Running port scan on %s for %s", target, v.Name())

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
			Module:  v.Name(),
			Host:    host,
			Port:    port,
			Finding: false,
		}

		targetAddress := net.JoinHostPort(host, strconv.Itoa(port))
		log.Printf("[INFO] Attempting to connect to %s:%d for %s", host, port, v.Name())

		// Try both PCoIP and Blast protocols on all ports
		// First try PCoIP
		connectionSuccessful, responseData, protocol, errString := checkVMwareProtocols(targetAddress, time.Duration(timeout)*time.Second)
		if errString != nil {
			errors = append(errors, *errString)
			continue
		}

		// Convert binary response to string for storage
		connectionDataString := ""
		if responseData != nil {
			connectionDataString = string(responseData)
			attempt.ConnectionData = &connectionDataString
			log.Printf("[INFO] Response data received (%d bytes)", len(responseData))
		}

		if connectionSuccessful {
			attempt.ConnectedSuccessfully = &connectionSuccessful
			log.Printf("[INFO] Successfully connected to %s", targetAddress)
			if v.AnalyzeResponse(connectionDataString) {
				attempt.Finding = true
				attempt.Protocol = protocol
				log.Printf("[INFO] RDP service detected on %s", targetAddress)
			}
		} else {
			log.Printf("[INFO] Failed to connect to %s", targetAddress)
		}
		attempts = append(attempts, attempt)
	}
	return attempts, errors
}

// Function to check for VMware Horizon protocols (tries multiple protocols)
func checkVMwareProtocols(address string, timeout time.Duration) (bool, []byte, *string, *string) {
	// First try PCoIP protocol
	successPCoIP, dataPCoIP, errPCoIP := tryPCoIPProtocol(address, timeout/3)
	if successPCoIP && (dataPCoIP != nil) {
		// If we got a successful PCoIP response with data, return it
		protocol := "PCoIP"
		return true, dataPCoIP, &protocol, nil
	}

	// If PCoIP failed or returned no data, try Blast protocol
	successBlast, dataBlast, errBlast := tryBlastProtocol(address, timeout/3)
	if successBlast && (dataBlast != nil) {
		// If we got a successful Blast response with data, return it
		protocol := "Blast"
		return true, dataBlast, &protocol, nil
	}

	// If both protocol-specific checks failed, try generic VMware client identifier
	successGeneric, dataGeneric, errGeneric := tryGenericVMware(address, timeout/3)
	if successGeneric {
		protocol := "Generic"
		return true, dataGeneric, &protocol, nil
	}

	// If all checks failed, return the most relevant error
	if errPCoIP != nil {
		return false, nil, nil, errPCoIP
	} else if errBlast != nil {
		return false, nil, nil, errBlast
	} else {
		return false, nil, nil, errGeneric
	}
}

// Try PCoIP protocol
func tryPCoIPProtocol(address string, timeout time.Duration) (bool, []byte, *string) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting for PCoIP probe: %s", err)
		return false, nil, &errStr
	}
	defer conn.Close()

	// Set read/write timeout
	conn.SetDeadline(time.Now().Add(timeout))

	// PCoIP client handshake packet
	pcoipProbe := []byte{
		0x50, 0x43, 0x4f, 0x49, // "PCOI"
		0x50, 0x00, 0x01, 0x00, // "P" + version info
	}

	_, err = conn.Write(pcoipProbe)
	if err != nil {
		errStr := fmt.Sprintf("Error sending PCoIP probe: %s", err)
		return false, nil, &errStr
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "reset by peer") {
		errStr := fmt.Sprintf("Error reading PCoIP response: %s", err)
		return false, nil, &errStr
	}

	// Even if we got an EOF or connection reset, we still connected
	return true, buffer[:max(n, 0)], nil
}

// Try Blast protocol
func tryBlastProtocol(address string, timeout time.Duration) (bool, []byte, *string) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting for Blast probe: %s", err)
		return false, nil, &errStr
	}
	defer conn.Close()

	// Set read/write timeout
	conn.SetDeadline(time.Now().Add(timeout))

	// VMware Blast client handshake
	blastProbe := []byte{
		// Simplified Blast header
		0x56, 0x4d, 0x57, 0x42, // "VMWB" (VMware Blast)
		0x01, 0x00, 0x00, 0x00, // Version info
	}

	_, err = conn.Write(blastProbe)
	if err != nil {
		errStr := fmt.Sprintf("Error sending Blast probe: %s", err)
		return false, nil, &errStr
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "reset by peer") {
		errStr := fmt.Sprintf("Error reading Blast response: %s", err)
		return false, nil, &errStr
	}

	// Even if we got an EOF or connection reset, we still connected
	return true, buffer[:max(n, 0)], nil
}

// Try generic VMware client identifier
func tryGenericVMware(address string, timeout time.Duration) (bool, []byte, *string) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting for generic probe: %s", err)
		return false, nil, &errStr
	}
	defer conn.Close()

	// Set read/write timeout
	conn.SetDeadline(time.Now().Add(timeout))

	// Send a basic client request with VMware Horizon client header
	clientRequest := []byte("CONNECT VMware-Horizon\r\n\r\n")

	_, err = conn.Write(clientRequest)
	if err != nil {
		errStr := fmt.Sprintf("Error sending VMware Horizon probe: %s", err)
		return false, nil, &errStr
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "reset by peer") {
		errStr := fmt.Sprintf("Error reading response: %s", err)
		return false, nil, &errStr
	}

	return true, buffer[:max(n, 0)], nil
}

func (v *VMwareHorizonLibrary) AnalyzeResponse(data string) bool {
	if len(data) == 0 {
		return false
	}

	// Binary protocol signatures
	binaryPatterns := []string{
		"\x50\x43\x4f\x49", // "PCOI" - PCoIP protocol
		"\x56\x4d\x57\x42", // "VMWB" - VMware Blast protocol
	}

	for _, pattern := range binaryPatterns {
		if strings.Contains(data, pattern) {
			log.Printf("[INFO] VMware Horizon protocol signature detected")
			return true
		}
	}

	// Text-based markers
	textMarkers := []string{
		"vmware",
		"horizon",
		"view-",
		"pcoip",
		"vmware-blast",
		"vmware-horizon",
	}
	dataLower := strings.ToLower(data)
	for _, marker := range textMarkers {
		if strings.Contains(dataLower, marker) {
			log.Printf("[INFO] VMware Horizon text marker detected in response")
			return true
		}
	}

	return false
}
