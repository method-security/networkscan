package remoteaccess

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	addressfern "github.com/Method-Security/networkscan/generated/go/address"
)

type VMwareHorizonLibrary struct{}

func (v *VMwareHorizonLibrary) StandardPorts() []int {
	return []int{443, 8443, 4172, 22443}
}

func (v *VMwareHorizonLibrary) Name() *addressfern.AddressFingerprintResourceModule {
	return addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(addressfern.RemoteAccessModuleVmwarehorizon)
}

func (v *VMwareHorizonLibrary) TryProtocols(address string, timeout time.Duration) addressfern.TryProtocols {
	tryProtocolsFunction := addressfern.TryProtocols{
		ConnectionAttempt: false,
	}
	errs := []string{}

	// Check PCoIP protocol
	successPCoIP, dataPCoIP, errPCoIP := CheckPCoIPProtocol(address, timeout)
	if len(errPCoIP) > 0 {
		errs = append(errs, errPCoIP...)
	}
	if successPCoIP && (dataPCoIP != nil) {
		tryProtocolsFunction.ConnectionAttempt = true
		tryProtocolsFunction.Protocol = "PCoIP"
		tryProtocolsFunction.ConnectionData = dataPCoIP
		tryProtocolsFunction.Errors = errs
	}

	// Check Blast protocol
	successBlast, dataBlast, errBlast := CheckBlastProtocol(address, timeout)
	if len(errBlast) > 0 {
		errs = append(errs, errBlast...)
	}
	if successBlast && (dataBlast != nil) {
		tryProtocolsFunction.ConnectionAttempt = true
		tryProtocolsFunction.Protocol = "Blast"
		tryProtocolsFunction.ConnectionData = dataBlast
		tryProtocolsFunction.Errors = errs
	}

	return tryProtocolsFunction
}

func CheckPCoIPProtocol(address string, timeout time.Duration) (bool, *string, []string) {
	errs := []string{}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting for PCoIP probe: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// Set read/write timeout
	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		errStr := fmt.Sprintf("Error setting deadline: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// PCoIP client handshake packet
	pcoipProbe := []byte{
		0x50, 0x43, 0x4f, 0x49, // "PCOI"
		0x50, 0x00, 0x01, 0x00, // "P" + version info
	}

	_, err = conn.Write(pcoipProbe)
	if err != nil {
		errStr := fmt.Sprintf("Error sending PCoIP probe: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// Read response
	buffer := make([]byte, bufferSize)
	n, err := conn.Read(buffer)
	if err != nil {
		errStr := fmt.Sprintf("Error reading PCoIP response: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// Even if we got an EOF or connection reset, we still connected
	if n > 0 {
		responseData := string(buffer[:n])
		return true, &responseData, errs
	}

	err = conn.Close()
	if err != nil {
		errStr := fmt.Sprintf("Error closing connection: %s", err)
		errs = append(errs, errStr)
	}

	return true, nil, errs
}

func CheckBlastProtocol(address string, timeout time.Duration) (bool, *string, []string) {
	errs := []string{}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting for Blast probe: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// Set read/write timeout
	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		errStr := fmt.Sprintf("Error setting deadline: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// VMware Blast client handshake
	blastProbe := []byte{
		// Simplified Blast header
		0x56, 0x4d, 0x57, 0x42, // "VMWB" (VMware Blast)
		0x01, 0x00, 0x00, 0x00, // Version info
	}

	_, err = conn.Write(blastProbe)
	if err != nil {
		errStr := fmt.Sprintf("Error sending Blast probe: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// Read response
	buffer := make([]byte, bufferSize)
	n, err := conn.Read(buffer)
	if err != nil && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "reset by peer") {
		errStr := fmt.Sprintf("Error reading Blast response: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	// Even if we got an EOF or connection reset, we still connected
	if n > 0 {
		responseData := string(buffer[:n])
		return true, &responseData, errs
	}

	err = conn.Close()
	if err != nil {
		errStr := fmt.Sprintf("Error closing connection: %s", err)
		errs = append(errs, errStr)
	}
	return true, nil, errs
}

func (v *VMwareHorizonLibrary) AnalyzeResponse(data string) bool {
	if len(data) == 0 {
		return false
	}

	raw := []byte(data)

	// Binary protocol signatures
	binaryPatterns := [][]byte{
		{0x50, 0x43, 0x4f, 0x49}, // "PCOI" - PCoIP protocol
		{0x56, 0x4d, 0x57, 0x42}, // "VMWB" - VMware Blast protocol
	}

	for _, pattern := range binaryPatterns {
		if bytes.Contains(raw, pattern) {
			log.Printf("[INFO] VMware Horizon binary protocol signature detected: %x", pattern)
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

	dataLower := strings.ToLower(string(raw)) // Convert only once, after binary check
	for _, marker := range textMarkers {
		if strings.Contains(dataLower, marker) {
			log.Printf("[INFO] VMware Horizon text marker detected: %s", marker)
			return true
		}
	}

	return false
}
