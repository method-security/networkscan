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

var bufferSize = 4096

type CitrixGatewayLibrary struct{}

func (c *CitrixGatewayLibrary) Name() *addressfern.AddressFingerprintResourceModule {
	return addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(addressfern.RemoteAccessModuleCitrixgateway)
}

func (c *CitrixGatewayLibrary) StandardPorts() []int {
	return []int{1494, 2598, 443, 8443}
}

func (c *CitrixGatewayLibrary) TryProtocols(address string, timeout time.Duration) addressfern.TryProtocols {
	protocol := "ICA"
	errs := []string{}

	tryProtocolsFunction := addressfern.TryProtocols{
		ConnectionAttempt: false,
		Protocol:          protocol,
	}

	// Check ICA protocol (with first packet variation)
	successICA, dataICA, errICA := CheckICAProtocol(address, timeout)
	if len(errICA) > 0 {
		errs = append(errs, errICA...)
	}
	if successICA && (dataICA != nil) {
		tryProtocolsFunction.ConnectionAttempt = true
		tryProtocolsFunction.ConnectionData = dataICA
		tryProtocolsFunction.Errors = errs
	}

	// Check alternative ICA protocol (with more fields)
	successICA2, dataICA2, errICA2 := AnotherCheckICAProtocol(address, timeout)
	if len(errICA2) > 0 {
		errs = append(errs, errICA2...)
	}
	if successICA2 && (dataICA2 != nil) {
		tryProtocolsFunction.ConnectionAttempt = true
		tryProtocolsFunction.ConnectionData = dataICA2
		tryProtocolsFunction.Errors = errs
	}

	tryProtocolsFunction.Errors = errs
	return tryProtocolsFunction
}

// CheckICAProtocol tests for Citrix ICA protocol with first packet variation
func CheckICAProtocol(address string, timeout time.Duration) (bool, *string, []string) {
	errs := []string{}

	// Create dialer with appropriate timeout
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting for ICA check: %s", err)
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

	// Standard ICA client packet
	icaInitPacket1 := []byte{
		0x7f, 0x7f, 0x49, 0x43, 0x41, // ICA signature "..ICA"
		0x00, 0x01, 0x00, 0x00, 0x01, // Version info
		0x00, 0x00, 0x00, // Additional fields
	}

	// Try sending the first probe
	_, err = conn.Write(icaInitPacket1)
	if err != nil {
		errStr := fmt.Sprintf("Error sending ICA probe: %s", err)
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

	// Read response from first probe
	buffer := make([]byte, bufferSize)
	n, err := conn.Read(buffer)

	// If we got a successful read, return the data
	if err == nil && n > 0 {
		responseData := string(buffer[:n])
		return true, &responseData, errs
	}

	if err != nil {
		errStr := fmt.Sprintf("Error reading ICA response: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	err = conn.Close()
	if err != nil {
		errStr := fmt.Sprintf("Error closing connection: %s", err)
		errs = append(errs, errStr)
	}

	// We connected but got no useful data
	return true, nil, errs
}

// AnotherCheckICAProtocol tests for Citrix ICA protocol with second packet variation
func AnotherCheckICAProtocol(address string, timeout time.Duration) (bool, *string, []string) {
	errs := []string{}

	// Create dialer with appropriate timeout
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		errStr := fmt.Sprintf("Error connecting for second ICA probe: %s", err)
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

	// Alternative ICA client packet (with more fields)
	icaInitPacket2 := []byte{
		0x7f, 0x7f, 0x49, 0x43, 0x41, // ICA signature "..ICA"
		0x01, 0x00, 0x02, 0x00, 0x01, // Different version info
		0x00, 0x00, 0x00, 0x00, 0x00, // More fields
		0x00, 0x00, // Extra bytes sometimes needed
	}

	// Send the second probe
	_, err = conn.Write(icaInitPacket2)
	if err != nil {
		errStr := fmt.Sprintf("Error sending alternative ICA probe: %s", err)
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

	// Read response from second probe
	buffer := make([]byte, bufferSize)
	n, err := conn.Read(buffer)

	// If we got data from second probe
	if err == nil && n > 0 {
		responseData := string(buffer[:n])
		return true, &responseData, errs
	}

	if err != nil {
		errStr := fmt.Sprintf("Error reading from second ICA probe: %s", err)
		errs = append(errs, errStr)
		return false, nil, errs
	}

	err = conn.Close()
	if err != nil {
		errStr := fmt.Sprintf("Error closing connection: %s", err)
		errs = append(errs, errStr)
	}

	// We connected but got no useful data
	return true, nil, errs
}

func (c *CitrixGatewayLibrary) AnalyzeResponse(data string) bool {
	if len(data) == 0 {
		return false
	}

	raw := []byte(data)

	// Binary protocol signatures
	binaryPatterns := [][]byte{
		{0x01, 0x30, 0x01, 0x01},
		{0x01, 0x30, 0x01, 0x02},
		{0xC0, 0x01, 0x09, 0x01},
		{0x7F, 0x7F, 0x43},
	}

	for _, pattern := range binaryPatterns {
		if bytes.Contains(raw, pattern) {
			log.Printf("[INFO] Citrix binary protocol signature detected: %x", pattern)
			return true
		}
	}

	// Text-based markers
	textMarkers := []string{"citrix", "ica", "ctx_"}
	dataLower := strings.ToLower(string(raw)) // safe now
	for _, marker := range textMarkers {
		if strings.Contains(dataLower, marker) {
			log.Printf("[INFO] Citrix text marker detected: %s", marker)
			return true
		}
	}

	return false
}
