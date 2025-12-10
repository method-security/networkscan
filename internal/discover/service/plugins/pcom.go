// Package plugins provides Unitronics PCOM service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type PcomFingerprinter struct{}

func (PcomFingerprinter) Name() string { return "pcom" }

func (PcomFingerprinter) DefaultPorts() []int { return []int{20256} }

// Precompiled regexes for optional metadata extraction.
var (
	reModel     = regexp.MustCompile(`Model:\s*([^\r\n]+)`)
	rePlcName   = regexp.MustCompile(`PLC Name:\s*([^\r\n]+)`)
	reOSVersion = regexp.MustCompile(`OS Version:\s*([^\r\n]+)`)
)

// Detect attempts to identify a Unitronics PCOM service using progressive detection.
func (PcomFingerprinter) Detect(
	ctx context.Context,
	ip net.IP,
	port int,
	host string,
	timeout int,
) (*discoverfern.ServiceDetails, error) {
	timeoutDur := time.Duration(timeout) * time.Second

	// Try multiple PCOM detection strategies in order of likelihood
	strategies := []func(context.Context, net.IP, int, string, time.Duration) (*discoverfern.ServiceDetails, error){
		tryPcomASCIIVariants,
		tryPcomBinaryVariants,
		tryPcomTCPHeader,
		tryPcomConnectionTest,
	}

	for _, strategy := range strategies {
		if result, err := strategy(ctx, ip, port, host, timeoutDur); err == nil && result != nil {
			return result, nil
		}
	}

	return nil, fmt.Errorf("no PCOM service detected")
}

// tryPcomASCIIVariants tests multiple ASCII PCOM command variants
func tryPcomASCIIVariants(ctx context.Context, ip net.IP, port int, host string, timeout time.Duration) (*discoverfern.ServiceDetails, error) {
	asciiCommands := [][]byte{
		[]byte("/01ID00\r"), // Standard ID request
		[]byte("/00ID01\r"), // Unit 0 ID request
		[]byte("/01UG00\r"), // Get Unit ID
		[]byte("/00UG01\r"), // Get Unit ID (unit 0)
		[]byte("/01GF00\r"), // Get PLC Version
		[]byte("/00GF01\r"), // Get PLC Version (unit 0)
	}

	for _, cmd := range asciiCommands {
		if result, err := testPcomCommand(ctx, ip, port, host, timeout, cmd); err == nil {
			return result, nil
		}
	}

	return nil, fmt.Errorf("no ASCII PCOM response")
}

// tryPcomBinaryVariants tests multiple binary PCOM command variants
func tryPcomBinaryVariants(ctx context.Context, ip net.IP, port int, host string, timeout time.Duration) (*discoverfern.ServiceDetails, error) {
	binaryCommands := [][]byte{
		// Get PLC Name (0x0C) with PCOM/TCP header
		{0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00},
		// Read Memory (0x01) with PCOM/TCP header
		{0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00},
		// Simple binary probe without TCP header
		{0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00},
		{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00},
	}

	for _, cmd := range binaryCommands {
		if result, err := testPcomCommand(ctx, ip, port, host, timeout, cmd); err == nil {
			return result, nil
		}
	}

	return nil, fmt.Errorf("no binary PCOM response")
}

// tryPcomTCPHeader tests PCOM/TCP header format
func tryPcomTCPHeader(ctx context.Context, ip net.IP, port int, host string, timeout time.Duration) (*discoverfern.ServiceDetails, error) {
	tcpHeaderCommands := [][]byte{
		{0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00},
		{0x12, 0x34, 0x00, 0x00, 0x00, 0x08, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00},
		{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x0C, 0x0D, 0x00},
	}

	for _, cmd := range tcpHeaderCommands {
		if result, err := testPcomCommand(ctx, ip, port, host, timeout, cmd); err == nil {
			return result, nil
		}
	}

	return nil, fmt.Errorf("no PCOM/TCP response")
}

// tryPcomConnectionTest performs a basic connection test
func tryPcomConnectionTest(ctx context.Context, ip net.IP, port int, host string, timeout time.Duration) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1024)

	// Try reading with a short timeout
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := conn.Read(buffer)

	if n > 0 {
		response := string(buffer[:n])
		if !isFalsePositive(response, buffer[:n]) {
			if port == 20256 && hasValidPcomIndicators(response, buffer[:n]) {
				return createBasicPcomService(ip, port, host), nil
			}
		}
	} else {
		// No immediate response, but successful connection on port 20256 might indicate PCOM
		// Only accept empty responses as PCOM indicators on the default PCOM port
		if port == 20256 {
			return createBasicPcomService(ip, port, host), nil
		}
	}

	return nil, fmt.Errorf("no PCOM indicators found")
}

// testPcomCommand tests a specific PCOM command and analyzes the response
func testPcomCommand(ctx context.Context, ip net.IP, port int, host string, timeout time.Duration, command []byte) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send command
	if _, err := conn.Write(command); err != nil {
		return nil, err
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	response := string(buffer[:n])

	// Check for false positives first
	if isFalsePositive(response, buffer[:n]) {
		return nil, fmt.Errorf("detected non-PCOM service")
	}

	// Analyze response for PCOM patterns
	if isPcomResponse(response, buffer[:n]) {
		return parsePcomResponse(response, ip, port, host)
	}

	return nil, fmt.Errorf("no valid PCOM response")
}

// isPcomResponse checks if response matches PCOM protocol patterns
func isPcomResponse(response string, rawResponse []byte) bool {
	// ASCII PCOM response pattern: /A<data><CR>
	if len(response) >= 2 && response[0] == '/' && response[1] == 'A' {
		return true
	}

	// Binary PCOM response patterns
	if len(rawResponse) >= 4 && isPcomBinaryResponse(rawResponse) {
		return true
	}

	// Specific binary patterns that indicate PCOM (excluding empty response check)
	if hasValidPcomIndicators(response, rawResponse) {
		return true
	}

	return false
}

// All the helper functions from the original (parsePcomResponse, isFalsePositive, etc.)
func parsePcomResponse(response string, ip net.IP, port int, host string) (*discoverfern.ServiceDetails, error) {
	metadata := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypePcom,
	}

	if len(response) > 3 && response[0] == '/' && response[1] == 'A' {
		dataSection := response[2 : len(response)-1]

		pcomInfo := &protocol.PcomServerInfo{}
		extracted := false

		if match := reModel.FindStringSubmatch(response); len(match) > 1 {
			pcomInfo.PlcModel = &match[1]
			extracted = true
		}

		if match := rePlcName.FindStringSubmatch(response); len(match) > 1 {
			pcomInfo.PlcName = &match[1]
			extracted = true
		}

		if match := reOSVersion.FindStringSubmatch(response); len(match) > 1 {
			pcomInfo.FirmwareVersion = &match[1]
			extracted = true
		}

		if len(dataSection) >= 8 {
			modelCode := dataSection[:2]
			if modelName := mapModelCode(modelCode); modelName != "" {
				pcomInfo.PlcModel = &modelName
				extracted = true
			}

			if len(dataSection) > 4 {
				version := dataSection[2:6]
				pcomInfo.Version = &version
				extracted = true
			}
		}

		if extracted {
			metadata.Metadata = discoverfern.NewServiceMetadataFromPcom(pcomInfo)
		}
	}

	return metadata, nil
}

func isPcomBinaryResponse(response []byte) bool {
	if len(response) < 4 {
		return false
	}

	return (response[0] == 0x2F && response[1] == 0x41) ||
		(response[0] == 0x00 && response[1] == 0x00) ||
		(len(response) >= 6 && response[4] == 0x81)
}

func createBasicPcomService(ip net.IP, port int, host string) *discoverfern.ServiceDetails {
	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypePcom,
	}
}

func mapModelCode(code string) string {
	modelMap := map[string]string{
		"01": "Vision 120", "02": "Vision 230", "03": "Vision 280", "04": "Vision 290",
		"05": "Vision 350", "06": "Vision 430", "07": "Vision 530", "08": "Vision 570",
		"09": "Vision 1040", "0A": "Vision 1210", "0B": "Samba 35", "0C": "Samba 43",
		"0D": "Jazz 2", "0E": "M90", "0F": "M91", "10": "UniStream 5",
		"11": "UniStream 7", "12": "UniStream 10", "13": "UniStream 15",
	}

	if name, exists := modelMap[code]; exists {
		return name
	}
	return ""
}

func isFalsePositive(response string, rawResponse []byte) bool {
	if len(response) == 0 && len(rawResponse) == 0 {
		return false
	}

	// MySQL server errors
	if contains(response, "Host ") && contains(response, "is not allowed to connect to this MySQL server") {
		return true
	}
	if contains(response, "mysql_native_password") || contains(response, "Mysql Version:") {
		return true
	}

	// HTTP responses
	if contains(response, "HTTP/1.") && (contains(response, "400") || contains(response, "404") || contains(response, "500") || contains(response, "408") || contains(response, "200")) {
		return true
	}
	if contains(response, "Server: nginx") || contains(response, "Server: Apache") || contains(response, "Server: Tomcat") || contains(response, "Server: Tengine") {
		return true
	}

	// HTML content
	if contains(response, "<html>") || contains(response, "<!DOCTYPE") || contains(response, "<title>") {
		return true
	}

	// SSH, FTP, SMTP, Telnet
	if contains(response, "SSH-2.0-") || (contains(response, "220 ") && contains(response, "FTP server")) {
		return true
	}
	if contains(response, "220 ") && contains(response, "SMTP") {
		return true
	}
	if contains(response, "Telnet") || contains(response, "connection() already keep alive") {
		return true
	}

	// TLS/SSL responses (binary)
	if len(rawResponse) >= 3 {
		// TLS Alert: 0x15 0x03 0x01-0x04
		if rawResponse[0] == 0x15 && rawResponse[1] == 0x03 {
			return true
		}
		// TLS Handshake: 0x16 0x03 0x01-0x04
		if rawResponse[0] == 0x16 && rawResponse[1] == 0x03 {
			return true
		}
		// TLS Change Cipher: 0x14 0x03
		if rawResponse[0] == 0x14 && rawResponse[1] == 0x03 {
			return true
		}
		// TLS Application Data: 0x17 0x03
		if rawResponse[0] == 0x17 && rawResponse[1] == 0x03 {
			return true
		}
	}

	// Other false positives
	if contains(response, "Bad Request") || contains(response, "Internal Server Error") {
		return true
	}

	if len(response) > 8 && response[:4] == "HTTP" {
		return true
	}

	return false
}

func hasValidPcomIndicators(response string, binaryResponse []byte) bool {
	// NOTE: Empty response check moved to caller context where port is available
	// Empty responses should ONLY be considered valid PCOM indicators on port 20256

	// Check for specific binary patterns
	if len(binaryResponse) >= 6 {
		if (binaryResponse[0] == 0x02 && binaryResponse[1] == 0x09) ||
			(binaryResponse[0] == 0x00 && binaryResponse[1] == 0x5B) ||
			(binaryResponse[0] == 0x00 && binaryResponse[1] == 0x00) {
			return true
		}
	}

	// VMware authentication responses might still be on PCOM ports
	if contains(response, "VMware Authentication Daemon") {
		return true
	}

	// Short binary responses with non-printable characters
	if len(binaryResponse) > 0 && len(binaryResponse) < 50 {
		nonPrintableCount := 0
		for _, b := range binaryResponse {
			if b < 32 || b > 126 {
				nonPrintableCount++
			}
		}
		if float64(nonPrintableCount)/float64(len(binaryResponse)) > 0.5 {
			return true
		}
	}

	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			strings.Contains(strings.ToLower(s), strings.ToLower(substr)))
}
