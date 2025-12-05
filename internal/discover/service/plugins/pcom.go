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
// These are *best effort* and only used if the device returns human-readable info.
var (
	reModel           = regexp.MustCompile(`Model:\s*([^\r\n]+)`)
	rePlcName         = regexp.MustCompile(`PLC Name:\s*([^\r\n]+)`)
	reHardwareVersion = regexp.MustCompile(`Hardware Version:\s*([^\r\n]+)`)
	reOSVersion       = regexp.MustCompile(`OS Version:\s*([^\r\n]+)`)
	reOSBuild         = regexp.MustCompile(`OS Build:\s*([^\r\n]+)`)
	reUniqueID        = regexp.MustCompile(`PLC Unique ID:\s*([^\r\n]+)`)
)

// Detect attempts to identify a Unitronics PCOM service and extract basic info.
func (PcomFingerprinter) Detect(
	ctx context.Context,
	ip net.IP,
	port int,
	host string,
	timeout int,
) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	timeoutDur := time.Duration(timeout) * time.Second

	dialer := net.Dialer{
		Timeout: timeoutDur,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// Note: We'll close this initial connection and create fresh ones for each request

	if err := conn.SetDeadline(time.Now().Add(timeoutDur)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// PCOM over TCP requires a 6-byte header followed by the PCOM ASCII command
	// Try unit IDs in order of frequency based on Shodan data
	requests := [][]byte{
		buildPcomTCPRequest("ID", 0x01), // Unit 1 (most common in Shodan)
		buildPcomTCPRequest("ID", 0x00), // Unit 0 (default)
		buildPcomTCPRequest("ID", 0x03), // Unit 3
		buildPcomTCPRequest("ID", 0x0A), // Unit 10
	}

	buf := make([]byte, 2048)
	var (
		lastErr error
		payload []byte
	)

	// Close the initial connection since we'll create fresh ones for each request
	_ = conn.Close()

	for _, req := range requests {
		// Create a fresh connection for each request
		requestConn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = err
			continue
		}

		// Set deadline for both read and write operations
		if err := requestConn.SetDeadline(time.Now().Add(timeoutDur)); err != nil {
			lastErr = err
			_ = requestConn.Close()
			continue
		}

		// Send the request
		if _, err := requestConn.Write(req); err != nil {
			lastErr = err
			_ = requestConn.Close()
			continue
		}

		// Read response - try multiple reads for slow responses
		var totalRead int
		for attempts := 0; attempts < 3 && totalRead < len(buf)-1; attempts++ {
			n, err := requestConn.Read(buf[totalRead:])
			if err != nil {
				if attempts == 0 {
					lastErr = err
				}
				break
			}
			if n > 0 {
				totalRead += n
				// If we got data, try once more to see if there's more
				if attempts == 0 {
					time.Sleep(100 * time.Millisecond)
				}
			} else {
				break
			}
		}

		_ = requestConn.Close() // Always close after each attempt

		if totalRead == 0 {
			lastErr = fmt.Errorf("no response received")
			continue
		}

		resp := buf[:totalRead]

		// Quick reject for TLS/HTTPS endpoints.
		if looksLikeTLS(resp) {
			lastErr = fmt.Errorf("remote appears to speak TLS, not PCOM")
			continue
		}

		// SIMPLE DETECTION: Just look for PCOM in the response
		respStr := sanitizeASCII(resp)
		if strings.Contains(strings.ToUpper(respStr), "PCOM") {
			payload = resp
			break
		}

		// AGGRESSIVE DETECTION: If we're on port 20256, try to detect PCOM more liberally
		if port == 20256 {
			// Check for any response that could be PCOM
			if totalRead > 0 && !looksLikeTLS(resp) {
				// Look for PCOM indicators in any response on port 20256
				if strings.Contains(strings.ToLower(respStr), "pcom") ||
					strings.Contains(strings.ToLower(respStr), "unitronics") ||
					strings.Contains(strings.ToLower(respStr), "vision") ||
					strings.Contains(respStr, "/A") || // PCOM response format
					(len(resp) > 6 && isValidASCII(resp)) { // Any substantial ASCII response
					payload = resp
					break
				}
			}
		}

		// Try to parse PCOM TCP response (6-byte header + payload)
		if tcpPayload, ok := parsePcomTCPResponse(resp); ok {
			payload = tcpPayload
			break
		}

		// Try to parse a framed PCOM response (STX .. ETX, checksum).
		if framePayload, ok := parsePcomFrame(resp); ok {
			payload = framePayload
			break
		}

		// Some devices might respond in plain ASCII without strict framing.
		if isLikelyPcom(resp) {
			payload = resp
			break
		}

		lastErr = fmt.Errorf("response did not look like PCOM: %q", sanitizeASCII(resp))
	}

	if payload == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no valid PCOM response")
	}

	// Convert payload to a readable string for pattern matching / extraction.
	payloadStr := sanitizeASCII(payload)

	// Optional metadata extraction (best-effort).
	plcModel := firstMatchPtr(reModel, payloadStr)
	plcName := firstMatchPtr(rePlcName, payloadStr)
	hwVersion := firstMatchPtr(reHardwareVersion, payloadStr)
	osVersion := firstMatchPtr(reOSVersion, payloadStr)
	osBuild := firstMatchPtr(reOSBuild, payloadStr)
	_ = hwVersion // currently unused, but kept in case you want to add it to metadata later.
	uniqueID := firstMatchPtr(reUniqueID, payloadStr)
	_ = uniqueID // same as above.

	var firmwareVersion *string
	if osVersion != nil && osBuild != nil {
		v := *osVersion + " Build " + *osBuild
		firmwareVersion = &v
	} else if osVersion != nil {
		firmwareVersion = osVersion
	}

	versionStr := "PCOM"
	version := &versionStr

	metadata := &protocol.PcomServerInfo{
		Version:         version,
		PlcModel:        plcModel,
		PlcName:         plcName,
		FirmwareVersion: firmwareVersion,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypePcom,
		Version:   version,
		Metadata:  discoverfern.NewServiceMetadataFromPcom(metadata),
	}

	return result, nil
}

// buildPcomTcpRequest builds a proper PCOM TCP request with 6-byte header + ASCII command
// TCP Header format:
// Bytes 0-1: Transaction ID (2 bytes)
// Byte 2: Protocol selector (101 for ASCII)
// Byte 3: Reserved (0)
// Bytes 4-5: Payload length (2 bytes, big endian)
func buildPcomTCPRequest(command string, unitID byte) []byte {
	// Build the PCOM ASCII command: /UUCC<checksum>\r
	unitStr := fmt.Sprintf("%02d", unitID)

	// Build command without checksum first
	commandPart := fmt.Sprintf("/%s%s", unitStr, command)

	// Calculate ASCII checksum (sum of bytes, take low byte, 2's complement)
	var sum byte
	for _, c := range commandPart {
		sum += byte(c)
	}
	checksum := (^sum) + 1 // 2's complement

	// Build complete payload with checksum
	payload := fmt.Sprintf("%s%02X\r", commandPart, checksum)

	// Build 6-byte TCP header
	transactionID := uint16(0x1234) // Random transaction ID
	protocol := byte(101)           // 101 = ASCII protocol
	reserved := byte(0)
	payloadLen := uint16(len(payload))

	header := make([]byte, 6)
	header[0] = byte(transactionID & 0xFF) // Transaction ID low byte (little-endian)
	header[1] = byte(transactionID >> 8)   // Transaction ID high byte
	header[2] = protocol                   // Protocol selector
	header[3] = reserved                   // Reserved
	header[4] = byte(payloadLen & 0xFF)    // Payload length low byte (little-endian)
	header[5] = byte(payloadLen >> 8)      // Payload length high byte

	// Combine header + payload
	request := append(header, []byte(payload)...)
	return request
}

// parsePcomTcpResponse parses a PCOM TCP response (6-byte header + payload)
// Returns the payload portion if valid, false otherwise
func parsePcomTCPResponse(b []byte) ([]byte, bool) {
	if len(b) < 6 {
		return nil, false
	}

	// Parse 6-byte header
	// Bytes 0-1: Transaction ID (little-endian)
	// Byte 2: Protocol selector (101 for ASCII, 102 for binary)
	// Byte 3: Reserved
	// Bytes 4-5: Payload length (little-endian)

	protocol := b[2]
	payloadLen := uint16(b[4]) | (uint16(b[5]) << 8) // Little-endian

	// Check if protocol selector looks valid (101 or 102)
	if protocol != 101 && protocol != 102 {
		return nil, false
	}

	// Check if we have enough data for the claimed payload length
	if len(b) < 6+int(payloadLen) {
		return nil, false
	}

	// Extract payload
	payload := b[6 : 6+payloadLen]

	// For ASCII responses, they should start with /A
	if protocol == 101 && len(payload) >= 2 && payload[0] == '/' && payload[1] == 'A' {
		return payload, true
	}

	// For binary responses or other valid patterns
	if protocol == 102 || len(payload) > 0 {
		return payload, true
	}

	return nil, false
}

// parsePcomFrame tries to find a PCOM-like frame in b:
//
//	STX (0x02) ... ETX (0x03) checksum [CR]
//
// It returns the payload between STX and ETX (excluding framing) if the XOR
// checksum matches. Otherwise it returns (nil, false).
func parsePcomFrame(b []byte) ([]byte, bool) {
	if len(b) < 5 {
		return nil, false
	}

	// Find STX.
	stx := -1
	for i, c := range b {
		if c == 0x02 {
			stx = i
			break
		}
	}
	if stx == -1 {
		return nil, false
	}

	// Find ETX after STX.
	etx := -1
	for j := stx + 1; j < len(b); j++ {
		if b[j] == 0x03 {
			etx = j
			break
		}
	}
	if etx == -1 {
		return nil, false
	}

	// Need at least one byte after ETX for checksum.
	if etx+1 >= len(b) {
		return nil, false
	}
	checksum := b[etx+1]

	// Verify XOR checksum from STX through ETX inclusive.
	var x byte
	for i := stx; i <= etx; i++ {
		x ^= b[i]
	}
	if x != checksum {
		return nil, false
	}

	// Payload is everything between STX and ETX (exclusive).
	return b[stx+1 : etx], true
}

// looksLikeTLS does a coarse check whether this is probably a TLS record.
// We don't need perfection here; just enough to avoid misclassifying HTTPS.
func looksLikeTLS(b []byte) bool {
	if len(b) < 3 {
		return false
	}

	// Valid TLS content types: 20, 21, 22, 23
	switch b[0] {
	case 0x14, 0x15, 0x16, 0x17:
	default:
		return false
	}

	// TLS major version is always 3 (0x03) for SSLv3/TLS1.0+.
	if b[1] != 0x03 {
		return false
	}

	return true
}

// isLikelyPcom does a heuristic check for PCOM-style data, used as a
// fallback when strict framing isn't present.
func isLikelyPcom(b []byte) bool {
	s := sanitizeASCII(b)
	sLower := strings.ToLower(s)

	// Check for Unitronics-related keywords
	if strings.Contains(sLower, "unitronics") ||
		strings.Contains(sLower, "pcom") ||
		strings.Contains(sLower, "vision") ||
		strings.Contains(sLower, "plc") ||
		strings.Contains(sLower, "samba") ||
		strings.Contains(sLower, "jazz") {
		return true
	}

	// Check for common PCOM model patterns (based on Shodan data)
	if strings.Contains(s, "V1") || strings.Contains(s, "V2") || strings.Contains(s, "V3") ||
		strings.Contains(s, "V4") || strings.Contains(s, "V5") || strings.Contains(s, "V6") ||
		strings.Contains(s, "V7") || strings.Contains(s, "M9") || strings.Contains(s, "Jazz") ||
		strings.Contains(s, "V570") || strings.Contains(s, "V700") || strings.Contains(s, "V130") {
		return true
	}

	// Some PCOM responses start with "/A" or "/I" etc.
	if len(b) >= 2 && b[0] == '/' && (b[1] == 'A' || b[1] == 'I' || b[1] == 'V') {
		return true
	}

	// Check for structured device information patterns from Shodan
	if strings.Contains(sLower, "model:") || strings.Contains(sLower, "version") ||
		strings.Contains(sLower, "hardware") || strings.Contains(sLower, "firmware") ||
		strings.Contains(sLower, "os version:") || strings.Contains(sLower, "os build:") ||
		strings.Contains(sLower, "plc name:") || strings.Contains(sLower, "unique id:") ||
		strings.Contains(sLower, "uid master:") {
		return true
	}

	// Check for hex-like responses that might be binary PCOM
	if len(b) >= 8 && (b[2] == 101 || b[2] == 102) { // Protocol selector bytes
		return true
	}

	// For aggressive detection: accept responses that look like structured data
	if len(b) > 10 && isValidASCII(b) {
		// Look for colon-separated structured data
		if strings.Count(s, ":") >= 2 && strings.Count(s, "\n") >= 1 {
			return true
		}
		// Or any response with multiple lines and alphanumeric content
		lines := strings.Split(s, "\n")
		if len(lines) >= 2 {
			alphanumCount := 0
			for _, c := range s {
				if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
					alphanumCount++
				}
			}
			if alphanumCount > len(s)/2 {
				return true
			}
		}
	}

	return false
}

// sanitizeASCII turns binary into a readable string, preserving basic ASCII,
// and replacing non-printables with '.'.
func sanitizeASCII(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if (c >= 32 && c <= 126) || c == '\r' || c == '\n' || c == '\t' {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

// firstMatchPtr returns a *string for the first matching group, or nil.
func firstMatchPtr(re *regexp.Regexp, s string) *string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return nil
	}
	v := strings.TrimSpace(m[1])
	if v == "" {
		return nil
	}
	return &v
}

// isValidASCII checks if the byte slice contains mostly printable ASCII characters
func isValidASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}

	printableCount := 0
	for _, c := range b {
		if (c >= 32 && c <= 126) || c == '\r' || c == '\n' || c == '\t' {
			printableCount++
		}
	}

	// At least 80% of characters should be printable ASCII
	return float64(printableCount)/float64(len(b)) >= 0.8
}
