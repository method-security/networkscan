// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package db2

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

type DB2Plugin struct{}

const DB2 = "db2"

// DDM and DRDA constants
const (
	DDM_MAGIC   = 0xD0   // Magic byte for DDM messages
	EXCSAT      = 0x1041 // Exchange Server Attributes (client → server)
	EXCSATRD    = 0x1443 // EXCSAT Reply (server → client)
	EXTNAM      = 0x115E // External Name (server identification)
	SRVRLSLV    = 0x2454 // Server Release Level (version encoding)
	SRVNAM      = 0x2434 // Server Name (instance name)
	MGRLVLLS    = 0x1404 // Manager Level List
	MIN_DDM_LEN = 10     // Minimum DDM message length
)

// db2Metadata holds enriched metadata extracted from EXCSATRD response
type db2Metadata struct {
	ServerName string // DB2 instance name (from SRVNAM parameter)
	Version    string // DB2 version string (e.g., "11.5.6.0") - only if explicitly returned
	ServerType string // "DB2", "Derby", or "Informix"
}

// Version extraction regex patterns
var (
	// EXTNAM version extraction: "DB2/LINUXX8664 11.5.6.0" → "11.5.6.0"
	extnamVersionRegex = regexp.MustCompile(`(\d+\.\d+\.\d+(?:\.\d+)?)`)

	// SRVRLSLV decoding: "SQL11056" → "11.5.6"
	srvrlslvRegex = regexp.MustCompile(`^SQL(\d{2})(\d{2})(\d+)`)
)

// buildEXCSAT constructs a minimal EXCSAT message to initiate DRDA handshake.
//
// The EXCSAT message contains client attributes that the server can use to
// identify the connecting client. For fingerprinting, we send minimal required
// parameters to reduce message size and avoid unnecessary complexity.
//
// Message structure:
//
//	DDM Header (10 bytes):
//	  Length: 2 bytes (big-endian, total message length)
//	  Magic: 1 byte (0xD0)
//	  Format: 1 byte (0x01 = chained DSS, RQSDSS format)
//	  Codepoint: 2 bytes (0x1041 = EXCSAT)
//	  Correlation ID: 2 bytes (0x0001)
//	  Length2: 2 bytes (length - 6, per DRDA spec)
//
//	Parameters:
//	  EXTNAM (External Name): Client identification
//	    - Length: 2 bytes
//	    - Codepoint: 2 bytes (0x115E)
//	    - Data: ASCII string "networkscan"
//
// Returns:
//
//	[]byte: Properly formatted EXCSAT message ready to send
func buildEXCSAT() []byte {

	extnam := []byte("networkscan")

	extnameParamLen := uint16(2 + 2 + len(extnam))

	totalLen := uint16(10 + int(extnameParamLen))

	msg := make([]byte, 0, totalLen)

	msg = append(msg, byte(totalLen>>8), byte(totalLen))
	msg = append(msg, DDM_MAGIC)
	msg = append(msg, 0x01)
	msg = append(msg, byte(EXCSAT>>8&0xFF), byte(EXCSAT&0xFF))
	msg = append(msg, 0x00, 0x01)
	lengthParam := totalLen - 6
	msg = append(msg, byte(lengthParam>>8), byte(lengthParam))

	msg = append(msg, byte(extnameParamLen>>8), byte(extnameParamLen))
	msg = append(msg, byte(EXTNAM>>8&0xFF), byte(EXTNAM&0xFF))
	msg = append(msg, extnam...)

	return msg
}

// checkDDMResponse validates that the response is a valid DDM message structure.
//
// Validation checks:
//  1. Minimum length (10 bytes for DDM header)
//  2. Magic byte (0xD0 indicates DDM message)
//  3. Declared length matches actual response length
//  4. Codepoint matches expected value (0x1443 for EXCSATRD)
//
// Parameters:
//   - response: The raw response bytes from the DB2 server
//   - expectedCodepoint: The codepoint we expect (0x1443 for EXCSATRD)
//
// Returns:
//   - bool: true if response is valid DDM message
//   - error: nil if valid, error details if validation fails
func checkDDMResponse(response []byte, expectedCodepoint uint16) (bool, error) {

	if len(response) < MIN_DDM_LEN {
		return false, &utils.InvalidResponseErrorInfo{
			Service: DB2,
			Info:    fmt.Sprintf("response too short: got %d bytes, need at least %d", len(response), MIN_DDM_LEN),
		}
	}

	if response[2] != DDM_MAGIC {
		return false, &utils.InvalidResponseErrorInfo{
			Service: DB2,
			Info:    fmt.Sprintf("invalid DDM magic byte: expected 0x%02X, got 0x%02X", DDM_MAGIC, response[2]),
		}
	}

	declaredLen := binary.BigEndian.Uint16(response[0:2])
	if declaredLen < MIN_DDM_LEN || int(declaredLen) > len(response) {
		return false, &utils.InvalidResponseErrorInfo{
			Service: DB2,
			Info:    fmt.Sprintf("invalid message length: declared %d, actual %d", declaredLen, len(response)),
		}
	}

	codepoint := binary.BigEndian.Uint16(response[4:6])
	if codepoint != expectedCodepoint {
		return false, &utils.InvalidResponseErrorInfo{
			Service: DB2,
			Info:    fmt.Sprintf("unexpected codepoint: expected 0x%04X, got 0x%04X", expectedCodepoint, codepoint),
		}
	}

	return true, nil
}

// extractParameter extracts a parameter value from a DDM message by codepoint.
//
// DDM messages contain zero or more parameters, each with this structure:
//
//	Offset 0-1: Parameter length (big-endian, includes length field + codepoint)
//	Offset 2-3: Parameter codepoint (big-endian, identifies parameter type)
//	Offset 4+:  Parameter data
//
// Parameters:
//   - response: DDM message bytes (starting from first parameter, skip 10-byte header)
//   - targetCodepoint: The codepoint to search for (e.g., 0x115E for EXTNAM)
//
// Returns:
//   - []byte: Parameter data if found, nil otherwise
func extractParameter(response []byte, targetCodepoint uint16) []byte {

	offset := 10
	responseLen := len(response)

	for offset+4 <= responseLen {

		paramLen := binary.BigEndian.Uint16(response[offset : offset+2])

		paramCodepoint := binary.BigEndian.Uint16(response[offset+2 : offset+4])

		if paramCodepoint == targetCodepoint {

			dataStart := offset + 4
			dataEnd := offset + int(paramLen)

			if dataEnd > responseLen {
				return nil
			}

			return response[dataStart:dataEnd]
		}

		offset += int(paramLen)

		if paramLen < 4 {
			break
		}
	}

	return nil
}

// extractEXTNAM extracts the EXTNAM (External Name) parameter from EXCSATRD response.
//
// EXTNAM contains a human-readable server identification string, such as:
//   - "DB2/LINUXX8664 11.5.6.0" (DB2 on Linux x86-64, version 11.5.6.0)
//   - "Apache Derby Network Server" (Apache Derby)
//   - "Informix Dynamic Server" (IBM Informix)
//
// This is the primary method for identifying the database product and version.
//
// Parameters:
//   - response: EXCSATRD response bytes
//
// Returns:
//   - string: EXTNAM value if found, empty string otherwise
func extractEXTNAM(response []byte) string {
	data := extractParameter(response, EXTNAM)
	if data == nil {
		return ""
	}

	return string(data)
}

// extractSRVRLSLV extracts the SRVRLSLV (Server Release Level) parameter.
//
// SRVRLSLV contains an encoded version string in format "SQLvvrrm" where:
//
//	vv = Major version (2 digits)
//	rr = Minor version (2 digits)
//	m  = Modification level (1+ digits)
//
// Examples:
//
//	"SQL11056" → 11.5.6
//	"SQL10050" → 10.5.0
//	"SQL09074" → 9.7.4
//
// Parameters:
//   - response: EXCSATRD response bytes
//
// Returns:
//   - string: SRVRLSLV value if found, empty string otherwise
func extractSRVRLSLV(response []byte) string {
	data := extractParameter(response, SRVRLSLV)
	if data == nil {
		return ""
	}
	return string(data)
}

// extractServerName extracts the SRVNAM (Server Name) parameter.
//
// SRVNAM contains the DB2 instance name (e.g., "DB2", "SAMPLE", or custom name).
//
// Parameters:
//   - response: EXCSATRD response bytes
//
// Returns:
//   - string: SRVNAM value if found, empty string otherwise
func extractServerName(response []byte) string {
	data := extractParameter(response, SRVNAM)
	if data == nil {
		return ""
	}
	return string(data)
}

// parseEXTNAMVersion extracts version string from EXTNAM parameter.
//
// EXTNAM typically contains version in format "ProductName X.Y.Z.W" or "ProductName X.Y.Z".
// We use regex to extract the numeric version portion.
//
// Examples:
//
//	"DB2/LINUXX8664 11.5.6.0" → "11.5.6.0"
//	"DB2 for z/OS 12.1.0" → "12.1.0"
//
// Parameters:
//   - extnam: EXTNAM string value
//
// Returns:
//   - string: Extracted version, or empty string if not found
func parseEXTNAMVersion(extnam string) string {
	matches := extnamVersionRegex.FindStringSubmatch(extnam)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// decodeSRVRLSLV decodes the SRVRLSLV version encoding.
//
// Format: "SQLvvrrm" where vv=major, rr=minor, m=modification
//
// Examples:
//
//	"SQL11056" → "11.5.6"
//	"SQL10050" → "10.5.0"
//	"SQL09074" → "9.7.4"
//
// Parameters:
//   - srvrlslv: SRVRLSLV string value
//
// Returns:
//   - string: Decoded version, or empty string if format invalid
func decodeSRVRLSLV(srvrlslv string) string {
	matches := srvrlslvRegex.FindStringSubmatch(srvrlslv)
	if len(matches) >= 4 {
		// Convert to integers to remove leading zeros, then back to strings
		var major, minor, mod int
		_, _ = fmt.Sscanf(matches[1], "%d", &major)
		_, _ = fmt.Sscanf(matches[2], "%d", &minor)
		_, _ = fmt.Sscanf(matches[3], "%d", &mod)
		return fmt.Sprintf("%d.%d.%d", major, minor, mod)
	}
	return ""
}

// identifyServerType determines if the server is DB2, Derby, or Informix based on EXTNAM.
//
// Detection logic:
//   - If EXTNAM contains "DB2/" or "DB2 " → IBM DB2
//   - If EXTNAM contains "Derby" → Apache Derby
//   - If EXTNAM contains "Informix" → IBM Informix
//   - Otherwise → "unknown"
//
// Parameters:
//   - extnam: EXTNAM string value
//
// Returns:
//   - string: "DB2", "Derby", "Informix", or "unknown"
func identifyServerType(extnam string) string {
	extnameUpper := strings.ToUpper(extnam)

	if strings.Contains(extnameUpper, "DB2/") || strings.Contains(extnameUpper, "DB2 ") {
		return "DB2"
	}
	if strings.Contains(extnameUpper, "DERBY") {
		return "Derby"
	}
	if strings.Contains(extnameUpper, "INFORMIX") {
		return "Informix"
	}
	return "unknown"
}

// parseEXCSATRDMetadata extracts complete metadata from EXCSATRD response.
//
// Extraction priority for version:
//  1. EXTNAM parameter (most reliable, human-readable)
//  2. SRVRLSLV parameter (encoded, requires decoding)
//  3. Neither available → empty version (CPE will use "*")
//
// Parameters:
//   - response: EXCSATRD response bytes
//
// Returns:
//   - db2Metadata: Extracted metadata (ServerName, Version, ServerType)
func parseEXCSATRDMetadata(response []byte) db2Metadata {
	metadata := db2Metadata{
		ServerType: "unknown",
	}

	extnam := extractEXTNAM(response)
	if extnam != "" {

		metadata.ServerType = identifyServerType(extnam)

		version := parseEXTNAMVersion(extnam)
		if version != "" {
			metadata.Version = version
		}
	}

	if metadata.Version == "" {
		srvrlslv := extractSRVRLSLV(response)
		if srvrlslv != "" {
			version := decodeSRVRLSLV(srvrlslv)
			if version != "" {
				metadata.Version = version
			}
		}
	}

	serverName := extractServerName(response)
	if serverName != "" {
		metadata.ServerName = serverName
	}

	return metadata
}

// DetectDB2 performs DB2 fingerprinting using DRDA handshake.
//
// Detection flow:
//  1. Build and send EXCSAT message
//  2. Receive EXCSATRD response from server
//  3. Validate DDM structure and EXCSATRD codepoint
//  4. Extract metadata (server type, version, instance name)
//  5. Return detection result
//
// Parameters:
//   - conn: Network connection to the database server
//   - timeout: Timeout duration for network operations
//
// Returns:
//   - db2Metadata: Extracted metadata (if detected)
//   - bool: true if DRDA server detected (not necessarily DB2)
//   - error: Error details if detection failed
func DetectDB2(conn net.Conn, timeout time.Duration) (db2Metadata, bool, error) {

	excsat := buildEXCSAT()

	response, err := utils.SendRecv(conn, excsat, timeout)
	if err != nil {
		return db2Metadata{}, false, err
	}

	if len(response) == 0 {
		return db2Metadata{}, false, &utils.InvalidResponseError{Service: DB2}
	}

	isValid, err := checkDDMResponse(response, EXCSATRD)
	if !isValid {
		return db2Metadata{}, false, err
	}

	metadata := parseEXCSATRDMetadata(response)

	return metadata, true, nil
}

// buildDB2CPE constructs a CPE (Common Platform Enumeration) string for DB2.
//
// CPE format: cpe:2.3:a:ibm:db2:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases.
//
// Parameters:
//   - version: DB2 version string (e.g., "11.5.6.0"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildDB2CPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:ibm:db2:%s:*:*:*:*:*:*:*", version)
}
func (p *DB2Plugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	metadata, detected, err := DetectDB2(conn, timeout)
	if detected && err != nil {

		return nil, nil
	} else if detected && err == nil {

		if metadata.ServerType != "DB2" {

			return nil, nil
		}

		payload := probe.ServiceDB2{
			ServerName: metadata.ServerName,
		}

		cpe := buildDB2CPE(metadata.Version)
		payload.CPEs = []string{cpe}

		return probe.Result(target, payload, false, metadata.Version, probe.TCP), nil
	}

	return nil, err
}
func (p *DB2Plugin) PortPriority(port uint16) bool {
	return port == 50000 || port == 446
}
func (p *DB2Plugin) Name() string {
	return DB2
}
func (p *DB2Plugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *DB2Plugin) Priority() int {
	return 120
}

var defaultDB2PluginPorts = probe.Ports((&DB2Plugin{}).PortPriority)

func (p *DB2Plugin) DefaultPorts() []int { return defaultDB2PluginPorts }
func (p *DB2Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
