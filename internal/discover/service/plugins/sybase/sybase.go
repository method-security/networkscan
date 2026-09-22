// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package sybase

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

// TDS Option Token Constants
const (
	VERSION         uint32 = 0
	ENCRYPTION      uint32 = 1
	INSTOPT         uint32 = 2
	THREADID        uint32 = 3
	MARS            uint32 = 4
	TRACEID         uint32 = 5
	FEDAUTHREQUIRED uint32 = 6
	NONCEOPT        uint32 = 7
	TERMINATOR      byte   = 0xFF
)

// Protocol constants
const (
	SYBASE       = "sybase"
	DEFAULT_PORT = 5000
)

// OptionToken represents a TDS option token from pre-login response
type OptionToken struct {
	PLOptionToken  uint32
	PLOffset       uint32
	PLOptionLength uint32
	PLOptionData   []byte
}

// Data holds version information extracted from Sybase ASE
type Data struct {
	Version string
}

// SybasePlugin implements the Plugin interface for Sybase ASE fingerprinting
type SybasePlugin struct{}

// Version extraction patterns
var (
	// Pattern 1: "Adaptive Server Enterprise/16.0 SP03" → "16.0.3"
	aseWithSP = regexp.MustCompile(`Adaptive Server Enterprise/(\d+)\.(\d+)\s+SP(\d+)`)

	// Pattern 2: "Adaptive Server Enterprise/15.7.0 SP138" → "15.7.138"
	aseFullWithSP = regexp.MustCompile(`Adaptive Server Enterprise/(\d+)\.(\d+)\.(\d+)\s+SP(\d+)`)

	// Pattern 3: "Adaptive Server Enterprise/16.0" → "16.0"
	aseMajorMinor = regexp.MustCompile(`Adaptive Server Enterprise/(\d+\.\d+)`)

	// Pattern 4: "Sybase SQL Server/12.5.4" → "12.5.4" (legacy format)
	legacySybase = regexp.MustCompile(`Sybase SQL Server/(\d+\.\d+\.\d+)`)
)

// PortPriority returns true if the port is the default Sybase ASE port (5000)
func (p *SybasePlugin) PortPriority(port uint16) bool {
	return port == DEFAULT_PORT
}

// Name returns the protocol name for Sybase ASE
func (p *SybasePlugin) Name() string {
	return SYBASE
}

// Type returns the protocol type (TCP)
func (p *SybasePlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}

// Priority returns the execution priority (145 = after MSSQL 143, before generic)
func (p *SybasePlugin) Priority() int {
	return 145
}

// Run executes the Sybase ASE fingerprinting logic
func (p *SybasePlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {

	data, detected, err := DetectSybase(conn, timeout)
	if !detected {
		return nil, err
	}

	version := data.Version
	cpe := buildSybaseCPE(version)

	payload := ServiceSybase{
		CPEs:    []string{cpe},
		Version: version,
	}

	return helpers.MetadataResult(target, payload, false, version, common.TransportTypeTcp), nil
}

// DetectSybase sends a TDS pre-login packet and validates the Sybase ASE response
func DetectSybase(conn net.Conn, timeout time.Duration) (Data, bool, error) {

	preLoginPacket := []byte{

		0x12,
		0x01,
		0x00, 0x58,
		0x00, 0x00,
		0x01,
		0x00,

		0x00,
		0x00, 0x1F,
		0x00, 0x06,

		0x01,
		0x00, 0x25,
		0x00, 0x01,

		0x02,
		0x00, 0x26,
		0x00, 0x01,

		0x03,
		0x00, 0x27,
		0x00, 0x04,

		0x04,
		0x00, 0x2B,
		0x00, 0x01,

		0x05,
		0x00, 0x2C,
		0x00, 0x24,

		0xFF,

		0x11, 0x09, 0x00, 0x01, 0x00, 0x00,
		0x00,
		0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00,

		0xF9, 0xB8, 0xCB, 0x5C, 0x94, 0x6B, 0x89, 0x1F,
		0xD9, 0xAA, 0x3C, 0x13, 0x4B, 0xD0, 0x7B, 0x88,
		0x03, 0x5C, 0x32, 0x21, 0x24, 0xA2, 0x81, 0x86,
		0x37, 0xCF, 0x62, 0x39, 0x4A, 0x46, 0x2C, 0xC6,
		0x00, 0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, preLoginPacket, timeout)
	if err != nil {
		return Data{}, false, err
	}

	if len(response) == 0 {
		return Data{}, false, errors.New("service unavailable")
	}

	if err := validateTDSResponse(response); err != nil {
		return Data{}, false, err
	}

	optionTokens, err := parseTDSOptionTokens(response)
	if err != nil {
		return Data{}, false, err
	}

	version, isSybase := extractVersion(optionTokens)
	if !isSybase {

		return Data{}, false, nil
	}

	return Data{Version: version}, true, nil
}

// validateTDSResponse validates the TDS packet header structure
func validateTDSResponse(response []byte) error {

	if len(response) < 8 {
		return fmt.Errorf("%s: invalid response: %s", SYBASE,
			"response too short for TDS packet header")

	}

	if response[0] != 0x04 {
		return fmt.Errorf("%s: invalid response: %s", SYBASE,
			"packet type should be 0x04 (tabular response)")

	}

	if response[1] != 0x01 {
		return fmt.Errorf("%s: invalid response: %s", SYBASE,
			"packet status should be 0x01 (EOM)")

	}

	packetLength := int(binary.BigEndian.Uint16(response[2:4]))
	if len(response) != packetLength {
		return fmt.Errorf("%s: invalid response: %s", SYBASE,
			fmt.Sprintf("packet length mismatch: declared %d, actual %d", packetLength, len(response)))

	}

	if response[4] != 0x00 || response[5] != 0x00 {
		return fmt.Errorf("%s: invalid response: %s", SYBASE,
			"SPID should be zero in pre-login response")

	}

	if response[6] != 0x01 {
		return fmt.Errorf("%s: invalid response: %s", SYBASE,
			"PacketID should be 1")

	}

	if response[7] != 0x00 {
		return fmt.Errorf("%s: invalid response: %s", SYBASE,
			"Window should be zero")

	}

	return nil
}

// parseTDSOptionTokens extracts option tokens from TDS response body
func parseTDSOptionTokens(response []byte) ([]OptionToken, error) {

	position := 8
	var optionTokens []OptionToken

	for position < len(response) && response[position] != TERMINATOR {

		if position+5 > len(response) {
			return nil, fmt.Errorf("%s: invalid response: %s", SYBASE,
				"truncated option token")

		}

		plOptionToken := uint32(response[position])
		plOffset := uint32(binary.BigEndian.Uint16(response[position+1 : position+3]))
		plOptionLength := uint32(binary.BigEndian.Uint16(response[position+3 : position+5]))

		// Extract option data
		var plOptionData []byte
		if plOptionLength > 0 {
			dataStart := 8 + plOffset
			dataEnd := dataStart + plOptionLength

			if dataEnd > uint32(len(response)) {
				return nil, fmt.Errorf("%s: invalid response: %s", SYBASE,
					"option token data extends beyond packet")

			}

			plOptionData = response[dataStart:dataEnd]
		}

		optionTokens = append(optionTokens, OptionToken{
			PLOptionToken:  plOptionToken,
			PLOffset:       plOffset,
			PLOptionLength: plOptionLength,
			PLOptionData:   plOptionData,
		})

		position += 5
	}

	if position >= len(response) || response[position] != TERMINATOR {
		return nil, fmt.Errorf("%s: invalid response: %s", SYBASE,
			"option token list not terminated by 0xFF")

	}

	if len(optionTokens) < 1 {
		return nil, fmt.Errorf("%s: invalid response: %s", SYBASE,
			"no option tokens found, VERSION is required")

	}

	return optionTokens, nil
}

// extractVersion extracts version string from option tokens and determines if it's Sybase
func extractVersion(optionTokens []OptionToken) (string, bool) {
	// Find VERSION option token (PLOptionToken = 0)
	var versionData []byte
	for _, token := range optionTokens {
		if token.PLOptionToken == VERSION {
			versionData = token.PLOptionData
			break
		}
	}

	if len(versionData) == 0 {
		return "", false
	}

	versionStr := string(versionData)

	isSybase := strings.Contains(versionStr, "Sybase") ||
		strings.Contains(versionStr, "Adaptive Server Enterprise") ||
		strings.Contains(versionStr, "Adaptive Server") ||
		strings.Contains(versionStr, "SAP ASE")

	if strings.Contains(versionStr, "Microsoft") {
		return "", false
	}

	if !isSybase {
		return "", false
	}

	version := parseVersionString(versionStr)

	return version, true
}

// parseVersionString extracts semantic version from Sybase version string
func parseVersionString(versionStr string) string {

	if matches := aseWithSP.FindStringSubmatch(versionStr); len(matches) >= 4 {
		major := matches[1]
		minor := matches[2]
		spStr := matches[3]

		if spNum, err := strconv.Atoi(spStr); err == nil {
			return fmt.Sprintf("%s.%s.%d", major, minor, spNum)
		}

		return fmt.Sprintf("%s.%s.%s", major, minor, spStr)
	}

	if matches := aseFullWithSP.FindStringSubmatch(versionStr); len(matches) >= 5 {
		major := matches[1]
		minor := matches[2]

		spStr := matches[4]

		if spNum, err := strconv.Atoi(spStr); err == nil {
			return fmt.Sprintf("%s.%s.%d", major, minor, spNum)
		}

		return fmt.Sprintf("%s.%s.%s", major, minor, spStr)
	}

	if matches := aseMajorMinor.FindStringSubmatch(versionStr); len(matches) >= 2 {
		return matches[1]
	}

	if matches := legacySybase.FindStringSubmatch(versionStr); len(matches) >= 2 {
		return matches[1]
	}

	return ""
}

// buildSybaseCPE generates a CPE (Common Platform Enumeration) string for Sybase ASE
//
// Uses wildcard version ("*") when version is unknown to match Wappalyzer/RMI/FTP plugin
// behavior and enable asset inventory use cases even without precise version information.
//
// CPE format: cpe:2.3:a:sap:adaptive_server_enterprise:{version}:*:*:*:*:*:*:*
//
// Parameters:
//   - version: Version string (e.g., "16.0.3"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildSybaseCPE(version string) string {

	version = strings.TrimSpace(version)

	if version == "" {
		version = "*"
	}

	cpeTemplate := "cpe:2.3:a:sap:adaptive_server_enterprise:%s:*:*:*:*:*:*:*"

	return fmt.Sprintf(cpeTemplate, version)
}

var defaultSybasePluginPorts = helpers.Ports((&SybasePlugin{}).PortPriority)

func (p *SybasePlugin) DefaultPorts() []int { return defaultSybasePluginPorts }
func (p *SybasePlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
