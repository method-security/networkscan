// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package mysql

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type MYSQLPlugin struct{}

const (
	// protocolVersion = 10
	// maxPacketLength = 1<<24 - 1
	MYSQL = "MySQL"
)

// Version detection regex patterns for MySQL-family servers
// Priority order: Aurora → MariaDB → Percona → MySQL
var (
	// Aurora MySQL: {mysql_major}.mysql_aurora.{aurora_version}
	auroraRegex = regexp.MustCompile(`(\d+\.\d+)\.mysql_aurora\.(\d+\.\d+\.\d+)`)

	// MariaDB: {major}.{minor}.{patch}-MariaDB{optional-suffix}
	// Note: Older versions have "5.5.5-" prefix (RPL_VERSION_HACK) which must be stripped
	mariadbRegex = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)-MariaDB`)

	// Percona Server: {base_mysql_version}-{percona_build}
	perconaRegex = regexp.MustCompile(`^(\d+\.\d+\.\d+-\d+)`)

	// MySQL (Oracle): {major}.{minor}.{patch}{optional-suffix}
	mysqlRegex = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)
)

// CPE vendor/product mappings for MySQL-family servers
// CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
var cpeTemplates = map[string]string{
	"mysql":   "cpe:2.3:a:oracle:mysql:%s:*:*:*:*:*:*:*",
	"mariadb": "cpe:2.3:a:mariadb:mariadb:%s:*:*:*:*:*:*:*",
	"percona": "cpe:2.3:a:percona:percona_server:%s:*:*:*:*:*:*:*",
	"aurora":  "cpe:2.3:a:amazon:aurora:%s:*:*:*:*:*:*:*",
}

// Run checks if the identified service is a MySQL (or MariaDB) server using
// two methods. Upon the connection of a client to a MySQL server it can return
// one of two responses. Either the server returns an initial handshake packet
// or an error message packet.
func (p *MYSQLPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	mysqlVersionStr, err := CheckInitialHandshakePacket(response)
	if err == nil {

		serverType, version := parseVersionString(mysqlVersionStr)

		cpe := buildMySQLCPE(serverType, version)

		payload := ServiceMySQL{
			PacketType:   "handshake",
			ErrorMessage: "",
			ErrorCode:    0,
			CPEs:         []string{cpe},
		}
		return helpers.MetadataResult(target, payload, false, mysqlVersionStr, common.TransportTypeTcp), nil
	}

	errorStr, errorCode, err := CheckErrorMessagePacket(response)
	if err == nil {
		payload := ServiceMySQL{
			PacketType:   "error",
			ErrorMessage: errorStr,
			ErrorCode:    errorCode,
		}
		return helpers.MetadataResult(target, payload, false, "", common.TransportTypeTcp), nil
	}
	return nil, nil
}
func (p *MYSQLPlugin) PortPriority(port uint16) bool {
	return port == 3306
}
func (p *MYSQLPlugin) Name() string {
	return MYSQL
}
func (p *MYSQLPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *MYSQLPlugin) Priority() int {
	return 133
}

// CheckErrorMessagePacket checks the response packet error message
func CheckErrorMessagePacket(response []byte) (string, int, error) {

	if len(response) < 8 {
		return "", 0, fmt.Errorf("%s: invalid response: %s", MYSQL,
			"packet is too small for an error message packet")

	}

	packetLength := int(
		uint32(
			response[0],
		) | uint32(
			response[1],
		)<<8 | uint32(
			response[2],
		)<<16 | uint32(
			response[3],
		)<<24,
	)
	actualResponseLength := len(response) - 4

	if packetLength != actualResponseLength {
		return "", 0, fmt.Errorf("%s: invalid response: %s", MYSQL,
			"packet length does not match length of the response from the server")

	}

	header := int(response[4])
	if header != 0xff {
		return "", 0, fmt.Errorf("%s: invalid response: %s", MYSQL,
			"packet has an invalid header for an error message packet")

	}

	errorCode := int(uint32(response[5]) | uint32(response[6])<<8)
	if errorCode < 1000 || errorCode > 2000 {
		return "", errorCode, fmt.Errorf("%s: invalid response: %s", MYSQL,
			"packet has an invalid error code")

	}

	errorStr, err := readEOFTerminatedASCIIString(response, 7)
	if err != nil {
		return "", errorCode, fmt.Errorf("%s: invalid response: %s", MYSQL, err.Error())
	}

	return errorStr, errorCode, nil
}

// CheckInitialHandshakePacket checks if the response received from the server
// matches the expected response for the MySQL service
func CheckInitialHandshakePacket(response []byte) (string, error) {

	if len(response) < 35 {
		return "", fmt.Errorf("%s: invalid response: %s", MYSQL,
			"packet length is too small for an initial handshake packet")

	}

	packetLength := int(
		uint32(
			response[0],
		) | uint32(
			response[1],
		)<<8 | uint32(
			response[2],
		)<<16 | uint32(
			response[3],
		)<<24,
	)
	version := int(response[4])

	if packetLength < 25 || packetLength > 4096 {
		return "", fmt.Errorf("%s: invalid response: %s", MYSQL,
			"packet length doesn't make sense for the MySQL handshake packet")

	}

	if version != 10 {
		return "", fmt.Errorf("%s: invalid response: %s", MYSQL,
			"packet has an invalid version")

	}

	mysqlVersionStr, position, err := readNullTerminatedASCIIString(response, 5)
	if err != nil {
		return "", fmt.Errorf("%s: invalid response: %s", MYSQL,
			"unable to read null-terminated ASCII version string, err: "+err.Error())

	}

	fillerPos := position + 13
	if fillerPos >= len(response) {
		return "", fmt.Errorf("%s: invalid response: %s", MYSQL,
			"buffer is too small to be a valid initial handshake packet")

	}

	if response[fillerPos] != 0x00 {
		return "", fmt.Errorf("%s: invalid response: %s", MYSQL,
			fmt.Sprintf(
				"expected filler byte at ths position to be zero got: %d",
				response[fillerPos],
			))

	}

	return mysqlVersionStr, nil
}

// parseVersionString extracts server type and version from MySQL version string.
//
// Detects MySQL-family servers in priority order:
//  1. Aurora MySQL (mysql_aurora keyword)
//  2. MariaDB (MariaDB keyword, strips legacy 5.5.5- prefix)
//  3. Percona Server (Percona keyword)
//  4. MySQL (Oracle) - default for valid version numbers
//  5. Unknown - fallback for invalid/missing version strings
//
// Parameters:
//   - versionStr: Version string from MySQL handshake packet
//
// Returns:
//   - serverType: One of "mysql", "mariadb", "percona", "aurora", "unknown"
//   - version: Extracted version string, or empty if not found
func parseVersionString(versionStr string) (string, string) {

	if strings.Contains(versionStr, "mysql_aurora") {
		if matches := auroraRegex.FindStringSubmatch(versionStr); len(matches) >= 3 {
			auroraVersion := matches[2]
			return "aurora", auroraVersion
		}
	}

	if strings.Contains(versionStr, "MariaDB") {

		cleanStr := strings.Replace(versionStr, "5.5.5-", "", 1)
		if matches := mariadbRegex.FindStringSubmatch(cleanStr); len(matches) >= 4 {
			version := fmt.Sprintf("%s.%s.%s", matches[1], matches[2], matches[3])
			return "mariadb", version
		}
	}

	if strings.Contains(versionStr, "Percona") {
		if matches := perconaRegex.FindStringSubmatch(versionStr); len(matches) >= 2 {
			version := matches[1]
			return "percona", version
		}
	}

	if matches := mysqlRegex.FindStringSubmatch(versionStr); len(matches) >= 4 {
		version := fmt.Sprintf("%s.%s.%s", matches[1], matches[2], matches[3])
		return "mysql", version
	}

	return "unknown", ""
}

// buildMySQLCPE generates a CPE (Common Platform Enumeration) string for MySQL-family servers.
//
// Uses wildcard version ("*") when version is unknown to match Wappalyzer/RMI/FTP plugin
// behavior and enable asset inventory use cases even without precise version information.
//
// CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
//
// Vendor/product mappings:
//   - mysql   → cpe:2.3:a:oracle:mysql
//   - mariadb → cpe:2.3:a:mariadb:mariadb
//   - percona → cpe:2.3:a:percona:percona_server
//   - aurora  → cpe:2.3:a:amazon:aurora
//
// Parameters:
//   - serverType: Server type ("mysql", "mariadb", "percona", "aurora", "unknown", or empty)
//   - version: Version string (e.g., "8.0.28"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildMySQLCPE(serverType, version string) string {

	if serverType == "" || serverType == "unknown" {
		serverType = "mysql"
	}

	if version == "" {
		version = "*"
	}

	cpeTemplate, exists := cpeTemplates[serverType]
	if !exists {

		cpeTemplate = cpeTemplates["mysql"]
	}

	return fmt.Sprintf(cpeTemplate, version)
}

// readNullTerminatedASCIIString is responsible for reading a null terminated
// ASCII string from a buffer and returns it as a string type
func readNullTerminatedASCIIString(buffer []byte, startPosition int) (string, int, error) {
	characters := []byte{}
	success := false
	endPosition := 0

	for position := startPosition; position < len(buffer); position++ {
		if buffer[position] >= 0x20 && buffer[position] <= 0x7E {
			characters = append(characters, buffer[position])
		} else if buffer[position] == 0x00 {
			success = true
			endPosition = position
			break
		} else {
			return "", 0, fmt.Errorf("%s: invalid response: %s", MYSQL, "encountered invalid ASCII character")
		}
	}

	if !success {
		return "", 0, fmt.Errorf("%s: invalid response: %s", MYSQL,
			"hit the end of the buffer without encountering a null terminator")

	}

	return string(characters), endPosition, nil
}

// readEOFTerminatedASCIIString is responsible for reading an ASCII string
// that is terminated by the end of the message
func readEOFTerminatedASCIIString(buffer []byte, startPosition int) (string, error) {
	characters := []byte{}

	for position := startPosition; position < len(buffer); position++ {
		if buffer[position] >= 0x20 && buffer[position] <= 0x7E {
			characters = append(characters, buffer[position])
		} else {
			return "", fmt.Errorf("%s: invalid response: %s", MYSQL, "encountered invalid ASCII character")
		}
	}

	return string(characters), nil
}

var defaultMYSQLPluginPorts = helpers.Ports((&MYSQLPlugin{}).PortPriority)

func (p *MYSQLPlugin) DefaultPorts() []int { return defaultMYSQLPluginPorts }
func (p *MYSQLPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
