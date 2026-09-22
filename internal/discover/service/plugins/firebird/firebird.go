// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package firebird

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

// FirebirdPlugin implements the Plugin interface for Firebird SQL server fingerprinting
type FirebirdPlugin struct{}

const (
	FIREBIRD = "firebird"

	// Protocol operation codes
	opConnect    = 1  // Client initiates connection
	opAccept     = 3  // Server accepts connection
	opReject     = 4  // Server rejects connection (but confirms Firebird presence)
	opResponse   = 9  // Error response with status vector
	opCondAccept = 20 // Conditional acceptance (protocol 13+)
	opAcceptData = 21 // Acceptance with authentication data (protocol 13+)
	opAttach     = 2  // Attach to database operation

	// Protocol version constants
	// FB_PROTOCOL_FLAG (0x8000) distinguishes Firebird from InterBase
	fbProtocolFlag = 0x8000

	// Connect version and architecture
	connectVersion3 = 3 // CONNECT_VERSION3
	archGeneric     = 1 // Architecture type (generic)
)

// Run performs Firebird server fingerprinting through two phases:
// Phase 1 (Detection): Send op_connect, receive op_accept, extract protocol version
// Phase 2 (Enrichment): Map protocol to major.minor version (HIGH confidence)
func (p *FirebirdPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {

	connectPacket := buildConnectPacket()

	response, err := utils.SendRecv(conn, connectPacket, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, nil
	}

	opcode := binary.BigEndian.Uint32(response[0:4])

	switch opcode {
	case opAccept, opCondAccept, opAcceptData:

		if len(response) < 16 {
			return nil, &utils.InvalidResponseErrorInfo{
				Service: FIREBIRD,
				Info:    "op_accept response truncated (< 16 bytes)",
			}
		}

		protocolVersion := int32(binary.BigEndian.Uint32(response[4:8]))

		isFirebird, version := identifyFirebird(protocolVersion)
		if !isFirebird {
			return nil, nil
		}

		cpe := buildFirebirdCPE(version)

		payload := ServiceFirebird{
			ProtocolVersion: protocolVersion,
			CPEs:            []string{cpe},
		}

		return helpers.MetadataResult(target, payload, false, version, common.TransportTypeTcp), nil

	case opReject:

		cpe := buildFirebirdCPE("")

		payload := ServiceFirebird{
			CPEs: []string{cpe},
		}

		return helpers.MetadataResult(target, payload, false, "", common.TransportTypeTcp), nil

	case opResponse:

		return nil, nil

	default:

		return nil, nil
	}
}

// PortPriority returns true if the port is Firebird's default port 3050
func (p *FirebirdPlugin) PortPriority(port uint16) bool {
	return port == 3050
}

// Name returns the protocol name
func (p *FirebirdPlugin) Name() string {
	return FIREBIRD
}

// Type returns the protocol type (TCP)
func (p *FirebirdPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}

// Priority returns the execution priority (default 100)
func (p *FirebirdPlugin) Priority() int {
	return 100
}

// buildConnectPacket constructs an op_connect packet offering protocols 10, 13, 16, 17
//
// Packet structure:
//
//	p_operation: op_connect (1)
//	p_cnct_operation: op_attach (2)
//	p_cnct_cversion: CONNECT_VERSION3 (3)
//	p_cnct_client: arch_generic (1)
//	p_cnct_file: "" (empty database path for fingerprinting)
//	p_cnct_count: 4 (number of protocols offered)
//	p_cnct_user_id: [] (empty UID buffer for fingerprinting)
//	--- For each protocol (repeated 4 times) ---
//	p_cnct_version: protocol version (10, 13, 16, 17)
//	p_cnct_architecture: arch_generic (1)
//	p_cnct_min_type: 0
//	p_cnct_max_type: 5
//	p_cnct_weight: preference weight (2, 4, 6, 8)
func buildConnectPacket() []byte {
	var buf []byte

	buf = append(buf, packInt(opConnect)...)
	buf = append(buf, packInt(opAttach)...)
	buf = append(buf, packInt(connectVersion3)...)
	buf = append(buf, packInt(archGeneric)...)
	buf = append(buf, packString("")...)

	buf = append(buf, packInt(4)...)
	buf = append(buf, packString("")...)

	buf = append(buf, packInt(0x0000000a)...)
	buf = append(buf, packInt(archGeneric)...)
	buf = append(buf, packInt(0)...)
	buf = append(buf, packInt(5)...)
	buf = append(buf, packInt(2)...)

	buf = append(buf, packInt(0x0000800d)...)
	buf = append(buf, packInt(archGeneric)...)
	buf = append(buf, packInt(0)...)
	buf = append(buf, packInt(5)...)
	buf = append(buf, packInt(4)...)

	buf = append(buf, packInt(0x00008010)...)
	buf = append(buf, packInt(archGeneric)...)
	buf = append(buf, packInt(0)...)
	buf = append(buf, packInt(5)...)
	buf = append(buf, packInt(6)...)

	buf = append(buf, packInt(0x00008011)...)
	buf = append(buf, packInt(archGeneric)...)
	buf = append(buf, packInt(0)...)
	buf = append(buf, packInt(5)...)
	buf = append(buf, packInt(8)...)

	return buf
}

// packInt packs an int32 value as big-endian 4-byte sequence
func packInt(value int32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(value))
	return buf
}

// packString packs a string as length-prefixed sequence (4-byte length + string bytes)
func packString(s string) []byte {
	length := len(s)
	buf := make([]byte, 4+length)
	binary.BigEndian.PutUint32(buf[0:4], uint32(length))
	copy(buf[4:], s)

	padding := (4 - (length % 4)) % 4
	buf = append(buf, make([]byte, padding)...)

	return buf
}

// identifyFirebird determines if the protocol version indicates Firebird (vs InterBase)
// and maps the protocol version to a Firebird major.minor version string.
//
// Returns:
//   - isFirebird: true if this is Firebird (not InterBase)
//   - version: Firebird major.minor version string (e.g., "5.0", "4.0")
//
// Protocol Version Mapping:
//   - 17 (0x8011): Firebird 5.0
//   - 16 (0x8010): Firebird 4.0
//   - 15 (0x800f): Firebird 3.0.2+
//   - 13 (0x800d): Firebird 3.0
//   - 12 (0x800c): Firebird 2.5
//   - 11 (0x800b): Firebird 2.1
//   - 10 (0x000a): Firebird 1.x OR InterBase (ambiguous)
//   - 14 (0x000e): InterBase (NOT Firebird)
//
// The FB_PROTOCOL_FLAG (0x8000) distinguishes Firebird from InterBase for
// protocol versions 11+.
func identifyFirebird(protocolVersion int32) (isFirebird bool, version string) {

	if protocolVersion == 14 {
		return false, ""
	}

	if protocolVersion == 10 {
		return true, ""
	}

	if protocolVersion > 10 && (protocolVersion&fbProtocolFlag) == 0 {
		return false, ""
	}

	bareVersion := protocolVersion & 0x7fff

	switch bareVersion {
	case 17:
		return true, "5.0"
	case 16:
		return true, "4.0"
	case 15:
		return true, "3.0.2"
	case 13:
		return true, "3.0"
	case 12:
		return true, "2.5"
	case 11:
		return true, "2.1"
	default:

		return true, ""
	}
}

// buildFirebirdCPE generates a CPE (Common Platform Enumeration) string for Firebird.
//
// Uses wildcard version ("*") when version is unknown to match FTP/MySQL/PostgreSQL
// plugin behavior and enable asset inventory use cases even without precise version.
//
// CPE format: cpe:2.3:a:firebirdsql:firebird:{version}:*:*:*:*:*:*:*
//
// Parameters:
//   - version: Version string (e.g., "4.0", "5.0.3"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildFirebirdCPE(version string) string {

	if version == "" {
		version = "*"
	}

	return fmt.Sprintf("cpe:2.3:a:firebirdsql:firebird:%s:*:*:*:*:*:*:*", version)
}

var defaultFirebirdPluginPorts = helpers.Ports((&FirebirdPlugin{}).PortPriority)

func (p *FirebirdPlugin) DefaultPorts() []int { return defaultFirebirdPluginPorts }
func (p *FirebirdPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
