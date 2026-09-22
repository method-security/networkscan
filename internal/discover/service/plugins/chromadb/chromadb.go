// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package chromadb

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

const CHROMADB = "chromadb"
const CHROMADBTLS = "chromadb"
const DefaultChromaDBPort = 8000

type ChromaDBPlugin struct{}
type ChromaDBTLSPlugin struct{}

// chromadbHeartbeatResponse represents the JSON structure returned by GET /api/v1/heartbeat
type chromadbHeartbeatResponse struct {
	NanosecondHeartbeat int64 `json:"nanosecond heartbeat"`
}

// chromadbVersionResponse represents the JSON structure returned by GET /api/v1/version
type chromadbVersionResponse struct {
	Version string `json:"version"`
}

// parseChromaDBHeartbeat validates a ChromaDB heartbeat response and checks for unique marker.
//
// Validation rules:
//   - json["nanosecond heartbeat"] must exist (field name with space is unique to ChromaDB)
//   - Value must be numeric and > 1e18 (reasonable nanosecond timestamp)
//
// Parameters:
//   - response: Raw HTTP response body (expected to be JSON)
//
// Returns:
//   - bool: true if ChromaDB detected, false otherwise
//   - int64: Heartbeat value (0 if detection failed)
func parseChromaDBHeartbeat(response []byte) (bool, int64) {

	if len(response) == 0 {
		return false, 0
	}

	// Parse JSON
	var parsed chromadbHeartbeatResponse
	if err := json.Unmarshal(response, &parsed); err != nil {
		return false, 0
	}

	// Validate nanosecond heartbeat field exists and is reasonable
	// ChromaDB returns Unix nanosecond timestamps (> 1e18)
	const minNanosecondTimestamp = 1_000_000_000_000_000_000 // 1e18
	if parsed.NanosecondHeartbeat < minNanosecondTimestamp {
		return false, 0
	}

	return true, parsed.NanosecondHeartbeat
}

// getChromaDBVersion attempts to extract version from /api/v1/version endpoint.
//
// This is an enrichment step that happens after detection succeeds. Version extraction
// may fail if the endpoint is unavailable, authentication is required, or response is malformed.
//
// Parameters:
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//   - secure: Whether to negotiate TLS on the new connection
//
// Returns:
//   - string: Version string (empty if unavailable)
//   - error: Error details if version extraction failed (non-fatal)
func getChromaDBVersion(target helpers.Endpoint, timeout time.Duration, secure bool) (string, error) {
	ctx := target.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := helpers.ContextDuration(ctx, timeout)
	defer cancel()
	// The heartbeat requests Connection: close; enrichment needs a fresh socket,
	// still governed by the original plugin context and proxy-aware dialer.
	conn, err := helpers.DialDuration(ctx, "tcp", target.Address.String(), timeout)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	if secure {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: target.Host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return "", err
		}
		conn = tlsConn
	}

	host := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Address.Port()))

	request := buildChromaDBHTTPRequest("/api/v1/version", host)

	jsonBody, err := readChromaDBResponse(conn, request, timeout)
	if err != nil {
		return "", err
	}

	if len(jsonBody) == 0 {
		return "", nil
	}

	// Parse JSON response
	var versionString string
	if err := json.Unmarshal(jsonBody, &versionString); err == nil {
		return cleanChromaDBVersion(versionString), nil
	}
	var versionResp chromadbVersionResponse
	if err := json.Unmarshal(jsonBody, &versionResp); err != nil {
		return "", nil
	}

	version := cleanChromaDBVersion(versionResp.Version)

	return version, nil
}

func readChromaDBResponse(conn net.Conn, request string, timeout time.Duration) ([]byte, error) {
	if err := utils.Send(conn, []byte(request), timeout); err != nil {
		return nil, err
	}
	if err := helpers.SetReadDeadlineDuration(conn, timeout); err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 2<<20)), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ChromaDB HTTP status %d", response.StatusCode)
	}
	const maxBodyBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("ChromaDB response exceeds size limit")
	}
	return body, err
}

// cleanChromaDBVersion removes pre-release suffixes and commit hashes from version strings.
//
// Examples:
//   - "1.4.0-alpha" → "1.4.0"
//   - "1.4.0+abc123" → "1.4.0"
//   - "1.4.0-beta.1" → "1.4.0"
//
// Parameters:
//   - version: Raw version string from API
//
// Returns:
//   - string: Cleaned semantic version (empty if invalid)
func cleanChromaDBVersion(version string) string {
	if version == "" {
		return ""
	}

	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}

	if idx := strings.Index(version, "+"); idx != -1 {
		version = version[:idx]
	}

	return version
}

// buildChromaDBCPE constructs a CPE (Common Platform Enumeration) string for ChromaDB.
// CPE format: cpe:2.3:a:chroma:chromadb:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases.
//
// Parameters:
//   - version: ChromaDB version string (e.g., "1.4.0"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildChromaDBCPE(version string) string {

	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:chroma:chromadb:%s:*:*:*:*:*:*:*", version)
}

// buildChromaDBHTTPRequest constructs an HTTP/1.1 GET request for the specified path.
//
// Parameters:
//   - path: HTTP path (e.g., "/api/v1/heartbeat", "/api/v1/version")
//   - host: Target host:port (e.g., "localhost:8000")
//
// Returns:
//   - string: Complete HTTP request ready to send
func buildChromaDBHTTPRequest(path, host string) string {
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: networkscan\r\n"+
			"Accept: application/json\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host)
}

// extractHTTPBody extracts the JSON body from an HTTP response.
//
// HTTP responses have format: headers\r\n\r\nbody
// This function finds the separator and returns everything after it.
//
// Parameters:
//   - response: Raw HTTP response bytes
//
// Returns:
//   - []byte: JSON body (empty if separator not found)
func extractHTTPBody(response []byte) []byte {

	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			bodyStart := i + 4
			if bodyStart < len(response) {
				return response[bodyStart:]
			}
			break
		}
	}

	return response
}

// detectChromaDB performs ChromaDB detection using HTTP REST API.
//
// Detection phases:
//  1. Send HTTP GET /api/v1/heartbeat request (DETECTION)
//  2. Receive and parse JSON response
//  3. Validate ChromaDB markers (json["nanosecond heartbeat"] exists and valid)
//  4. Extract version from GET /api/v1/version endpoint (ENRICHMENT)
//
// Parameters:
//   - conn: Network connection to the target service
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//   - tls: Whether the connection uses TLS
//
// Returns:
//   - *discover.ServiceDetails: Service information if ChromaDB detected, nil otherwise
//   - error: Error details if detection failed
func detectChromaDB(conn net.Conn, target helpers.Endpoint, timeout time.Duration, tls bool) (*discover.ServiceDetails, error) {

	host := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Address.Port()))

	request := buildChromaDBHTTPRequest("/api/v1/heartbeat", host)

	jsonBody, err := readChromaDBResponse(conn, request, timeout)
	if err != nil {
		return nil, err
	}

	if len(jsonBody) == 0 {
		return nil, nil
	}

	detected, _ := parseChromaDBHeartbeat(jsonBody)
	if !detected {
		return nil, nil
	}

	version, _ := getChromaDBVersion(target, timeout, tls)

	cpe := buildChromaDBCPE(version)
	payload := ServiceChromaDB{
		CPEs: []string{cpe},
	}

	if tls {
		return helpers.MetadataResult(target, payload, true, version, common.TransportTypeTcptls), nil
	}
	return helpers.MetadataResult(target, payload, false, version, common.TransportTypeTcp), nil
}
func (p *ChromaDBPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	return detectChromaDB(conn, target, timeout, false)
}
func (p *ChromaDBPlugin) PortPriority(port uint16) bool {
	return port == DefaultChromaDBPort
}
func (p *ChromaDBPlugin) Name() string {
	return CHROMADB
}
func (p *ChromaDBPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *ChromaDBPlugin) Priority() int {
	return 50
}
func (p *ChromaDBTLSPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	return detectChromaDB(conn, target, timeout, true)
}
func (p *ChromaDBTLSPlugin) PortPriority(port uint16) bool {
	return port == DefaultChromaDBPort
}
func (p *ChromaDBTLSPlugin) Name() string {
	return CHROMADBTLS
}
func (p *ChromaDBTLSPlugin) Type() common.TransportType {
	return common.TransportTypeTcptls
}
func (p *ChromaDBTLSPlugin) Priority() int {
	return 51
}

var defaultChromaDBPluginPorts = helpers.Ports((&ChromaDBPlugin{}).PortPriority)

func (p *ChromaDBPlugin) DefaultPorts() []int { return defaultChromaDBPluginPorts }
func (p *ChromaDBPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}

var defaultChromaDBTLSPluginPorts = helpers.Ports((&ChromaDBTLSPlugin{}).PortPriority)

func (p *ChromaDBTLSPlugin) DefaultPorts() []int { return defaultChromaDBTLSPluginPorts }
func (p *ChromaDBTLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
