// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted for networkscan; see ../NOTICE.md.

package chromadb

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
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
//   - conn: Network connection to the target service
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//
// Returns:
//   - string: Version string (empty if unavailable)
//   - error: Error details if version extraction failed (non-fatal)
func getChromaDBVersion(conn net.Conn, target probe.Target, timeout time.Duration) (string, error) {

	host := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Address.Port()))

	request := buildChromaDBHTTPRequest("/api/v1/version", host)

	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return "", err
	}

	if len(response) == 0 {
		return "", nil
	}

	jsonBody := extractHTTPBody(response)
	if len(jsonBody) == 0 {
		return "", nil
	}

	// Parse JSON response
	var versionResp chromadbVersionResponse
	if err := json.Unmarshal(jsonBody, &versionResp); err != nil {
		return "", nil
	}

	version := cleanChromaDBVersion(versionResp.Version)

	return version, nil
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
//   - *probe.Service: Service information if ChromaDB detected, nil otherwise
//   - error: Error details if detection failed
func detectChromaDB(conn net.Conn, target probe.Target, timeout time.Duration, tls bool) (*probe.Service, error) {

	host := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Address.Port()))

	request := buildChromaDBHTTPRequest("/api/v1/heartbeat", host)

	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	jsonBody := extractHTTPBody(response)

	detected, _ := parseChromaDBHeartbeat(jsonBody)
	if !detected {
		return nil, nil
	}

	version, _ := getChromaDBVersion(conn, target, timeout)

	cpe := buildChromaDBCPE(version)
	payload := probe.ServiceChromaDB{
		CPEs: []string{cpe},
	}

	if tls {
		return probe.Result(target, payload, true, version, probe.TCPTLS), nil
	}
	return probe.Result(target, payload, false, version, probe.TCP), nil
}
func (p *ChromaDBPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	return detectChromaDB(conn, target, timeout, false)
}
func (p *ChromaDBPlugin) PortPriority(port uint16) bool {
	return port == DefaultChromaDBPort
}
func (p *ChromaDBPlugin) Name() string {
	return CHROMADB
}
func (p *ChromaDBPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *ChromaDBPlugin) Priority() int {
	return 50
}
func (p *ChromaDBTLSPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	return detectChromaDB(conn, target, timeout, true)
}
func (p *ChromaDBTLSPlugin) PortPriority(port uint16) bool {
	return port == DefaultChromaDBPort
}
func (p *ChromaDBTLSPlugin) Name() string {
	return CHROMADBTLS
}
func (p *ChromaDBTLSPlugin) Type() probe.Protocol {
	return probe.TCPTLS
}
func (p *ChromaDBTLSPlugin) Priority() int {
	return 51
}

var defaultChromaDBPluginPorts = probe.Ports((&ChromaDBPlugin{}).PortPriority)

func (p *ChromaDBPlugin) DefaultPorts() []int { return defaultChromaDBPluginPorts }
func (p *ChromaDBPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}

var defaultChromaDBTLSPluginPorts = probe.Ports((&ChromaDBTLSPlugin{}).PortPriority)

func (p *ChromaDBTLSPlugin) DefaultPorts() []int { return defaultChromaDBTLSPluginPorts }
func (p *ChromaDBTLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
