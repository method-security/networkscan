// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package couchdb

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

const COUCHDB = "couchdb"
const COUCHDBTLS = "couchdb"

type COUCHDBPlugin struct{}
type COUCHDBTLSPlugin struct{}

// couchdbRootResponse represents the JSON structure returned by GET /
type couchdbRootResponse struct {
	CouchDB string `json:"couchdb"`
	Version string `json:"version"`
	Vendor  struct {
		Name string `json:"name"`
	} `json:"vendor"`
}

// parseCouchDBResponse validates a CouchDB root endpoint response and extracts version.
//
// Validation rules:
//   - json["couchdb"] must equal "Welcome" (case-sensitive)
//   - json["vendor"] must exist (checking for vendor.name)
//   - Version extracted from json["version"] if present
//
// Parameters:
//   - response: Raw HTTP response body (expected to be JSON)
//
// Returns:
//   - bool: true if CouchDB detected, false otherwise
//   - string: Version string (empty if not found or detection failed)
func parseCouchDBResponse(response []byte) (bool, string) {

	if len(response) == 0 {
		return false, ""
	}

	// Parse JSON
	var parsed couchdbRootResponse
	if err := json.Unmarshal(response, &parsed); err != nil {
		return false, ""
	}

	if parsed.CouchDB != "Welcome" {
		return false, ""
	}

	if parsed.Vendor.Name == "" {
		return false, ""
	}

	return true, parsed.Version
}

// buildCouchDBCPE constructs a CPE (Common Platform Enumeration) string for CouchDB.
// CPE format: cpe:2.3:a:apache:couchdb:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases.
//
// Parameters:
//   - version: CouchDB version string (e.g., "3.4.2"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildCouchDBCPE(version string) string {

	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:apache:couchdb:%s:*:*:*:*:*:*:*", version)
}

// buildCouchDBHTTPRequest constructs an HTTP/1.1 GET request for the specified path.
//
// Parameters:
//   - path: HTTP path (e.g., "/", "/_session")
//   - host: Target host:port (e.g., "localhost:5984")
//
// Returns:
//   - string: Complete HTTP request ready to send
func buildCouchDBHTTPRequest(path, host string) string {
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: networkscan\r\n"+
			"Accept: application/json\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host)
}

// detectCouchDB performs CouchDB detection using HTTP REST API.
//
// Detection phases:
//  1. Send HTTP GET / request
//  2. Receive and parse JSON response
//  3. Validate CouchDB markers (json["couchdb"] == "Welcome")
//  4. Extract version from json["version"] field
//
// Parameters:
//   - conn: Network connection to the target service
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//   - tls: Whether the connection uses TLS
//
// Returns:
//   - *discover.ServiceDetails: Service information if CouchDB detected, nil otherwise
//   - error: Error details if detection failed
func detectCouchDB(conn net.Conn, target helpers.Endpoint, timeout time.Duration, tls bool) (*discover.ServiceDetails, error) {

	host := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Address.Port()))

	request := buildCouchDBHTTPRequest("/", host)

	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	bodyStart := 0
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			bodyStart = i + 4
			break
		}
	}

	// If we found the body separator, extract JSON body
	var jsonBody []byte
	if bodyStart > 0 && bodyStart < len(response) {
		jsonBody = response[bodyStart:]
	} else {

		jsonBody = response
	}

	detected, version := parseCouchDBResponse(jsonBody)
	if !detected {
		return nil, nil
	}

	cpe := buildCouchDBCPE(version)
	payload := ServiceCouchDB{
		CPEs: []string{cpe},
	}

	if tls {
		return helpers.MetadataResult(target, payload, true, version, common.TransportTypeTcptls), nil
	}
	return helpers.MetadataResult(target, payload, false, version, common.TransportTypeTcp), nil
}
func (p *COUCHDBPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	return detectCouchDB(conn, target, timeout, false)
}
func (p *COUCHDBPlugin) PortPriority(port uint16) bool {
	return port == 5984
}
func (p *COUCHDBPlugin) Name() string {
	return COUCHDB
}
func (p *COUCHDBPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *COUCHDBPlugin) Priority() int {
	return 100
}
func (p *COUCHDBTLSPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	return detectCouchDB(conn, target, timeout, true)
}
func (p *COUCHDBTLSPlugin) PortPriority(port uint16) bool {
	return port == 6984
}
func (p *COUCHDBTLSPlugin) Name() string {
	return COUCHDBTLS
}
func (p *COUCHDBTLSPlugin) Type() common.TransportType {
	return common.TransportTypeTcptls
}
func (p *COUCHDBTLSPlugin) Priority() int {
	return 101
}

var defaultCOUCHDBPluginPorts = helpers.Ports((&COUCHDBPlugin{}).PortPriority)

func (p *COUCHDBPlugin) DefaultPorts() []int { return defaultCOUCHDBPluginPorts }
func (p *COUCHDBPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}

var defaultCOUCHDBTLSPluginPorts = helpers.Ports((&COUCHDBTLSPlugin{}).PortPriority)

func (p *COUCHDBTLSPlugin) DefaultPorts() []int { return defaultCOUCHDBTLSPluginPorts }
func (p *COUCHDBTLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
