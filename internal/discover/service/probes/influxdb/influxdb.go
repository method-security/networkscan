// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package influxdb

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

const (
	INFLUXDB              = "influxdb"
	DefaultInfluxDBPort   = 8086
	InfluxDBVersionHeader = "x-influxdb-version"
)

type InfluxDBPlugin struct{}

// influxdbHealthResponse represents the JSON structure returned by GET /health (2.x+ only)
type influxdbHealthResponse struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Status  string `json:"status"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// buildInfluxDBHTTPRequest constructs an HTTP/1.1 GET request for the specified path
func buildInfluxDBHTTPRequest(path, host string) string {
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: networkscan\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host)
}

// extractHTTPHeaders parses HTTP response and extracts headers into a map
func extractHTTPHeaders(response []byte) map[string]string {
	headers := make(map[string]string)

	responseStr := string(response)

	lines := strings.Split(responseStr, "\r\n")
	if len(lines) == 0 {
		return headers
	}

	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {

			break
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {

			headerName := strings.ToLower(strings.TrimSpace(parts[0]))
			headerValue := strings.TrimSpace(parts[1])
			headers[headerName] = headerValue
		}
	}

	return headers
}

// extractHTTPBody extracts the body from an HTTP response (after \r\n\r\n separator)
func extractHTTPBody(response []byte) []byte {

	bodyStart := 0
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			bodyStart = i + 4
			break
		}
	}

	if bodyStart > 0 && bodyStart < len(response) {
		return response[bodyStart:]
	}

	return nil
}

// cleanVersionString removes prerelease and build metadata for CPE generation
// Examples: "2.7.10-rc1" → "2.7.10", "3.0.0+arm64" → "3.0.0"
func cleanVersionString(version string) string {

	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}

	if idx := strings.Index(version, "+"); idx != -1 {
		version = version[:idx]
	}
	return strings.TrimSpace(version)
}

// detectInfluxDBViaPing performs InfluxDB detection using the /ping endpoint
// Returns: (version, detected, error)
func detectInfluxDBViaPing(conn net.Conn, target probe.Target, timeout time.Duration) (string, bool, error) {

	host := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Address.Port()))
	request := buildInfluxDBHTTPRequest("/ping", host)

	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", false, nil
	}

	responseStr := string(response)

	hasValidStatus := strings.Contains(responseStr, "HTTP/1.1 204") ||
		strings.Contains(responseStr, "HTTP/1.0 204") ||
		strings.Contains(responseStr, "HTTP/1.1 503") ||
		strings.Contains(responseStr, "HTTP/1.0 503")

	if !hasValidStatus {

		return "", false, nil
	}

	headers := extractHTTPHeaders(response)

	version, hasVersionHeader := headers[InfluxDBVersionHeader]
	if !hasVersionHeader || version == "" {

		return "", false, nil
	}

	cleanedVersion := cleanVersionString(version)
	return cleanedVersion, true, nil
}

// detectInfluxDBViaHealth performs InfluxDB detection using the /health endpoint (2.x+ only)
// Returns: (version, detected, error)
func detectInfluxDBViaHealth(conn net.Conn, target probe.Target, timeout time.Duration) (string, bool, error) {

	host := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Address.Port()))
	request := buildInfluxDBHTTPRequest("/health", host)

	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", false, nil
	}

	responseStr := string(response)

	hasOKStatus := strings.Contains(responseStr, "HTTP/1.1 200") ||
		strings.Contains(responseStr, "HTTP/1.0 200")

	if !hasOKStatus {

		return "", false, nil
	}

	body := extractHTTPBody(response)
	if body == nil || len(body) == 0 {
		return "", false, nil
	}

	// Parse JSON response
	var healthResponse influxdbHealthResponse
	err = json.Unmarshal(body, &healthResponse)
	if err != nil {

		return "", false, nil
	}

	if healthResponse.Name != "influxdb" {

		return "", false, nil
	}

	if healthResponse.Status == "" {

		return "", false, nil
	}

	cleanedVersion := ""
	if healthResponse.Version != "" {
		cleanedVersion = cleanVersionString(healthResponse.Version)
	}

	return cleanedVersion, true, nil
}

// buildInfluxDBCPE generates a CPE (Common Platform Enumeration) string for InfluxDB
// CPE format: cpe:2.3:a:influxdata:influxdb:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases
func buildInfluxDBCPE(version string) string {

	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:influxdata:influxdb:%s:*:*:*:*:*:*:*", version)
}
func (p *InfluxDBPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {

	version, detected, err := detectInfluxDBViaPing(conn, target, timeout)
	if err != nil {
		return nil, err
	}
	if detected {

		cpe := buildInfluxDBCPE(version)
		payload := probe.ServiceInfluxDB{
			CPEs: []string{cpe},
		}
		return probe.Result(target, payload, false, version, probe.TCP), nil
	}

	return nil, nil
}
func (p *InfluxDBPlugin) PortPriority(port uint16) bool {
	return port == DefaultInfluxDBPort
}
func (p *InfluxDBPlugin) Name() string {
	return INFLUXDB
}
func (p *InfluxDBPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *InfluxDBPlugin) Priority() int {
	return 100
}

var defaultInfluxDBPluginPorts = probe.Ports((&InfluxDBPlugin{}).PortPriority)

func (p *InfluxDBPlugin) DefaultPorts() []int { return defaultInfluxDBPluginPorts }
func (p *InfluxDBPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
