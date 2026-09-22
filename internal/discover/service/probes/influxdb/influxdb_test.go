// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol tests adapted for networkscan.
package influxdb

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	"github.com/stretchr/testify/assert"
)

func TestWireResponses(t *testing.T) {
	cases := []struct {
		name          string
		response      []byte
		health, match bool
	}{
		{"ping", buildMockInfluxDBPingResponse("2.7.10", "204 No Content"), false, true},
		{"health", buildMockInfluxDBHealthResponse("2.7.10"), true, true},
		{"prometheus", buildMockPrometheusResponse(), true, false},
		{"not found", buildMock404Response(), true, false},
		{"invalid JSON", buildMockInvalidJSONResponse(), true, false},
		{"missing version", buildMockMissingVersionHeaderResponse(), false, false},
		{"grafana", buildMockGrafanaHealthResponse(), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			go func() {
				defer func() { _ = server.Close() }()
				b := make([]byte, 4096)
				_, _ = server.Read(b)
				_, _ = server.Write(tc.response)
			}()
			detect := detectInfluxDBViaPing
			if tc.health {
				detect = detectInfluxDBViaHealth
			}
			_, match, _ := detect(client, probe.Target{Host: "localhost", Address: netip.MustParseAddrPort("127.0.0.1:8086")}, time.Second)
			if match != tc.match {
				t.Fatalf("match=%v want=%v", match, tc.match)
			}
		})
	}
}

// TestCleanVersionString tests version string cleanup (removing prerelease and build metadata)
func TestCleanVersionString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard_version_1x", "1.8.10", "1.8.10"},
		{"standard_version_2x", "2.7.10", "2.7.10"},
		{"standard_version_3x", "3.0.0", "3.0.0"},
		{"prerelease_rc", "3.0.0-rc1", "3.0.0"},
		{"prerelease_beta", "2.8.0-beta1", "2.8.0"},
		{"prerelease_alpha", "1.9.0-alpha1", "1.9.0"},
		{"build_metadata", "2.7.10+arm64", "2.7.10"},
		{"prerelease_and_build", "3.0.0-rc1+arm64", "3.0.0"},
		{"custom_build", "2.7.10-custom-build+linux", "2.7.10"},
		{"empty_version", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanVersionString(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestBuildInfluxDBCPE tests CPE generation for InfluxDB
func TestBuildInfluxDBCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "version_1x",
			version:  "1.8.10",
			expected: "cpe:2.3:a:influxdata:influxdb:1.8.10:*:*:*:*:*:*:*",
		},
		{
			name:     "version_2x",
			version:  "2.7.10",
			expected: "cpe:2.3:a:influxdata:influxdb:2.7.10:*:*:*:*:*:*:*",
		},
		{
			name:     "version_3x",
			version:  "3.0.0",
			expected: "cpe:2.3:a:influxdata:influxdb:3.0.0:*:*:*:*:*:*:*",
		},
		{
			name:     "prerelease_rc",
			version:  "3.0.0-rc1",
			expected: "cpe:2.3:a:influxdata:influxdb:3.0.0-rc1:*:*:*:*:*:*:*",
		},
		{
			name:     "empty_version_uses_wildcard",
			version:  "",
			expected: "cpe:2.3:a:influxdata:influxdb:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version_2_0",
			version:  "2.0.9",
			expected: "cpe:2.3:a:influxdata:influxdb:2.0.9:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildInfluxDBCPE(tt.version)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestExtractHTTPHeaders tests HTTP header extraction
func TestExtractHTTPHeaders(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected map[string]string
	}{
		{
			name: "influxdb_ping_headers",
			response: []byte("HTTP/1.1 204 No Content\r\n" +
				"Content-Type: application/json\r\n" +
				"X-Influxdb-Build: OSS\r\n" +
				"X-Influxdb-Version: 2.7.10\r\n" +
				"X-Request-Id: abc123\r\n" +
				"\r\n"),
			expected: map[string]string{
				"content-type":       "application/json",
				"x-influxdb-build":   "OSS",
				"x-influxdb-version": "2.7.10",
				"x-request-id":       "abc123",
			},
		},
		{
			name: "influxdb_1x_headers",
			response: []byte("HTTP/1.1 204 No Content\r\n" +
				"X-Influxdb-Version: 1.8.10\r\n" +
				"\r\n"),
			expected: map[string]string{
				"x-influxdb-version": "1.8.10",
			},
		},
		{
			name: "missing_version_header",
			response: []byte("HTTP/1.1 204 No Content\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n"),
			expected: map[string]string{
				"content-type": "application/json",
			},
		},
		{
			name:     "empty_response",
			response: []byte(""),
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHTTPHeaders(tt.response)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestExtractHTTPBody tests HTTP body extraction
func TestExtractHTTPBody(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected []byte
	}{
		{
			name: "json_body",
			response: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"name":"influxdb","version":"2.7.10"}`),
			expected: []byte(`{"name":"influxdb","version":"2.7.10"}`),
		},
		{
			name: "empty_body",
			response: []byte("HTTP/1.1 204 No Content\r\n" +
				"X-Influxdb-Version: 2.7.10\r\n" +
				"\r\n"),
			expected: nil,
		},
		{
			name:     "no_header_separator",
			response: []byte("not an http response"),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHTTPBody(tt.response)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// buildMockInfluxDBPingResponse creates a mock HTTP /ping response from InfluxDB
func buildMockInfluxDBPingResponse(version string, statusCode string) []byte {
	httpResponse := "HTTP/1.1 " + statusCode + "\r\n" +
		"Content-Type: application/json\r\n" +
		"Date: Wed, 01 Jan 2026 00:00:00 GMT\r\n" +
		"X-Influxdb-Build: OSS\r\n" +
		"X-Influxdb-Version: " + version + "\r\n" +
		"X-Request-Id: abc123def456\r\n" +
		"\r\n"

	return []byte(httpResponse)
}

// buildMockInfluxDBHealthResponse creates a mock HTTP /health response from InfluxDB 2.x+
func buildMockInfluxDBHealthResponse(version string) []byte {
	jsonBody := `{
  "name": "influxdb",
  "message": "ready for queries and writes",
  "status": "pass",
  "checks": [],
  "version": "` + version + `",
  "commit": "abc123def456"
}`

	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		jsonBody

	return []byte(httpResponse)
}

// buildMockPrometheusResponse creates a mock HTTP response from Prometheus (false positive test)
func buildMockPrometheusResponse() []byte {
	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n" +
		"\r\n" +
		"Prometheus is Healthy."

	return []byte(httpResponse)
}

// buildMock404Response creates a mock HTTP 404 response (for InfluxDB 1.x /health endpoint)
func buildMock404Response() []byte {
	httpResponse := "HTTP/1.1 404 Not Found\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html><body><h1>404 Not Found</h1></body></html>"

	return []byte(httpResponse)
}

// buildMockInvalidJSONResponse creates a mock response with invalid JSON
func buildMockInvalidJSONResponse() []byte {
	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		"{invalid json}"

	return []byte(httpResponse)
}

// buildMockMissingVersionHeaderResponse creates a mock response without X-Influxdb-Version
func buildMockMissingVersionHeaderResponse() []byte {
	httpResponse := "HTTP/1.1 204 No Content\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n"

	return []byte(httpResponse)
}

// buildMockGrafanaHealthResponse creates a mock /health response from Grafana (false positive test)
func buildMockGrafanaHealthResponse() []byte {
	jsonBody := `{
  "commit": "abc123",
  "database": "ok",
  "version": "9.5.3"
}`

	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		jsonBody

	return []byte(httpResponse)
}
