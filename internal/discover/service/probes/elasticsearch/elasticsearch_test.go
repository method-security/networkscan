package elasticsearch

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWireResponses(t *testing.T) {
	cases := []struct {
		name     string
		response []byte
		match    bool
	}{
		{"elasticsearch", buildMockElasticsearchResponse("8.11.3"), true},
		{"opensearch", buildMockOpenSearchResponse("2.11.0"), false},
		{"not found", buildMock404Response(), false},
		{"invalid JSON", buildMockInvalidJSONResponse(), false},
		{"missing tagline", buildMockMissingTaglineResponse(), false},
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
			_, match, _ := detectElasticsearch(client, time.Second)
			if match != tc.match {
				t.Fatalf("match=%v want=%v", match, tc.match)
			}
		})
	}
}

// TestCleanVersionString tests version string cleanup (removing -SNAPSHOT suffix)
func TestCleanVersionString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard_version", "8.11.3", "8.11.3"},
		{"snapshot_version", "8.11.3-SNAPSHOT", "8.11.3"},
		{"rc_version", "8.0.0-rc2", "8.0.0-rc2"},
		{"old_version", "7.17.16", "7.17.16"},
		{"empty_version", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanVersionString(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestBuildElasticsearchCPE tests CPE generation for Elasticsearch
func TestBuildElasticsearchCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with_version",
			version:  "8.11.3",
			expected: "cpe:2.3:a:elastic:elasticsearch:8.11.3:*:*:*:*:*:*:*",
		},
		{
			name:     "with_rc_version",
			version:  "8.0.0-rc2",
			expected: "cpe:2.3:a:elastic:elasticsearch:8.0.0-rc2:*:*:*:*:*:*:*",
		},
		{
			name:     "empty_version_uses_wildcard",
			version:  "",
			expected: "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
		},
		{
			name:     "old_version",
			version:  "7.17.16",
			expected: "cpe:2.3:a:elastic:elasticsearch:7.17.16:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildElasticsearchCPE(tt.version)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// buildMockElasticsearchResponse creates a mock HTTP response from Elasticsearch
func buildMockElasticsearchResponse(version string) []byte {
	jsonBody := `{
  "name" : "test-node",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "abc123",
  "version" : {
    "number" : "` + version + `",
    "build_flavor" : "default",
    "build_type" : "docker",
    "build_hash" : "abc123",
    "build_date" : "2023-11-04T10:04:57.184859352Z",
    "build_snapshot" : false,
    "lucene_version" : "9.8.0",
    "minimum_wire_compatibility_version" : "7.17.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "You Know, for Search"
}`

	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json; charset=UTF-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(jsonBody)) + "\r\n" +
		"\r\n" +
		jsonBody

	return []byte(httpResponse)
}

// buildMockOpenSearchResponse creates a mock HTTP response from OpenSearch
func buildMockOpenSearchResponse(version string) []byte {
	jsonBody := `{
  "name" : "test-node",
  "cluster_name" : "opensearch",
  "cluster_uuid" : "abc123",
  "version" : {
    "distribution" : "opensearch",
    "number" : "` + version + `",
    "build_type" : "docker",
    "build_hash" : "abc123",
    "build_date" : "2023-11-04T10:04:57.184859352Z",
    "build_snapshot" : false,
    "lucene_version" : "9.7.0",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}`

	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json; charset=UTF-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(jsonBody)) + "\r\n" +
		"\r\n" +
		jsonBody

	return []byte(httpResponse)
}

// buildMock404Response creates a mock HTTP 404 response
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

// buildMockMissingTaglineResponse creates a mock response without tagline
func buildMockMissingTaglineResponse() []byte {
	jsonBody := `{
  "name" : "test-node",
  "cluster_name" : "elasticsearch",
  "version" : {
    "number" : "8.11.3"
  }
}`

	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		jsonBody

	return []byte(httpResponse)
}
