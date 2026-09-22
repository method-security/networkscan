// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol tests adapted for networkscan.
package pinecone

import (
	"net/http"
	"testing"

	plugins "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
)

// TestPineconePluginInterface tests the plugin interface methods
func TestPineconePluginInterface(t *testing.T) {
	plugin := &PINECONEPlugin{}

	t.Run("Name", func(t *testing.T) {
		expected := "pinecone"
		if name := plugin.Name(); name != expected {
			t.Errorf("Name() = %q, want %q", name, expected)
		}
	})

	t.Run("Type", func(t *testing.T) {
		if pluginType := plugin.Type(); pluginType != plugins.TCPTLS {
			t.Errorf("Type() = %v, want TCPTLS (%v)", pluginType, plugins.TCPTLS)
		}
	})

	t.Run("Priority", func(t *testing.T) {
		priority := plugin.Priority()
		expectedPriority := 50
		if priority != expectedPriority {
			t.Errorf("Priority() = %d, want %d", priority, expectedPriority)
		}
	})

	t.Run("PortPriority default port 443", func(t *testing.T) {
		if !plugin.PortPriority(443) {
			t.Errorf("PortPriority(443) = false, want true (Pinecone default port)")
		}
	})

	t.Run("PortPriority non-default port 8443", func(t *testing.T) {
		if plugin.PortPriority(8443) {
			t.Error("PortPriority(8443) = true, want false (not Pinecone default)")
		}
	})

	t.Run("PortPriority port 80", func(t *testing.T) {
		if plugin.PortPriority(80) {
			t.Error("PortPriority(80) = true, want false (Pinecone uses HTTPS only)")
		}
	})

	t.Run("PortPriority port 8000", func(t *testing.T) {
		if plugin.PortPriority(8000) {
			t.Error("PortPriority(8000) = true, want false")
		}
	})

	t.Run("PortPriority port 0", func(t *testing.T) {
		if plugin.PortPriority(0) {
			t.Error("PortPriority(0) = true, want false (invalid port)")
		}
	})

	t.Run("PortPriority port 65535", func(t *testing.T) {
		if plugin.PortPriority(65535) {
			t.Error("PortPriority(65535) = true, want false")
		}
	})
}

// TestHeaderConstants tests that header constant values are correct
func TestHeaderConstants(t *testing.T) {
	tests := []struct {
		name        string
		constant    string
		expected    string
		description string
	}{
		{
			name:        "PROTOCOL_NAME",
			constant:    PROTOCOL_NAME,
			expected:    "pinecone",
			description: "Protocol name should be 'pinecone'",
		},
		{
			name:        "HEADER_API_VERSION",
			constant:    HEADER_API_VERSION,
			expected:    "X-Pinecone-Api-Version",
			description: "Primary detection header for API version",
		},
		{
			name:        "HEADER_AUTH_REJECTED",
			constant:    HEADER_AUTH_REJECTED,
			expected:    "X-Pinecone-Auth-Rejected-Reason",
			description: "Secondary detection header for auth rejection",
		},
		{
			name:        "USERAGENT",
			constant:    USERAGENT,
			expected:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
			description: "User agent string for HTTP requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("Constant %s = %q, want %q\nDescription: %s",
					tt.name, tt.constant, tt.expected, tt.description)
			}
		})
	}
}

// TestDefaultPort tests the DEFAULT_PORT constant
func TestDefaultPort(t *testing.T) {
	expectedPort := uint16(443)
	actualPort := uint16(DEFAULT_PORT)

	if actualPort != expectedPort {
		t.Errorf("DEFAULT_PORT = %d, want %d (HTTPS port for Pinecone)", actualPort, expectedPort)
	}
}

// TestHeaderCaseInsensitivity documents expected behavior for HTTP header case handling
func TestHeaderCaseInsensitivity(t *testing.T) {

	tests := []struct {
		name        string
		headerKey   string
		headerValue string
		lookupKey   string
		description string
	}{
		{
			name:        "exact case match",
			headerKey:   "X-Pinecone-Api-Version",
			headerValue: "2025-01",
			lookupKey:   "X-Pinecone-Api-Version",
			description: "Exact case match should work",
		},
		{
			name:        "lowercase lookup",
			headerKey:   "X-Pinecone-Api-Version",
			headerValue: "2025-01",
			lookupKey:   "x-pinecone-api-version",
			description: "Lowercase lookup should work (HTTP headers are case-insensitive)",
		},
		{
			name:        "uppercase lookup",
			headerKey:   "X-Pinecone-Api-Version",
			headerValue: "2025-01",
			lookupKey:   "X-PINECONE-API-VERSION",
			description: "Uppercase lookup should work (HTTP headers are case-insensitive)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			resp := &http.Response{
				StatusCode: 401,
				Header:     make(http.Header),
			}
			resp.Header.Set(tt.headerKey, tt.headerValue)

			actualValue := resp.Header.Get(tt.lookupKey)

			if actualValue != tt.headerValue {
				t.Errorf("Header.Get(%q) = %q, want %q\nDescription: %s",
					tt.lookupKey, actualValue, tt.headerValue, tt.description)
			}
		})
	}
}
