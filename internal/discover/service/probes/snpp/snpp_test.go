// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol tests adapted for networkscan.
package snpp

import (
	"testing"

	plugins "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
)

// TestIsValidSNPPBanner tests the SNPP banner validation logic
func TestIsValidSNPPBanner(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected bool
		reason   string
	}{
		{
			name:     "valid SNPP banner - standard",
			response: []byte("220 SNPP Gateway Ready\r\n"),
			expected: true,
			reason:   "Valid SNPP greeting with 220 code and SNPP in text",
		},
		{
			name:     "valid SNPP banner - with version",
			response: []byte("220 SNPP (V3) Gateway Ready\r\n"),
			expected: true,
			reason:   "Valid SNPP greeting with version indicator",
		},
		{
			name:     "valid SNPP banner - lowercase",
			response: []byte("220 snpp gateway ready\r\n"),
			expected: true,
			reason:   "Valid SNPP greeting with lowercase (case-insensitive match)",
		},
		{
			name:     "valid SNPP banner - mixed case",
			response: []byte("220 SnPp Gateway Ready\r\n"),
			expected: true,
			reason:   "Valid SNPP greeting with mixed case",
		},
		{
			name:     "valid SNPP banner - with hyphen separator",
			response: []byte("220-SNPP Gateway Ready\r\n"),
			expected: true,
			reason:   "Valid SNPP greeting with hyphen separator",
		},
		{
			name:     "invalid - wrong response code",
			response: []byte("221 SNPP Gateway Ready\r\n"),
			expected: false,
			reason:   "Wrong response code (221 instead of 220)",
		},
		{
			name:     "invalid - missing SNPP keyword",
			response: []byte("220 Gateway Ready\r\n"),
			expected: false,
			reason:   "No SNPP keyword in response",
		},
		{
			name:     "invalid - too short",
			response: []byte("22"),
			expected: false,
			reason:   "Response too short (less than 3 bytes)",
		},
		{
			name:     "invalid - empty response",
			response: []byte{},
			expected: false,
			reason:   "Empty response",
		},
		{
			name:     "invalid - 4xx error code",
			response: []byte("421 SNPP Service not available\r\n"),
			expected: false,
			reason:   "Error response code (421)",
		},
		{
			name:     "invalid - 5xx error code",
			response: []byte("500 SNPP Syntax error\r\n"),
			expected: false,
			reason:   "Error response code (500)",
		},
		{
			name:     "valid SNPP banner - with hostname",
			response: []byte("220 snpp.example.com SNPP Gateway Ready\r\n"),
			expected: true,
			reason:   "Valid SNPP greeting with hostname",
		},
		{
			name:     "valid SNPP banner - minimal",
			response: []byte("220 SNPP\r\n"),
			expected: true,
			reason:   "Minimal valid SNPP greeting",
		},
		{
			name:     "invalid - SMTP not SNPP",
			response: []byte("220 smtp.example.com ESMTP Postfix\r\n"),
			expected: false,
			reason:   "SMTP banner, not SNPP",
		},
		{
			name:     "invalid - FTP not SNPP",
			response: []byte("220 FTP server ready\r\n"),
			expected: false,
			reason:   "FTP banner, not SNPP",
		},
		{
			name:     "invalid - random data with 220",
			response: []byte("220 Random service\r\n"),
			expected: false,
			reason:   "Has 220 code but no SNPP keyword",
		},
		{
			name:     "valid SNPP banner - with extra spaces",
			response: []byte("220   SNPP   Gateway   Ready\r\n"),
			expected: true,
			reason:   "Valid SNPP greeting with extra spaces",
		},
		{
			name:     "invalid - SNPP in wrong position",
			response: []byte("SNPP 220 Gateway Ready\r\n"),
			expected: false,
			reason:   "SNPP keyword before response code (invalid format)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSNPPBanner(tt.response)
			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v. Reason: %s",
					tt.name, tt.expected, result, tt.reason)
			}
		})
	}
}

// TestSNPPPlugin validates the plugin interface implementation
func TestSNPPPlugin(t *testing.T) {
	plugin := &SNPPPlugin{}

	if plugin.Name() != "snpp" {
		t.Errorf("Name(): expected %q, got %q", "snpp", plugin.Name())
	}

	if plugin.Type() != plugins.TCP {
		t.Errorf("Type(): expected TCP, got %v", plugin.Type())
	}

	if plugin.Priority() != 10 {
		t.Errorf("Priority(): expected 10, got %d", plugin.Priority())
	}

	testPorts := []struct {
		port     uint16
		expected bool
	}{
		{444, true},
		{25, false},
		{443, false},
		{445, false},
		{80, false},
		{8080, false},
	}

	for _, tp := range testPorts {
		result := plugin.PortPriority(tp.port)
		if result != tp.expected {
			t.Errorf("PortPriority(%d): expected %v, got %v",
				tp.port, tp.expected, result)
		}
	}
}
