// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol tests adapted for networkscan.
package sybase

import (
	"testing"

	"github.com/Method-Security/networkscan/generated/go/common"
)

// TestValidateTDSResponse tests TDS packet header validation
func TestValidateTDSResponse(t *testing.T) {
	tests := []struct {
		name      string
		response  []byte
		shouldErr bool
		errInfo   string
	}{
		{
			name: "valid TDS response",
			response: []byte{
				0x04,
				0x01,
				0x00, 0x10,
				0x00, 0x00,
				0x01,
				0x00,
				0xFF,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			shouldErr: false,
		},
		{
			name:      "response too short",
			response:  []byte{0x04, 0x01, 0x00, 0x10},
			shouldErr: true,
			errInfo:   "too short",
		},
		{
			name: "invalid packet type",
			response: []byte{
				0x12,
				0x01,
				0x00, 0x10,
				0x00, 0x00,
				0x01,
				0x00,
				0xFF,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			shouldErr: true,
			errInfo:   "packet type",
		},
		{
			name: "invalid status",
			response: []byte{
				0x04,
				0x00,
				0x00, 0x10,
				0x00, 0x00,
				0x01,
				0x00,
				0xFF,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			shouldErr: true,
			errInfo:   "status",
		},
		{
			name: "length mismatch",
			response: []byte{
				0x04,
				0x01,
				0x00, 0x20,
				0x00, 0x00,
				0x01,
				0x00,
				0xFF,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			shouldErr: true,
			errInfo:   "mismatch",
		},
		{
			name: "invalid SPID",
			response: []byte{
				0x04,
				0x01,
				0x00, 0x10,
				0x00, 0x01,
				0x01,
				0x00,
				0xFF,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			shouldErr: true,
			errInfo:   "SPID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTDSResponse(tt.response)
			if tt.shouldErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errInfo)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

// TestParseTDSOptionTokens tests option token parsing
func TestParseTDSOptionTokens(t *testing.T) {
	tests := []struct {
		name          string
		response      []byte
		expectedCount int
		shouldErr     bool
		errInfo       string
	}{
		{
			name: "valid option tokens",
			response: buildValidTDSResponse(

				[]byte{0x00, 0x00, 0x00, 0x00, 0x06},

				[]byte{0x01, 0x00, 0x06, 0x00, 0x01},

				[]byte{0xFF},

				[]byte{0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00, 0x00},
			),
			expectedCount: 2,
			shouldErr:     false,
		},
		{
			name: "truncated option token",
			response: []byte{
				0x04, 0x01, 0x00, 0x10,
				0x00, 0x00, 0x01, 0x00,
				0x00, 0x00,
			},
			shouldErr: true,
			errInfo:   "truncated",
		},
		{
			name: "missing terminator",
			response: buildValidTDSResponse(

				[]byte{0x00, 0x00, 0x00, 0x00, 0x06},

				nil,

				[]byte{0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00},
			),
			shouldErr: true,
			errInfo:   "terminated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := parseTDSOptionTokens(tt.response)
			if tt.shouldErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errInfo)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if len(tokens) != tt.expectedCount {
					t.Errorf("expected %d tokens, got %d", tt.expectedCount, len(tokens))
				}
			}
		})
	}
}

// TestParseVersionString tests version string extraction
func TestParseVersionString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ASE with SP notation",
			input:    "Adaptive Server Enterprise/16.0 SP03",
			expected: "16.0.3",
		},
		{
			name:     "ASE full version with SP",
			input:    "Adaptive Server Enterprise/15.7.0 SP138",
			expected: "15.7.138",
		},
		{
			name:     "ASE major.minor only",
			input:    "Adaptive Server Enterprise/16.0",
			expected: "16.0",
		},
		{
			name:     "legacy Sybase SQL Server",
			input:    "Sybase SQL Server/12.5.4",
			expected: "12.5.4",
		},
		{
			name:     "no version pattern matches",
			input:    "Unknown Server",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseVersionString(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestExtractVersion tests version extraction and Sybase identification
func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name       string
		tokens     []OptionToken
		wantVer    string
		wantSybase bool
	}{
		{
			name: "Sybase ASE version",
			tokens: []OptionToken{
				{
					PLOptionToken: VERSION,
					PLOptionData:  []byte("Adaptive Server Enterprise/16.0 SP03"),
				},
			},
			wantVer:    "16.0.3",
			wantSybase: true,
		},
		{
			name: "Legacy Sybase",
			tokens: []OptionToken{
				{
					PLOptionToken: VERSION,
					PLOptionData:  []byte("Sybase SQL Server/12.5.4"),
				},
			},
			wantVer:    "12.5.4",
			wantSybase: true,
		},
		{
			name: "Microsoft SQL Server (not Sybase)",
			tokens: []OptionToken{
				{
					PLOptionToken: VERSION,
					PLOptionData:  []byte("Microsoft SQL Server/15.0.2000"),
				},
			},
			wantVer:    "",
			wantSybase: false,
		},
		{
			name: "Unknown server",
			tokens: []OptionToken{
				{
					PLOptionToken: VERSION,
					PLOptionData:  []byte("Unknown Database Server"),
				},
			},
			wantVer:    "",
			wantSybase: false,
		},
		{
			name:       "No VERSION token",
			tokens:     []OptionToken{},
			wantVer:    "",
			wantSybase: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVer, gotSybase := extractVersion(tt.tokens)
			if gotVer != tt.wantVer {
				t.Errorf("version: expected %q, got %q", tt.wantVer, gotVer)
			}
			if gotSybase != tt.wantSybase {
				t.Errorf("isSybase: expected %v, got %v", tt.wantSybase, gotSybase)
			}
		})
	}
}

// TestBuildSybaseCPE tests CPE generation
func TestBuildSybaseCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "version with patch",
			version:  "16.0.3",
			expected: "cpe:2.3:a:sap:adaptive_server_enterprise:16.0.3:*:*:*:*:*:*:*",
		},
		{
			name:     "version without patch",
			version:  "16.0",
			expected: "cpe:2.3:a:sap:adaptive_server_enterprise:16.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version (wildcard)",
			version:  "",
			expected: "cpe:2.3:a:sap:adaptive_server_enterprise:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version with whitespace",
			version:  "  16.0.3  ",
			expected: "cpe:2.3:a:sap:adaptive_server_enterprise:16.0.3:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSybaseCPE(tt.version)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestPluginInterface tests the Plugin interface implementation
func TestPluginInterface(t *testing.T) {
	plugin := &SybasePlugin{}

	if !plugin.PortPriority(5000) {
		t.Error("expected port 5000 to be priority")
	}
	if plugin.PortPriority(1433) {
		t.Error("expected port 1433 to not be priority")
	}

	if plugin.Name() != SYBASE {
		t.Errorf("expected name %q, got %q", SYBASE, plugin.Name())
	}

	if plugin.Type() != common.TransportTypeTcp {
		t.Errorf("expected type TCP, got %s", plugin.Type())
	}

	if plugin.Priority() != 145 {
		t.Errorf("expected priority 145, got %d", plugin.Priority())
	}
}

// Helper function to build valid TDS response for testing
func buildValidTDSResponse(tokens ...[]byte) []byte {
	var body []byte

	for _, token := range tokens {
		if token != nil {
			body = append(body, token...)
		}
	}

	totalLength := uint16(8 + len(body))

	header := []byte{
		0x04,
		0x01,
		byte(totalLength >> 8), byte(totalLength),
		0x00, 0x00,
		0x01,
		0x00,
	}

	return append(header, body...)
}

// BenchmarkValidateTDSResponse benchmarks TDS response validation
func BenchmarkValidateTDSResponse(b *testing.B) {
	response := []byte{
		0x04, 0x01, 0x00, 0x10,
		0x00, 0x00, 0x01, 0x00,
		0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validateTDSResponse(response)
	}
}

// BenchmarkParseVersionString benchmarks version string parsing
func BenchmarkParseVersionString(b *testing.B) {
	versionStr := "Adaptive Server Enterprise/16.0 SP03"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseVersionString(versionStr)
	}
}

// BenchmarkBuildSybaseCPE benchmarks CPE generation
func BenchmarkBuildSybaseCPE(b *testing.B) {
	version := "16.0.3"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildSybaseCPE(version)
	}
}
