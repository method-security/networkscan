package mssql

import (
	"testing"
)

// TestBuildMSSQLCPE_WithVersion tests CPE generation with a known version
func TestBuildMSSQLCPE_WithVersion(t *testing.T) {
	testcases := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "SQL Server 2019",
			version:  "15.0.2000",
			expected: "cpe:2.3:a:microsoft:sql_server:15.0.2000:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2017",
			version:  "14.0.1000",
			expected: "cpe:2.3:a:microsoft:sql_server:14.0.1000:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2016",
			version:  "13.0.5026",
			expected: "cpe:2.3:a:microsoft:sql_server:13.0.5026:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2014",
			version:  "12.0.6024",
			expected: "cpe:2.3:a:microsoft:sql_server:12.0.6024:*:*:*:*:*:*:*",
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := buildMSSQLCPE(tc.version)

			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// TestBuildMSSQLCPE_WithoutVersion tests CPE generation with unknown version (wildcard)
func TestBuildMSSQLCPE_WithoutVersion(t *testing.T) {
	version := ""
	expected := "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*"

	result := buildMSSQLCPE(version)

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}
