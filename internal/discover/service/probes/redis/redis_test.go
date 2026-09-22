package redis

import (
	"testing"
)

// TestExtractRedisVersion tests version extraction from INFO SERVER response
func TestExtractRedisVersion(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name: "standard INFO response with version",
			response: "# Server\r\n" +
				"redis_version:7.4.0\r\n" +
				"redis_git_sha1:c9d29f6a\r\n" +
				"redis_mode:standalone\r\n",
			want: "7.4.0",
		},
		{
			name: "older Redis version",
			response: "# Server\r\n" +
				"redis_version:5.0.14\r\n" +
				"os:Linux 5.10.0\r\n",
			want: "5.0.14",
		},
		{
			name: "version 6.x",
			response: "redis_version:6.2.7\r\n" +
				"redis_mode:cluster\r\n",
			want: "6.2.7",
		},
		{
			name:     "empty response",
			response: "",
			want:     "",
		},
		{
			name: "missing version field",
			response: "# Server\r\n" +
				"redis_mode:standalone\r\n",
			want: "",
		},
		{
			name:     "malformed response",
			response: "invalid response data",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRedisVersion(tt.response)
			if got != tt.want {
				t.Errorf("extractRedisVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildRedisCPE tests CPE generation for Redis servers
func TestBuildRedisCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "specific version",
			version: "7.4.0",
			want:    "cpe:2.3:a:redis:redis:7.4.0:*:*:*:*:*:*:*",
		},
		{
			name:    "older version",
			version: "5.0.14",
			want:    "cpe:2.3:a:redis:redis:5.0.14:*:*:*:*:*:*:*",
		},
		{
			name:    "version 6.x",
			version: "6.2.7",
			want:    "cpe:2.3:a:redis:redis:6.2.7:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version (wildcard)",
			version: "",
			want:    "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRedisCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildRedisCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}
