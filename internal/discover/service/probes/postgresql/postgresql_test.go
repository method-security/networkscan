package postgres

import (
	"testing"
)

// TestParseParameterStatus tests parsing of PostgreSQL ParameterStatus messages
func TestParseParameterStatus(t *testing.T) {
	tests := []struct {
		name      string
		msg       []byte
		wantName  string
		wantValue string
		wantErr   bool
	}{
		{
			name: "server_version parameter",
			msg: []byte{
				0x53,
				0x00, 0x00, 0x00, 0x1D,

				0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x76,
				0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00,

				0x31, 0x34, 0x2e, 0x35, 0x00,
			},
			wantName:  "server_version",
			wantValue: "14.5",
			wantErr:   false,
		},
		{
			name: "application_name parameter",
			msg: []byte{
				0x53,
				0x00, 0x00, 0x00, 0x19,

				0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
				0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00,

				0x70, 0x73, 0x71, 0x6c, 0x00,
			},
			wantName:  "application_name",
			wantValue: "psql",
			wantErr:   false,
		},
		{
			name: "client_encoding parameter",
			msg: []byte{
				0x53,
				0x00, 0x00, 0x00, 0x17,

				0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65,
				0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00,

				0x55, 0x54, 0x46, 0x38, 0x00,
			},
			wantName:  "client_encoding",
			wantValue: "UTF8",
			wantErr:   false,
		},
		{
			name:      "message too short",
			msg:       []byte{0x53, 0x00},
			wantName:  "",
			wantValue: "",
			wantErr:   true,
		},
		{
			name: "wrong message type",
			msg: []byte{
				0x52,
				0x00, 0x00, 0x00, 0x08,
				0x00, 0x00, 0x00, 0x00,
			},
			wantName:  "",
			wantValue: "",
			wantErr:   true,
		},
		{
			name: "missing null terminators",
			msg: []byte{
				0x53,
				0x00, 0x00, 0x00, 0x10,

				0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x76,
				0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
			},
			wantName:  "",
			wantValue: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotValue, err := parseParameterStatus(tt.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseParameterStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotName != tt.wantName {
				t.Errorf("parseParameterStatus() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotValue != tt.wantValue {
				t.Errorf("parseParameterStatus() gotValue = %v, want %v", gotValue, tt.wantValue)
			}
		})
	}
}

// TestBuildPostgreSQLCPE tests CPE generation for PostgreSQL
func TestBuildPostgreSQLCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "version 14.5",
			version: "14.5",
			want:    "cpe:2.3:a:postgresql:postgresql:14.5:*:*:*:*:*:*:*",
		},
		{
			name:    "version 16.1",
			version: "16.1",
			want:    "cpe:2.3:a:postgresql:postgresql:16.1:*:*:*:*:*:*:*",
		},
		{
			name:    "version 17.2",
			version: "17.2",
			want:    "cpe:2.3:a:postgresql:postgresql:17.2:*:*:*:*:*:*:*",
		},
		{
			name:    "version 9.6.24",
			version: "9.6.24",
			want:    "cpe:2.3:a:postgresql:postgresql:9.6.24:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildPostgreSQLCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildPostgreSQLCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}
