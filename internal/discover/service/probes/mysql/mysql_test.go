package mysql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseVersionString tests the parseVersionString function for various MySQL-family version strings.
func TestParseVersionString(t *testing.T) {
	tests := []struct {
		name           string
		versionStr     string
		wantServerType string
		wantVersion    string
	}{

		{"MySQL 8.0.28", "8.0.28", "mysql", "8.0.28"},
		{"MySQL 5.7.40", "5.7.40", "mysql", "5.7.40"},
		{"MySQL 8.0.28 with distro", "8.0.28-0ubuntu0.20.04.3", "mysql", "8.0.28"},
		{"MySQL 5.6.51", "5.6.51", "mysql", "5.6.51"},

		{"MariaDB 10.5.12", "10.5.12-MariaDB", "mariadb", "10.5.12"},
		{"MariaDB 11.0.3", "11.0.3-MariaDB-1:11.0.3+maria~ubu2204", "mariadb", "11.0.3"},
		{"MariaDB with legacy prefix", "5.5.5-10.5.12-MariaDB", "mariadb", "10.5.12"},
		{"MariaDB 10.4.7", "10.4.7-MariaDB", "mariadb", "10.4.7"},
		{"MariaDB 10.5.19 with distro", "10.5.19-MariaDB-0+deb11u2", "mariadb", "10.5.19"},

		{"Percona 8.0.28-19", "8.0.28-19-Percona", "percona", "8.0.28-19"},
		{"Percona 5.7.40-43", "5.7.40-43-Percona", "percona", "5.7.40-43"},
		{"Percona 8.0.28-20", "8.0.28-20-Percona Server", "percona", "8.0.28-20"},

		{"Aurora MySQL 3.x", "8.0.mysql_aurora.3.11.0", "aurora", "3.11.0"},
		{"Aurora MySQL 2.x", "5.7.mysql_aurora.2.11.0", "aurora", "2.11.0"},

		{"Empty string", "", "unknown", ""},
		{"Invalid format", "not-a-version", "unknown", ""},
		{"Random text", "random text without version", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverType, version := parseVersionString(tt.versionStr)
			assert.Equal(t, tt.wantServerType, serverType, "server type mismatch")
			assert.Equal(t, tt.wantVersion, version, "version mismatch")
		})
	}
}

// TestBuildMySQLCPE tests the buildMySQLCPE function for generating correct CPE strings.
func TestBuildMySQLCPE(t *testing.T) {
	tests := []struct {
		name       string
		serverType string
		version    string
		wantCPE    string
	}{

		{"MySQL with version", "mysql", "8.0.28", "cpe:2.3:a:oracle:mysql:8.0.28:*:*:*:*:*:*:*"},
		{"MySQL 5.7.40", "mysql", "5.7.40", "cpe:2.3:a:oracle:mysql:5.7.40:*:*:*:*:*:*:*"},
		{"MySQL wildcard version", "mysql", "", "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},

		{"MariaDB with version", "mariadb", "10.5.12", "cpe:2.3:a:mariadb:mariadb:10.5.12:*:*:*:*:*:*:*"},
		{"MariaDB 11.0.3", "mariadb", "11.0.3", "cpe:2.3:a:mariadb:mariadb:11.0.3:*:*:*:*:*:*:*"},
		{"MariaDB wildcard version", "mariadb", "", "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"},

		{"Percona with version", "percona", "8.0.28-19", "cpe:2.3:a:percona:percona_server:8.0.28-19:*:*:*:*:*:*:*"},
		{"Percona 5.7.40-43", "percona", "5.7.40-43", "cpe:2.3:a:percona:percona_server:5.7.40-43:*:*:*:*:*:*:*"},
		{"Percona wildcard version", "percona", "", "cpe:2.3:a:percona:percona_server:*:*:*:*:*:*:*:*"},

		{"Aurora with version", "aurora", "3.11.0", "cpe:2.3:a:amazon:aurora:3.11.0:*:*:*:*:*:*:*"},
		{"Aurora 2.11.0", "aurora", "2.11.0", "cpe:2.3:a:amazon:aurora:2.11.0:*:*:*:*:*:*:*"},
		{"Aurora wildcard version", "aurora", "", "cpe:2.3:a:amazon:aurora:*:*:*:*:*:*:*:*"},

		{"Unknown with version", "unknown", "1.0.0", "cpe:2.3:a:oracle:mysql:1.0.0:*:*:*:*:*:*:*"},
		{"Unknown wildcard version", "unknown", "", "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},

		{"Empty server empty version", "", "", "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},
		{"Empty server with version", "", "1.0.0", "cpe:2.3:a:oracle:mysql:1.0.0:*:*:*:*:*:*:*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildMySQLCPE(tt.serverType, tt.version)
			assert.Equal(t, tt.wantCPE, cpe, "CPE mismatch")
		})
	}
}
