package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"

	_ "github.com/go-sql-driver/mysql" // MySQL driver
)

func collectMetadata(ctx context.Context, db *sql.DB) ([]string, error) {
	metadataQueries := []struct {
		name  string
		query string
	}{
		{"Server Version", "SELECT @@version"},
		{"Database Version", "SELECT version()"},
		{"Server Variables", "SHOW VARIABLES"},
		{"Server Status", "SHOW STATUS"},
		{"Server Character Set", "SHOW CHARACTER SET"},
		{"Server Collation", "SHOW COLLATION"},
		{"Server Engine Status", "SHOW ENGINE INNODB STATUS"},
		{"Server Plugins", "SHOW PLUGINS"},
		{"Databases", "SHOW DATABASES"},
		{"Server Timezone", "SELECT @@global.time_zone"},
	}

	var exposedData []string
	for _, mq := range metadataQueries {
		log.Printf("[INFO] Attempting to get %s\n", mq.name)

		rows, err := db.QueryContext(ctx, mq.query)
		if err != nil {
			log.Printf("[ERROR] Failed to query %s: %s\n", mq.name, err)
			return nil, err
		}

		// Get column names
		columns, err := rows.Columns()
		if err != nil {
			log.Printf("[ERROR] Failed to get columns for %s: %s\n", mq.name, err)
			return nil, err
		}

		// Prepare holders for row data
		values := make([]sql.RawBytes, len(columns))
		scanArgs := make([]interface{}, len(values))
		for i := range values {
			scanArgs[i] = &values[i]
		}

		// Record the metadata category
		exposedData = append(exposedData, fmt.Sprintf("=== %s ===", mq.name))

		// Fetch rows
		for rows.Next() {
			err = rows.Scan(scanArgs...)
			if err != nil {
				log.Printf("[ERROR] Failed to scan row for %s: %s\n", mq.name, err)
				return nil, err
			}

			// Build row output
			var rowData string
			for i, col := range values {
				if col != nil {
					rowData += fmt.Sprintf("%s: %s, ", columns[i], string(col))
				}
			}
			if rowData != "" {
				exposedData = append(exposedData, rowData)
			}
		}

		if err = rows.Err(); err != nil {
			log.Printf("[ERROR] Error iterating rows for %s: %s\n", mq.name, err)
			return nil, err
		}

		err = rows.Close()
		if err != nil {
			log.Printf("[ERROR] Failed to close rows for %s: %s\n", mq.name, err)
			return nil, err
		}
	}

	return exposedData, nil
}

func grabMySQLBanner(target string) (string, error) {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return "", fmt.Errorf("failed to establish TCP connection: %v", err)
	}

	banner := make([]byte, 2048)
	n, err := conn.Read(banner)
	if err != nil {
		return "", fmt.Errorf("failed to read banner: %v", err)
	}

	bannerStr := string(banner[:n])
	fmt.Printf("[DEBUG] Raw MySQL Banner: %s\n", bannerStr)

	err = conn.Close()
	if err != nil {
		return bannerStr, fmt.Errorf("failed to close connection: %v", err)
	}

	return bannerStr, nil
}

// isMySQLBanner checks if the banner contains MySQL fingerprints
func isMySQLBanner(banner string) bool {
	for _, pattern := range []string{
		// Authentication Methods
		"caching_sha2_password",
		"mysql_native_password",
		"mysql_old_password",
		"mysql_clear_password",

		// Server Version and Type
		"mariadb",
		"percona",

		// Default Database Names
		"information_schema",
		"performance_schema",
		"mysql",

		// MySQL Configuration and Keywords
		"max_connections",
		"sql_mode",
		"secure_file_priv",

		// MySQL Error Messages or Status Codes
		"er_access_denied_error",
		"er_bad_db_error",
		"er_no_such_table",
	} {
		if strings.Contains(strings.ToLower(banner), pattern) {
			return true
		}
	}

	return false
}
