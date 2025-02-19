package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	databaseFern "github.com/Method-Security/networkscan/generated/go/database"
	_ "github.com/go-sql-driver/mysql" // MySQL driver
)

func RunMySQLEnumerate(ctx context.Context, targets []string, connectionTimeout int) (databaseFern.DatabaseEnumerateReport, error) {
	report := databaseFern.DatabaseEnumerateReport{
		Targets:      targets,
		DatabaseType: databaseFern.DatabaseTypeMysql,
	}
	errors := []string{}

	details := []*databaseFern.DatabaseEnumerateDetails{}
	for i, target := range targets {
		log.Printf("[INFO] [%d/%d] Processing target: %s", i+1, len(targets), target)

		// Set a new clock for each target
		targetCtx, targetCancel := context.WithTimeout(ctx, time.Duration(connectionTimeout)*time.Second)
		defer targetCancel()

		detail, err := processTarget(targetCtx, target, connectionTimeout)
		if err != nil {
			errors = append(errors, err.Error())
		}
		details = append(details, detail)
	}

	report.DatabaseDetails = details
	report.Errors = errors
	return report, nil
}

func processTarget(ctx context.Context, target string, timeout int) (*databaseFern.DatabaseEnumerateDetails, error) {
	detail := databaseFern.DatabaseEnumerateDetails{
		Target: target,
	}

	log.Printf("[INFO] Attempting to grab banner from MySQL server at: %s\n", target)
	banner, err := grabMySQLBanner(target, timeout)
	if err != nil {
		log.Printf("[ERROR] Failed to grab banner from %s: %s\n", target, err)
		return &detail, err
	}
	log.Printf("[INFO] Successfully grabbed banner from %s\n", target)
	detail.Banner = &banner

	log.Printf("[INFO] Attempting to connect to MySQL server at: %s\n", target)
	dsn := fmt.Sprintf("root:@tcp(%s)/", target)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("[ERROR] Failed to create connection to %s: %s\n", target, err)

		return &detail, err
	}

	// Set the connection to timeout after the timeout period
	db.SetConnMaxLifetime(time.Duration(timeout) * time.Second)

	err = db.PingContext(ctx)
	if err != nil {
		connected := false
		detail.Connected = &connected
		log.Printf("[ERROR] Failed to connect to %s: %s\n", target, err)
		if strings.Contains(err.Error(), "Access denied for user") {
			passwordRequired := true
			detail.PasswordRequired = &passwordRequired
		}
		return &detail, err
	}

	// Set the password to false as we are using the root user
	passwordRequired := false
	detail.PasswordRequired = &passwordRequired

	log.Printf("[INFO] Successfully connected to %s\n", target)
	connected := true
	detail.Connected = &connected

	exposedData, err := collectMetadata(ctx, db)
	if err != nil {
		return &detail, err
	}

	err = db.Close()
	if err != nil {
		log.Printf("[ERROR] Failed to close connection to %s: %s\n", target, err)
	}

	detail.ExposedData = exposedData
	log.Printf("[INFO] Completed metadata collection for %s\n", target)
	return &detail, nil
}

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

func grabMySQLBanner(target string, timeout int) (string, error) {
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to establish TCP connection: %v", err)
	}

	banner := make([]byte, 2048)
	n, err := conn.Read(banner)
	if err != nil {
		return "", fmt.Errorf("failed to read banner: %v", err)
	}

	bannerStr := string(banner[:n])
	fmt.Printf("Raw MySQL Banner: %s\n", bannerStr)

	err = conn.Close()
	if err != nil {
		return bannerStr, fmt.Errorf("failed to close connection: %v", err)
	}

	return bannerStr, nil
}
