package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"time"

	databaseFern "github.com/Method-Security/networkscan/generated/go/database"
	_ "github.com/lib/pq" // PostgreSQL driver
)

func grabPostgresBanner(target string, timeout int) (string, error) {
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to establish TCP connection: %v", err)
	}

	banner := make([]byte, 1024)
	n, err := conn.Read(banner)
	if err != nil {
		return "", fmt.Errorf("failed to read banner: %v", err)
	}

	bannerStr := string(banner[:n])
	fmt.Printf("Raw PostgreSQL Banner: %s\n", bannerStr)

	err = conn.Close()
	if err != nil {
		return bannerStr, fmt.Errorf("failed to close connection: %v", err)
	}

	return bannerStr, nil
}

func RunPostgresEnumerate(ctx context.Context, targets []string, timeout int) (databaseFern.DatabaseEnumerateReport, error) {
	report := databaseFern.DatabaseEnumerateReport{
		Targets:      targets,
		DatabaseType: databaseFern.DatabaseTypePostgresql,
	}
	errors := []string{}

	// Metadata queries that might work without authentication
	metadataQueries := []struct {
		name  string
		query string
	}{
		{"Server Version", "SELECT version()"},
		{"Server Variables", "SHOW ALL"},
		{"Databases", "SELECT datname FROM pg_database"},
		{"Server Timezone", "SHOW timezone"},
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	details := []*databaseFern.DatabaseEnumerateDetails{}
	for _, target := range targets {
		detail := databaseFern.DatabaseEnumerateDetails{
			Target: target,
		}

		// First grab the banner
		log.Printf("Attempting to grab banner from PostgreSQL server at: %s\n", target)
		banner, err := grabPostgresBanner(target, timeout)
		if err != nil {
			log.Printf("Failed to grab banner from %s: %s\n", target, err)
			errors = append(errors, err.Error())
		} else {
			log.Printf("Successfully grabbed banner from %s\n", target)
			detail.Banner = &banner
		}

		log.Printf("Attempting to connect to PostgreSQL server at: %s\n", target)

		// PostgreSQL connection string without authentication
		dsn := fmt.Sprintf("host=%s", target)
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			log.Printf("Failed to create connection to %s: %s\n", target, err)
			errors = append(errors, err.Error())
			continue
		}

		db.SetConnMaxLifetime(time.Duration(timeout) * time.Second)

		err = db.PingContext(ctx)
		if err != nil {
			connected := false
			detail.Connected = &connected
			errors = append(errors, fmt.Sprintf("Failed to connect to %s: %s", target, err))
			details = append(details, &detail)
			continue
		}

		log.Printf("Successfully connected to %s\n", target)
		connected := true
		detail.Connected = &connected
		var exposedData []string

		// Try each metadata query
		for _, mq := range metadataQueries {
			log.Printf("Attempting to get %s\n", mq.name)

			rows, err := db.QueryContext(ctx, mq.query)
			if err != nil {
				log.Printf("Failed to query %s: %s\n", mq.name, err)
				errors = append(errors, fmt.Sprintf("Failed to query %s: %s", mq.name, err))
				continue
			}

			// Get column names
			columns, err := rows.Columns()
			if err != nil {
				log.Printf("Failed to get columns for %s: %s\n", mq.name, err)
				errors = append(errors, fmt.Sprintf("Failed to get columns for %s: %s", mq.name, err))
				continue
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
					log.Printf("Failed to scan row for %s: %s\n", mq.name, err)
					errors = append(errors, fmt.Sprintf("Failed to scan row for %s: %s", mq.name, err))
					continue
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
				log.Printf("Error iterating rows for %s: %s\n", mq.name, err)
				errors = append(errors, fmt.Sprintf("Error iterating rows for %s: %s", mq.name, err))
			}

			err = rows.Close()
			if err != nil {
				log.Printf("Failed to close rows for %s: %s\n", mq.name, err)
				errors = append(errors, fmt.Sprintf("Failed to close rows for %s: %s", mq.name, err))
			}
		}

		err = db.Close()
		if err != nil {
			log.Printf("Failed to close connection to %s: %s\n", target, err)
			errors = append(errors, fmt.Sprintf("Failed to close connection to %s: %s", target, err))
		}

		detail.ExposedData = exposedData
		details = append(details, &detail)
		log.Printf("Completed metadata collection for %s\n", target)
	}

	report.DatabaseDetails = details
	report.Errors = errors
	return report, nil
}
