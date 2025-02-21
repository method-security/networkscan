package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	databaseFern "github.com/Method-Security/networkscan/generated/go/database"
	_ "github.com/go-sql-driver/mysql" // MySQL driver
)

// RunMySQLEnumerate Overview:
//  1. Connect to the target
//     a. Exit if connection isnt established
//  2. Grab the MySQL banner
//     a. Exit if no banner is returned (assume MySQL is not implemented)
//     b. Else set successful connection to true
//  3. Check if the MySQL banner is valid
//     a. If not, set fingerprinted to false and exit
//  4. Check if the root user with no password is allowed
//     a. If not, set password required to true and exit
//  5. Grab the metadata from the database
//     a. Server Version
//     b. Database Version
//     c. Server Variables
//     d. Server Status
//     e. Server Character Set
//     f. Server Collation
//     g. Server Engine Status
//     h. Server Plugins
//     i. Databases
//     j. Server Timezone

func RunMySQLEnumerate(ctx context.Context, targets []string, timeout int) (databaseFern.DatabaseEnumerateReport, error) {
	log.Printf("[INFO] Starting MySQL enumeration for %d targets with a timeout of %ds", len(targets), timeout)
	report := databaseFern.DatabaseEnumerateReport{
		Targets:      targets,
		DatabaseType: databaseFern.DatabaseTypeMysql,
	}

	// Create channels for collecting results and errors
	detailsChan := make(chan *databaseFern.DatabaseEnumerateDetails, len(targets))
	errorsChan := make(chan string, len(targets))
	var wg sync.WaitGroup

	// Process each target concurrently
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()

			// Create a context with timeout for each target
			targetCtx, targetCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
			defer targetCancel()

			// Start enumeration in a separate goroutine
			resultChan := make(chan struct {
				detail *databaseFern.DatabaseEnumerateDetails
				err    error
			}, 1)

			go func() {
				detail, err := enumerateTarget(targetCtx, target)
				resultChan <- struct {
					detail *databaseFern.DatabaseEnumerateDetails
					err    error
				}{detail, err}
			}()

			// Wait for either completion or timeout
			select {
			case <-targetCtx.Done():
				if targetCtx.Err() == context.DeadlineExceeded {
					errMsg := fmt.Sprintf("Parameter timeout (%ds) while enumerating %s", timeout, target)
					errorsChan <- errMsg
					log.Printf("[ERROR] %s", errMsg)
				}
			case result := <-resultChan:
				// Always add details if we have them
				if result.detail != nil {
					detailsChan <- result.detail
					log.Printf("[INFO] Collected enumeration details for target %s", target)
				}

				// Handle any errors
				if result.err != nil {
					errorsChan <- result.err.Error()
					log.Printf("[ERROR] Error while enumerating target %s: %s", target, result.err)
				} else {
					log.Printf("[INFO] Successfully enumerated target %s", target)
				}
			}
		}(i, target)
	}

	// Create a goroutine to close channels after all workers are done
	go func() {
		wg.Wait()
		close(detailsChan)
		close(errorsChan)
	}()

	// Collect results
	var details []*databaseFern.DatabaseEnumerateDetails
	var errors []string

	// Read from channels until they're closed
	for detail := range detailsChan {
		details = append(details, detail)
	}
	for err := range errorsChan {
		errors = append(errors, err)
	}

	log.Printf("[INFO] Enumeration complete. Processed %d targets with %d errors", len(targets), len(errors))
	report.DatabaseDetails = details
	report.Errors = errors
	return report, nil
}

func enumerateTarget(ctx context.Context, target string) (*databaseFern.DatabaseEnumerateDetails, error) {
	detail := databaseFern.DatabaseEnumerateDetails{
		Target: target,
	}

	log.Printf("[INFO] Attempting to grab banner from MySQL server at: %s\n", target)
	banner, err := grabMySQLBanner(target)
	if err != nil {
		log.Printf("[ERROR] Failed to grab banner from %s: %s\n", target, err)
		return &detail, err
	}
	log.Printf("[INFO] Successfully grabbed banner from %s\n", target)
	detail.Banner = &banner

	log.Printf("[INFO] Successfully connected to %s\n", target)
	connected := true
	detail.Connected = &connected

	if !isMySQLBanner(banner) {
		log.Printf("[ERROR] %s does not contain MySQL fingerprints", target)
		return &detail, fmt.Errorf("MySQL banner not found")
	}

	fingerprinted := true
	detail.Fingerprinted = &fingerprinted

	log.Printf("[INFO] Attempting to connect to MySQL server at: %s\n", target)
	dsn := fmt.Sprintf("root:@tcp(%s)/", target)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("[ERROR] Failed to create connection to %s: %s\n", target, err)

		return &detail, err
	}

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
