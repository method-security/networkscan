package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	database "github.com/Method-Security/networkscan/generated/go/database"
	utilsFern "github.com/Method-Security/networkscan/generated/go/utils"
	_ "github.com/go-sql-driver/mysql" // MySQL driver
)

// LibraryEnumerateMySQL implements NetworkApplicationLibrary for MySQL enumeration.
type LibraryEnumerateMySQL struct{}

// EnumerateTarget Overview:
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

func (d *LibraryEnumerateMySQL) EnumerateTarget(ctx context.Context, target string) (*utilsFern.NetworkApplicationEnumerateDetails, []string) {
	detail := database.DatabaseEnumerateDetails{
		Target:       target,
		DatabaseType: database.DatabaseTypeMysql,
	}
	errors := []string{}

	log.Printf("[INFO] Attempting to grab banner from MySQL server at: %s\n", target)
	banner, err := grabMySQLBanner(target)
	if err != nil {
		log.Printf("[ERROR] Failed to grab banner from %s: %s\n", target, err)
		errors = append(errors, fmt.Sprintf("Failed to grab banner from %s: %v", target, err))
		return utilsFern.NewNetworkApplicationEnumerateDetailsFromDatabaseEnumerateDetails(&detail), errors
	}
	log.Printf("[INFO] Successfully grabbed banner from %s\n", target)
	detail.Banner = &banner

	log.Printf("[INFO] Successfully connected to %s\n", target)
	connected := true
	detail.Connected = &connected

	if !isMySQLBanner(banner) {
		log.Printf("[ERROR] %s does not contain MySQL fingerprints", target)
		errors = append(errors, fmt.Sprintf("%s does not contain MySQL fingerprints", target))
		return utilsFern.NewNetworkApplicationEnumerateDetailsFromDatabaseEnumerateDetails(&detail), errors
	}

	fingerprinted := true
	detail.Fingerprinted = &fingerprinted

	log.Printf("[INFO] Attempting to connect to MySQL server at: %s\n", target)
	dsn := fmt.Sprintf("root:@tcp(%s)/", target)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("[ERROR] Failed to create connection to %s: %s\n", target, err)
		errors = append(errors, fmt.Sprintf("Failed to create connection to %s: %v", target, err))
		return utilsFern.NewNetworkApplicationEnumerateDetailsFromDatabaseEnumerateDetails(&detail), errors
	}

	err = db.PingContext(ctx)
	if err != nil {
		connected := false
		detail.Connected = &connected
		log.Printf("[ERROR] Failed to connect to %s: %s\n", target, err)
		errors = append(errors, fmt.Sprintf("Failed to connect to %s: %v", target, err))
		if strings.Contains(err.Error(), "Access denied for user") {
			passwordRequired := true
			detail.PasswordRequired = &passwordRequired
		}
		return utilsFern.NewNetworkApplicationEnumerateDetailsFromDatabaseEnumerateDetails(&detail), errors
	}

	// Set the password to false as we are using the root user
	passwordRequired := false
	detail.PasswordRequired = &passwordRequired

	exposedData, err := collectMetadata(ctx, db)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error collecting metadata: %v", err))
		return utilsFern.NewNetworkApplicationEnumerateDetailsFromDatabaseEnumerateDetails(&detail), errors
	}

	err = db.Close()
	if err != nil {
		log.Printf("[ERROR] Failed to close connection to %s: %s\n", target, err)
		errors = append(errors, fmt.Sprintf("Failed to close connection to %s: %v", target, err))
	}

	detail.ExposedData = exposedData
	log.Printf("[INFO] Completed metadata collection for %s\n", target)
	return utilsFern.NewNetworkApplicationEnumerateDetailsFromDatabaseEnumerateDetails(&detail), errors
}
