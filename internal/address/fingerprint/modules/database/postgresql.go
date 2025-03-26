package database

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	addressfern "github.com/Method-Security/networkscan/generated/go/address"
	"github.com/jackc/pgx/v5"
)

type PostgreSQLLibrary struct{}

func (c *PostgreSQLLibrary) Name() *addressfern.AddressFingerprintResourceModule {
	return addressfern.NewAddressFingerprintResourceModuleFromDatabaseModule(addressfern.DatabaseModulePostgresql)
}

func (c *PostgreSQLLibrary) StandardPorts() []int {
	return []int{5432}
}

func (c *PostgreSQLLibrary) TryProtocols(address string, timeout time.Duration) addressfern.TryProtocols {
	tryProtocolsFunction := addressfern.TryProtocols{
		Protocol: "PostgreSQL",
	}
	var errors []string

	log.Printf("[INFO] Attempting PostgreSQL protocol fingerprint via pgx at: %s\n", address)

	response, err := grabPostgreSQLBanner(address, timeout)
	if err != nil {
		log.Printf("[ERROR] Connection attempt resulted in error: %s\n", err)
		errors = append(errors, err.Error())
	}

	if response != nil && c.AnalyzeResponse(*response) {
		log.Printf("[INFO] PostgreSQL protocol detected. Response: %s\n", *response)
		tryProtocolsFunction.ConnectionData = response
	} else {
		log.Printf("[INFO] No PostgreSQL protocol detected.")
	}

	tryProtocolsFunction.Errors = errors
	return tryProtocolsFunction
}

// grabPostgreSQLBanner attempts a pgx connection and returns the server's error response
func grabPostgreSQLBanner(address string, timeout time.Duration) (*string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	connStr := fmt.Sprintf("postgres://scanner@%s/?sslmode=disable&connect_timeout=%d", address, int(timeout.Seconds()))
	_, err := pgx.Connect(ctx, connStr)
	if err != nil {
		errMsg := err.Error()
		return &errMsg, nil
	}

	// Connection succeeded without error — unexpected, but valid
	msg := "PostgreSQL accepted connection without authentication"
	return &msg, nil
}

// AnalyzeResponse checks if the response contains PostgreSQL keywords in error or banner messages
func (c *PostgreSQLLibrary) AnalyzeResponse(data string) bool {
	data = strings.ToLower(data)

	keywords := []string{
		"postgresql",
		"psql",
		"pg_hba.conf",
		"sqlstate",
	}

	for _, keyword := range keywords {
		if strings.Contains(data, keyword) {
			return true
		}
	}
	return false
}
