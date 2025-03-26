package database

import (
	"fmt"
	"log"
	"strings"
	"time"

	addressfern "github.com/Method-Security/networkscan/generated/go/address"
	"github.com/go-mysql-org/go-mysql/client"
)

type MySQLLibrary struct{}

func (c *MySQLLibrary) Name() *addressfern.AddressFingerprintResourceModule {
	return addressfern.NewAddressFingerprintResourceModuleFromDatabaseModule(addressfern.DatabaseModuleMysql)
}

func (c *MySQLLibrary) StandardPorts() []int {
	return []int{3306}
}

func (c *MySQLLibrary) TryProtocols(address string, timeout time.Duration) addressfern.TryProtocols {
	tryProtocolsFunction := addressfern.TryProtocols{
		Protocol: "MySQL",
	}
	errors := []string{}

	log.Printf("[INFO] Attempting MySQL handshake using go-mysql at: %s\n", address)

	response, err := grabMySQLHandshake(address, timeout)
	if err != nil {
		errors = append(errors, err.Error())
		tryProtocolsFunction.Errors = errors
		return tryProtocolsFunction
	}

	tryProtocolsFunction.ConnectionData = response
	tryProtocolsFunction.Errors = errors
	return tryProtocolsFunction
}

// grabMySQLHandshake connects using go-mysql and parses the server handshake
func grabMySQLHandshake(address string, _ time.Duration) (*string, error) {
	conn, err := client.Connect(address, "user", "password", "database")
	if err != nil {
		msg := err.Error()
		return &msg, nil
	}

	err = conn.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close connection: %v", err)
	}

	version := conn.GetServerVersion()
	return &version, nil
}

// AnalyzeResponse checks if the response contains MySQL keywords in error or banner messages
func (c *MySQLLibrary) AnalyzeResponse(data string) bool {
	if data == "" {
		return false
	}

	data = strings.ToLower(data)
	log.Printf("[INFO] Analyzing MySQL response: %s", data)

	mysqlPatterns := []string{
		"mysql",
		"mariadb",
		"error 1045", // Access denied
		"error 1044", // Access denied for database
		"error 2002", // Connection refused
		"error 2003", // Can't connect
		"error 2005", // Unknown MySQL server host
		"error 2006", // MySQL server has gone away
		"error 2013", // Lost connection during query
	}

	// Check string patterns
	for _, pattern := range mysqlPatterns {
		if strings.Contains(data, pattern) {
			log.Printf("[INFO] MySQL pattern matched: %s", pattern)
			return true
		}
	}

	return false
}
