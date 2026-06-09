// Package postgres provides PostgreSQL service enumeration functionality.
package postgres

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	postgresfern "github.com/Method-Security/networkscan/generated/go/enumerate/postgres"
	"github.com/Method-Security/networkscan/utils"
	_ "github.com/lib/pq"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const defaultPort = 5432
const defaultTimeoutMs = 10000

// sslRequestCode is the PostgreSQL SSLRequest message code.
const sslRequestCode int32 = 80877103

// protocolVersion is the PostgreSQL v3.0 protocol version number.
const protocolVersion int32 = 196608

// LibraryEnumeratePostgres implements NetworkApplicationLibrary for PostgreSQL enumeration.
// It probes PostgreSQL targets via raw TCP SSLRequest and startup message handshake.
type LibraryEnumeratePostgres struct{}

// EnumerateTarget connects to a PostgreSQL instance, probes SSL support, reads startup message
// parameters, and optionally lists databases when trust authentication is observed.
func (p *LibraryEnumeratePostgres) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting PostgreSQL enumeration", svc1log.SafeParam("target", target))

	details := postgresfern.EnumeratePostgresDetails{Target: target}
	var errs []string

	host, port := utils.ParseHostPort(target, defaultPort)
	if host == "" {
		errs = append(errs, fmt.Sprintf("invalid target %q: could not parse host:port", target))
		return &enumeratefern.EnumerateServiceDetails{EnumeratePostgresDetails: &details}, errs
	}

	addr := utils.FormatHostPort(host, port)
	details.Target = addr

	// Derive timeout from context deadline if set, otherwise use default.
	timeoutMs := defaultTimeoutMs
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			timeoutMs = int(remaining.Milliseconds())
		}
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	// Step 1: Probe SSL support via SSLRequest.
	sslSupported, sslErr := probeSSL(addr, timeout)
	if sslErr != nil {
		log.Info("PostgreSQL SSL probe failed",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("error", sslErr))
		// TCP dial failure — stop here.
		errMsg := fmt.Sprintf("connection failed: %v", sslErr)
		details.Error = &errMsg
		errs = append(errs, errMsg)
		return &enumeratefern.EnumerateServiceDetails{EnumeratePostgresDetails: &details}, errs
	}
	details.SslSupported = &sslSupported

	// Step 2: Probe startup message — get parameters and auth method.
	serverVersion, serverEncoding, integerDatetimes, timeZone, authMethod, sslRequired, startupErr := probeStartup(addr, timeout)
	if sslRequired != nil {
		details.SslRequired = sslRequired
	}
	if startupErr != nil {
		log.Info("PostgreSQL startup probe error",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("error", startupErr))
		// Record error but don't return early — we may still have partial data.
		errMsg := startupErr.Error()
		details.Error = &errMsg
		errs = append(errs, errMsg)
	}

	if serverVersion != "" {
		details.ServerVersion = &serverVersion
	}
	if serverEncoding != "" {
		details.ServerEncoding = &serverEncoding
	}
	if integerDatetimes != nil {
		details.IntegerDatetimes = integerDatetimes
	}
	if timeZone != "" {
		details.TimeZone = &timeZone
	}
	if authMethod != "" {
		details.AuthMethod = &authMethod
	}

	// Step 3: If trust auth observed, enumerate databases.
	if authMethod == "trust" {
		databases, dbErr := probeDatabases(ctx, addr, timeout)
		if dbErr != nil {
			log.Info("PostgreSQL database enumeration failed",
				svc1log.SafeParam("target", addr),
				svc1log.SafeParam("error", dbErr))
		} else {
			details.Databases = databases
		}
	}

	return &enumeratefern.EnumerateServiceDetails{EnumeratePostgresDetails: &details}, errs
}

// probeSSL sends a PostgreSQL SSLRequest and returns whether SSL is supported.
// Returns (sslSupported, error). Error means TCP dial failure.
func probeSSL(addr string, timeout time.Duration) (bool, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, fmt.Errorf("TCP dial failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SSLRequest: int32 length=8, int32 requestCode=80877103
	msg := make([]byte, 8)
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], uint32(sslRequestCode))

	if _, err := conn.Write(msg); err != nil {
		return false, fmt.Errorf("sending SSLRequest: %w", err)
	}

	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false, fmt.Errorf("reading SSL response: %w", err)
	}

	return resp[0] == 'S', nil
}

// probeStartup opens a plain TCP connection, sends a PostgreSQL StartupMessage, and reads
// server responses to extract version, encoding, timezone, auth method, and SSL-required status.
func probeStartup(addr string, timeout time.Duration) (serverVersion, serverEncoding string, integerDatetimes *bool, timeZone, authMethod string, sslRequired *bool, err error) {
	conn, dialErr := net.DialTimeout("tcp", addr, timeout)
	if dialErr != nil {
		err = fmt.Errorf("TCP dial failed: %w", dialErr)
		return
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Build StartupMessage:
	// int32 length (including itself) + int32 protocol + key=value\0 pairs + \0
	params := "user\x00postgres\x00database\x00template1\x00application_name\x00networkscan\x00\x00"
	paramBytes := []byte(params)
	msgLen := int32(4 + 4 + len(paramBytes)) // length field + protocol + params
	msg := make([]byte, msgLen)
	binary.BigEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.BigEndian.PutUint32(msg[4:8], uint32(protocolVersion))
	copy(msg[8:], paramBytes)

	if _, writeErr := conn.Write(msg); writeErr != nil {
		err = fmt.Errorf("sending StartupMessage: %w", writeErr)
		return
	}

	// Read server messages until we have enough info or hit a terminal message.
	for {
		// Read message type byte.
		typeBuf := make([]byte, 1)
		if _, readErr := io.ReadFull(conn, typeBuf); readErr != nil {
			// EOF after partial data is acceptable.
			break
		}
		msgType := typeBuf[0]

		// Read message length (int32, includes itself).
		lenBuf := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, lenBuf); readErr != nil {
			break
		}
		msgBodyLen := int(binary.BigEndian.Uint32(lenBuf)) - 4
		if msgBodyLen < 0 {
			break
		}

		body := make([]byte, msgBodyLen)
		if msgBodyLen > 0 {
			if _, readErr := io.ReadFull(conn, body); readErr != nil {
				break
			}
		}

		switch msgType {
		case 'R': // AuthenticationRequest
			if len(body) >= 4 {
				authType := int32(binary.BigEndian.Uint32(body[0:4]))
				authMethod = parseAuthMethod(authType, body[4:])
			}
		case 'S': // ParameterStatus — key\0value\0
			key, val := parseKeyValue(body)
			switch key {
			case "server_version":
				serverVersion = val
			case "server_encoding":
				serverEncoding = val
			case "integer_datetimes":
				b := val == "on"
				integerDatetimes = &b
			case "TimeZone":
				timeZone = val
			}
		case 'E': // ErrorResponse
			errMsg := parseErrorMessage(body)
			if strings.Contains(strings.ToLower(errMsg), "ssl") {
				req := true
				sslRequired = &req
			}
			err = fmt.Errorf("server error: %s", errMsg)
			return
		case 'K': // BackendKeyData — server is ready
			return
		case 'Z': // ReadyForQuery
			return
		}
	}
	return
}

// parseAuthMethod converts a PostgreSQL auth type code to a human-readable string.
func parseAuthMethod(authType int32, extra []byte) string {
	switch authType {
	case 0:
		return "trust"
	case 2:
		return "kerberos"
	case 3:
		return "password"
	case 5:
		return "md5"
	case 7:
		return "gss"
	case 9:
		return "sspi"
	case 10:
		// SASL — parse mechanism name from the body.
		if len(extra) > 0 {
			// Null-terminated mechanism name.
			end := strings.IndexByte(string(extra), 0)
			if end > 0 {
				mech := strings.ToLower(string(extra[:end]))
				if strings.Contains(mech, "scram-sha-256") {
					return "scram-sha-256"
				}
				return mech
			}
			return "sasl"
		}
		return "scram-sha-256"
	case 12:
		return "scram-sha-256-final"
	default:
		return fmt.Sprintf("unknown(%d)", authType)
	}
}

// parseKeyValue parses a null-terminated key\0value\0 ParameterStatus body.
func parseKeyValue(body []byte) (key, value string) {
	s := string(body)
	parts := strings.SplitN(s, "\x00", 3)
	if len(parts) >= 2 {
		key = parts[0]
		value = parts[1]
	}
	return
}

// parseErrorMessage extracts the human-readable portion from a PostgreSQL ErrorResponse body.
func parseErrorMessage(body []byte) string {
	// ErrorResponse: sequence of (byte1 type, string value null-terminated) pairs, ending with \0.
	var msgs []string
	i := 0
	for i < len(body) {
		fieldType := body[i]
		i++
		if fieldType == 0 {
			break
		}
		end := strings.IndexByte(string(body[i:]), 0)
		if end < 0 {
			msgs = append(msgs, string(body[i:]))
			break
		}
		val := string(body[i : i+end])
		i += end + 1
		// 'M' = human-readable message, 'D' = detail, 'H' = hint
		if fieldType == 'M' || fieldType == 'D' {
			msgs = append(msgs, val)
		}
	}
	if len(msgs) > 0 {
		return strings.Join(msgs, "; ")
	}
	return string(body)
}

// probeDatabases connects as postgres user to template1 with trust auth and lists pg_database.
func probeDatabases(ctx context.Context, addr string, timeout time.Duration) ([]string, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=postgres dbname=template1 sslmode=disable connect_timeout=%d",
		addr, 0, int(timeout.Seconds())+1)

	// addr is already host:port — parse for separate host/port.
	host, port := utils.ParseHostPort(addr, defaultPort)
	dsn = fmt.Sprintf("host=%s port=%d user=postgres dbname=template1 sslmode=disable connect_timeout=%d",
		host, port, int(timeout.Seconds())+1)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open connection: %w", err)
	}
	defer func() { _ = db.Close() }()

	db.SetConnMaxLifetime(timeout)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, "SELECT datname FROM pg_database ORDER BY datname")
	if err != nil {
		return nil, fmt.Errorf("query pg_database: %w", err)
	}
	defer func() { _ = rows.Close() }()

	databases := make([]string, 0)
	for rows.Next() {
		var dbName string
		if err := rows.Scan(&dbName); err != nil {
			return databases, fmt.Errorf("scanning pg_database row: %w", err)
		}
		databases = append(databases, dbName)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return databases, fmt.Errorf("iterating pg_database rows: %w", rowsErr)
	}

	return databases, nil
}
