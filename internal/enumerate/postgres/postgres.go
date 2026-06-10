// Package postgres provides PostgreSQL service enumeration via raw TCP SSLRequest
// and startup message handshake.
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

// maxMsgBodySize caps the per-message allocation in probeStartup.  A legitimate
// PostgreSQL server never sends individual startup messages larger than a few
// kilobytes; capping at 1 MiB prevents a hostile target from forcing an
// unbounded allocation via an oversized length field.
const maxMsgBodySize = 1 << 20 // 1 MiB

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

	// probeStart is used to compute a shrinking budget across serial probes so
	// that each subsequent probe receives at most the time still remaining from
	// the original budget rather than the full original timeout.
	probeStart := time.Now()

	// Step 1: Probe SSL support via SSLRequest.
	// probeSSL distinguishes a hard TCP-dial failure (dialFailed=true, host
	// unreachable) from a softer I/O failure that occurs after a successful dial
	// (e.g. the server closed the connection before acknowledging the SSLRequest).
	// Only a dial failure terminates enumeration; an I/O failure after dial means
	// we could not determine SSL support but the host is still reachable.
	sslSupported, dialFailed, sslErr := probeSSL(ctx, addr, timeout)
	if dialFailed {
		log.Info("PostgreSQL TCP dial failed",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("error", sslErr))
		errMsg := fmt.Sprintf("connection failed: %v", sslErr)
		details.Error = &errMsg
		errs = append(errs, errMsg)
		return &enumeratefern.EnumerateServiceDetails{EnumeratePostgresDetails: &details}, errs
	}
	if sslErr != nil {
		// I/O failed after TCP dial — SSL status unknown but host is reachable.
		log.Info("PostgreSQL SSL probe I/O error (continuing)",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("error", sslErr))
	} else if sslSupported != nil {
		// nil means ambiguous response — not 'S' or 'N' — so leave SslSupported unset.
		details.SslSupported = sslSupported
	}

	// Step 2: Probe startup message — get parameters and auth method.
	// Pass only the remaining portion of the original budget so that the serial
	// SSL + startup probes together stay within the initial timeout.
	startupTimeout := timeout - time.Since(probeStart)
	if startupTimeout <= 0 {
		startupTimeout = 100 * time.Millisecond
	}
	serverVersion, serverEncoding, integerDatetimes, timeZone, authMethod, sslRequired, startupErr := probeStartup(ctx, addr, startupTimeout)
	if sslRequired != nil {
		details.SslRequired = sslRequired
	}
	if startupErr != nil {
		// Only record the error if we received no useful data.  When the server
		// sends ParameterStatus messages and/or AuthenticationOk (trust) and then
		// closes the connection before BackendKeyData / ReadyForQuery, probeStartup
		// exits via break and returns "startup probe ended unexpectedly".  That
		// error is spurious when we already have version, encoding, or auth data.
		gotData := serverVersion != "" || serverEncoding != "" || authMethod != "" ||
			integerDatetimes != nil || timeZone != ""
		if gotData {
			log.Info("PostgreSQL startup probe closed early but data received (ignoring error)",
				svc1log.SafeParam("target", addr),
				svc1log.SafeParam("error", startupErr))
		} else {
			log.Info("PostgreSQL startup probe error",
				svc1log.SafeParam("target", addr),
				svc1log.SafeParam("error", startupErr))
			// Record error but don't return early — we may still have partial data.
			errMsg := startupErr.Error()
			details.Error = &errMsg
			errs = append(errs, errMsg)
		}
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
	// Pass the remaining budget so all three serial probes together stay within
	// the original timeout.
	if authMethod == "trust" {
		dbTimeout := timeout - time.Since(probeStart)
		if dbTimeout <= 0 {
			dbTimeout = 100 * time.Millisecond
		}
		databases, dbErr := probeDatabases(ctx, addr, dbTimeout)
		if dbErr != nil {
			log.Info("PostgreSQL database enumeration failed",
				svc1log.SafeParam("target", addr),
				svc1log.SafeParam("error", dbErr))
			// Propagate to callers so the report errors list reflects the failure,
			// consistent with how the MySQL enumerator handles probeDatabases errors.
			errMsg := fmt.Sprintf("database enumeration failed: %v", dbErr)
			details.Error = &errMsg
			errs = append(errs, errMsg)
		} else {
			details.Databases = databases
		}
	}

	return &enumeratefern.EnumerateServiceDetails{EnumeratePostgresDetails: &details}, errs
}

// probeSSL sends a PostgreSQL SSLRequest and returns whether SSL is supported.
// Returns (sslSupported, dialFailed, err).
//   - dialFailed=true, err≠nil: TCP dial failed — host is unreachable.
//   - dialFailed=false, err≠nil: dial succeeded but SSLRequest I/O failed — host
//     is reachable but SSL status could not be determined.
//   - dialFailed=false, err=nil, sslSupported=non-nil: probe succeeded.
//     *sslSupported is true for 'S' (SSL accepted) and false for 'N' (SSL rejected).
//   - dialFailed=false, err=nil, sslSupported=nil: received an ambiguous byte (not
//     'S' or 'N'); the service may not be PostgreSQL; SSL status left unset.
//
// ctx is used for the dial so that the probe respects context cancellation.
func probeSSL(ctx context.Context, addr string, timeout time.Duration) (sslSupported *bool, dialFailed bool, err error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, connErr := dialer.DialContext(ctx, "tcp", addr)
	if connErr != nil {
		return nil, true, fmt.Errorf("TCP dial failed: %w", connErr)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SSLRequest: int32 length=8, int32 requestCode=80877103
	msg := make([]byte, 8)
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], uint32(sslRequestCode))

	if _, writeErr := conn.Write(msg); writeErr != nil {
		return nil, false, fmt.Errorf("sending SSLRequest: %w", writeErr)
	}

	resp := make([]byte, 1)
	if _, readErr := io.ReadFull(conn, resp); readErr != nil {
		return nil, false, fmt.Errorf("reading SSL response: %w", readErr)
	}

	switch resp[0] {
	case 'S':
		v := true
		return &v, false, nil
	case 'N':
		v := false
		return &v, false, nil
	default:
		// Ambiguous byte — not a definitive PostgreSQL SSL response.
		// Leave sslSupported unset rather than falsely reporting unsupported.
		return nil, false, nil
	}
}

// probeStartup opens a plain TCP connection, sends a PostgreSQL StartupMessage, and reads
// server responses to extract version, encoding, timezone, auth method, and SSL-required status.
// ctx is used for the dial so that the probe respects context cancellation.
func probeStartup(ctx context.Context, addr string, timeout time.Duration) (serverVersion, serverEncoding string, integerDatetimes *bool, timeZone, authMethod string, sslRequired *bool, err error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, dialErr := dialer.DialContext(ctx, "tcp", addr)
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
		if msgBodyLen < 0 || msgBodyLen > maxMsgBodySize {
			// Malformed or oversized message — stop parsing.
			break
		}

		body := make([]byte, msgBodyLen)
		if msgBodyLen > 0 {
			if _, readErr := io.ReadFull(conn, body); readErr != nil {
				break
			}
		}

		switch msgType {
		case 'R': // Authentication message (AuthenticationRequest or AuthenticationOk)
			if len(body) >= 4 {
				authType := int32(binary.BigEndian.Uint32(body[0:4]))
				if authType == 0 {
					// AuthenticationOk (type 0): the server accepted the connection
					// without requiring any credentials.  Over a plain TCP connection
					// from a remote client this only happens when the pg_hba.conf
					// method is "trust".  Record it as such.
					// Distinct from an AuthenticationRequest (types 2–12) which asks
					// the client to provide proof of identity.
					authMethod = "trust"
				} else {
					authMethod = parseAuthMethod(authType, body[4:])
					// The server has issued an auth challenge (SCRAM, MD5, etc.).
					// It will not send ParameterStatus / BackendKeyData /
					// ReadyForQuery until we complete authentication, which we
					// don't do in an enumeration probe.  Return now rather than
					// blocking until the connection deadline.
					return
				}
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
			// Set sslRequired only when the error message indicates the server
			// rejected the connection because SSL was not used.  Exclude messages
			// that merely mention SSL in a different context (e.g. "SSL is not
			// enabled on the server", which means SSL is UNAVAILABLE rather than
			// REQUIRED).  The canonical PostgreSQL message for SSL-required
			// rejections is "no pg_hba.conf entry for … SSL off".
			lowerErr := strings.ToLower(errMsg)
			if strings.Contains(lowerErr, "ssl") &&
				!strings.Contains(lowerErr, "ssl is not enabled") &&
				!strings.Contains(lowerErr, "ssl not enabled") {
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
	// The loop exited via break (I/O error, EOF, truncated body, or oversized
	// message) rather than through a terminal message case ('R'/'E'/'K'/'Z').
	// Signal this to callers so they can distinguish a complete probe from one
	// that ended unexpectedly with only partial (or no) data.
	if err == nil {
		err = fmt.Errorf("startup probe ended unexpectedly (connection closed or I/O error during message read)")
	}
	return
}

// parseAuthMethod converts a PostgreSQL AuthenticationRequest type code (types 2–12)
// to a human-readable string.  Type 0 (AuthenticationOk) is intentionally excluded
// here — it is handled explicitly by the caller to distinguish "auth complete without
// credentials" from a genuine auth-method negotiation.
func parseAuthMethod(authType int32, extra []byte) string {
	switch authType {
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
		// No mechanism list in the SASL message body — return empty so the caller
		// leaves authMethod unset rather than guessing "scram-sha-256".
		return ""
	case 12:
		return "scram-sha-256-final"
	default:
		// Unknown type code: return empty string so the caller leaves authMethod
		// unset rather than emitting a sentinel like "unknown(8)" into the report.
		return ""
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
	// addr is already host:port — parse for separate host/port.
	host, port := utils.ParseHostPort(addr, defaultPort)
	dsn := fmt.Sprintf("host=%s port=%d user=postgres dbname=template1 sslmode=disable connect_timeout=%d",
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
