// Package mysql provides MySQL service enumeration functionality.
package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	mysqlfern "github.com/Method-Security/networkscan/generated/go/enumerate/mysql"
	"github.com/Method-Security/networkscan/utils"
	mysqldriver "github.com/go-sql-driver/mysql"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const defaultPort = 3306
const defaultTimeoutMs = 10000

// clientSSLCapability is the MySQL capability flag bit for SSL/TLS support.
const clientSSLCapability = 0x0800

// LibraryEnumerateMySQL implements NetworkApplicationLibrary for MySQL enumeration.
// It probes MySQL targets via raw TCP handshake (protocol v10) and anonymous login attempts.
type LibraryEnumerateMySQL struct{}

// EnumerateTarget connects to a MySQL instance, reads the server greeting to extract
// version and TLS capability, and attempts an anonymous login to enumerate databases.
func (m *LibraryEnumerateMySQL) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting MySQL enumeration", svc1log.SafeParam("target", target))

	details := mysqlfern.EnumerateMysqlDetails{Target: target}
	var errs []string

	host, port := utils.ParseHostPort(target, defaultPort)
	if host == "" {
		errs = append(errs, fmt.Sprintf("invalid target %q: could not parse host:port", target))
		return &enumeratefern.EnumerateServiceDetails{EnumerateMysqlDetails: &details}, errs
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

	// Step A: Raw TCP handshake — read MySQL server greeting to extract version and TLS capability.
	canConnect, version, banner, tlsSupported, handshakeErr := probeHandshake(ctx, addr, timeout)
	details.CanConnect = &canConnect

	if handshakeErr != nil {
		log.Info("MySQL handshake probe failed",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("error", handshakeErr))
		if !canConnect {
			// TCP dial itself failed — anonymous probe will also fail; report and return.
			errMsg := fmt.Sprintf("connection failed: %v", handshakeErr)
			details.Error = &errMsg
			errs = append(errs, errMsg)
			return &enumeratefern.EnumerateServiceDetails{EnumerateMysqlDetails: &details}, errs
		}
		// TCP connected but greeting was non-standard or truncated.
		// Do NOT record as an error yet — the driver probe may still succeed.
		// If it does, the non-standard greeting is not a meaningful failure.
		// If it doesn't, we surface the handshake issue below.
	}

	if version != "" {
		details.Version = &version
	}
	if banner != "" {
		details.Banner = &banner
	}
	// Only publish TLS status when capability flags were actually parsed from the greeting.
	if tlsSupported != nil {
		details.TlsSupported = tlsSupported
	}

	// Step B: Anonymous login attempt — always run when TCP connected.
	// Re-derive timeout from remaining context budget so a slow handshake does not starve this probe.
	anonTimeout := timeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < anonTimeout {
			anonTimeout = remaining
		}
	}
	allowsAnonymousLogin, databases, anonErr := probeAnonymousLogin(ctx, addr, anonTimeout)
	// Only set when the result is conclusive; nil means inconclusive (timeout, TLS error, etc.)
	if allowsAnonymousLogin != nil {
		details.AllowsAnonymousLogin = allowsAnonymousLogin
	}
	if anonErr != nil {
		log.Info("MySQL anonymous login probe",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("error", anonErr))
		// When the login itself succeeded but SHOW DATABASES (or row iteration) failed,
		// surface the failure in errs and details.Error so callers see the incomplete result.
		if allowsAnonymousLogin != nil && *allowsAnonymousLogin {
			errMsg := fmt.Sprintf("anonymous login succeeded but database enumeration failed: %v", anonErr)
			details.Error = &errMsg
			errs = append(errs, errMsg)
		}
	}
	if allowsAnonymousLogin != nil && *allowsAnonymousLogin {
		// Only publish databases when the slice is non-nil. A nil slice means
		// SHOW DATABASES itself failed and no rows were ever returned; publishing nil
		// blurs "query failed" with "zero databases visible". A non-nil but empty
		// slice (zero-row result) is meaningfully distinct and is published as [].
		if databases != nil {
			details.DefaultDatabases = databases
		}
		log.Info("MySQL anonymous login succeeded",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("databases", len(databases)))
	}

	// Surface the handshake failure only when the driver probe was also inconclusive or denied.
	// If anonymous login succeeded, the non-standard greeting is not a meaningful error.
	if handshakeErr != nil && (allowsAnonymousLogin == nil || !*allowsAnonymousLogin) {
		errMsg := fmt.Sprintf("non-standard server greeting: %v", handshakeErr)
		details.Error = &errMsg
		errs = append(errs, errMsg)
	}

	return &enumeratefern.EnumerateServiceDetails{EnumerateMysqlDetails: &details}, errs
}

// probeHandshake opens a raw TCP connection to addr and reads the MySQL server greeting packet
// (protocol version 10) to extract the server version string and TLS capability flag.
// Returns (canConnect, version, banner, tlsSupported, error).
// tlsSupported is nil when capability flags could not be parsed from the greeting.
func probeHandshake(ctx context.Context, addr string, timeout time.Duration) (bool, string, string, *bool, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, "", "", nil, fmt.Errorf("dial failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// Read 4-byte packet header: 3 bytes payload length (little-endian) + 1 byte sequence number.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return true, "", "", nil, fmt.Errorf("read packet header: %w", err)
	}

	// Payload length is 3 bytes little-endian.
	pktLen := int(binary.LittleEndian.Uint32(append(header[:3], 0)))
	if pktLen == 0 || pktLen > 16*1024*1024 {
		return true, "", "", nil, fmt.Errorf("unexpected packet length: %d", pktLen)
	}

	// Read the packet body.
	body := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return true, "", "", nil, fmt.Errorf("read packet body: %w", err)
	}

	// MySQL Protocol v10 greeting layout:
	//   body[0]        = protocol version (should be 10)
	//   body[1:]       = null-terminated server version string
	//   After null:      4 bytes connection_id
	//                    8 bytes auth-plugin-data-part-1
	//                    1 byte filler (0x00)
	//                    2 bytes capability flags (lower 16 bits, little-endian)
	if len(body) < 2 {
		return true, "", "", nil, fmt.Errorf("packet body too short: %d bytes", len(body))
	}

	// Check for MySQL error packet: first byte 0xff means the server replied with an
	// ERR_Packet instead of a handshake (common under overload or access rules).
	// Parsing such a payload as a v10 greeting would produce bogus version/banner/TLS data.
	if body[0] == 0xff {
		if len(body) >= 3 {
			errCode := binary.LittleEndian.Uint16(body[1:3])
			msgStart := 3
			if len(body) > 3 && body[3] == '#' {
				msgStart = 9 // skip SQL-state marker '#' + 5-byte SQL state
			}
			errMsg := ""
			if msgStart < len(body) {
				errMsg = string(body[msgStart:])
			}
			return true, "", "", nil, fmt.Errorf("server sent error packet (code %d): %s", errCode, errMsg)
		}
		return true, "", "", nil, fmt.Errorf("server sent error packet")
	}

	// Expect MySQL protocol version 10 (the standard v10 handshake).
	if body[0] != 0x0a {
		return true, "", "", nil, fmt.Errorf("unexpected protocol version byte 0x%02x (expected 0x0a for v10 handshake)", body[0])
	}

	// Parse null-terminated server version starting at body[1].
	nullIdx := bytes.IndexByte(body[1:], 0x00)
	if nullIdx < 0 {
		return true, "", "", nil, fmt.Errorf("could not find null terminator in server greeting")
	}

	serverVersion := string(body[1 : 1+nullIdx])

	// Offset after: 1 (proto version) + nullIdx (version string) + 1 (null byte) = 2 + nullIdx
	// Then: 4 (connection_id) + 8 (auth-data-1) + 1 (filler) = 13 bytes before capability flags.
	capOffset := 1 + nullIdx + 1 + 13
	var tlsSupported *bool
	if capOffset+2 <= len(body) {
		capLow := binary.LittleEndian.Uint16(body[capOffset : capOffset+2])
		supported := (capLow & clientSSLCapability) != 0
		tlsSupported = &supported
	}

	banner := fmt.Sprintf("MySQL %s", serverVersion)
	return true, serverVersion, banner, tlsSupported, nil
}

// probeAnonymousLogin attempts to authenticate with empty username and password via the MySQL driver.
// Returns (allowsAnonymousLogin, databases, error).
// allowsAnonymousLogin is nil when the probe result is inconclusive (e.g. timeout or TLS error);
// it is a pointer to false when the server conclusively denied the login.
func probeAnonymousLogin(ctx context.Context, addr string, timeout time.Duration) (*bool, []string, error) {
	cfg := mysqldriver.NewConfig()
	cfg.User = ""
	cfg.Passwd = ""
	cfg.Net = "tcp"
	cfg.Addr = addr
	cfg.Timeout = timeout
	cfg.ReadTimeout = timeout
	cfg.WriteTimeout = timeout
	dsn := cfg.FormatDSN()

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open connection: %w", err)
	}
	defer func() { _ = db.Close() }()

	db.SetConnMaxLifetime(timeout)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		// A MySQLError means the server responded at the protocol level — this is a conclusive denial.
		var mysqlErr *mysqldriver.MySQLError
		if errors.As(err, &mysqlErr) {
			denied := false
			return &denied, nil, fmt.Errorf("anonymous login denied by server (MySQL error %d): %w", mysqlErr.Number, err)
		}
		// All other errors (timeout, TLS negotiation failure, connection reset) are inconclusive —
		// we cannot determine whether anonymous login is allowed or not.
		return nil, nil, fmt.Errorf("ping failed (inconclusive — could not determine login status): %w", err)
	}

	// Anonymous login succeeded — enumerate databases.
	rows, err := db.QueryContext(pingCtx, "SHOW DATABASES")
	if err != nil {
		succeeded := true
		return &succeeded, nil, fmt.Errorf("SHOW DATABASES failed: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Initialize as empty (not nil) so a zero-row success serializes as [] not null.
	databases := make([]string, 0)
	for rows.Next() {
		var dbName string
		if err := rows.Scan(&dbName); err != nil {
			// Return partial results alongside the error so the caller can surface both.
			succeeded := true
			return &succeeded, databases, fmt.Errorf("scanning SHOW DATABASES row: %w", err)
		}
		databases = append(databases, dbName)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		succeeded := true
		return &succeeded, databases, fmt.Errorf("iterating SHOW DATABASES rows: %w", rowsErr)
	}

	succeeded := true
	return &succeeded, databases, nil
}
