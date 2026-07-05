// Package mssql provides MSSQL service enumeration functionality.
package mssql

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	mssqlfern "github.com/Method-Security/networkscan/generated/go/enumerate/mssql"
	"github.com/Method-Security/networkscan/internal/netdial"
	"github.com/Method-Security/networkscan/utils"
	mssqldriver "github.com/microsoft/go-mssqldb"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const defaultPort = 1433
const defaultTimeoutMs = 10000

// encryptMode byte values from the TDS PRELOGIN response.
const (
	encryptOff    = 0
	encryptOn     = 1
	encryptNotSup = 2
	encryptReq    = 3
)

// LibraryEnumerateMSSSQL implements NetworkApplicationLibrary for MSSQL enumeration.
// It probes MSSQL targets via TDS PRELOGIN, dummy-credential login, and SQL Browser UDP.
type LibraryEnumerateMSSSQL struct{}

// EnumerateTarget connects to an MSSQL instance, extracts server metadata via TDS PRELOGIN
// and a dummy-credential login attempt, and probes SQL Browser on UDP/1434 for named instances.
func (m *LibraryEnumerateMSSSQL) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting MSSQL enumeration", svc1log.SafeParam("target", target))

	details := mssqlfern.EnumerateMssqlDetails{Target: target}
	var errs []string

	host, port := utils.ParseHostPort(target, defaultPort)
	if host == "" {
		errs = append(errs, fmt.Sprintf("invalid target %q: could not parse host:port", target))
		return &enumeratefern.EnumerateServiceDetails{EnumerateMssqlDetails: &details}, errs
	}

	addr := utils.FormatHostPort(host, port)
	details.Target = addr

	// Step A: Raw PRELOGIN probe — extract encrypt mode.
	encryptMode, preloginErr := probePrelogin(ctx, host, port)
	if preloginErr != nil {
		log.Info("MSSQL PRELOGIN probe failed",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("error", preloginErr))
	} else {
		details.EncryptMode = encryptMode
	}

	// Step B: TDS login probe with dummy credentials — extract server info from error.
	canConnect, hostname, version, buildNumber, edition, loginErr := probeTDSLogin(ctx, host, port)
	details.CanConnect = &canConnect

	// Step C: SQL Browser UDP 1434 — discover named instances.
	// Run this BEFORE the canConnect early-return: UDP/1434 is independent of TCP
	// connectivity, so a host where the TCP port is blocked or misconfigured may
	// still respond to SSRP and expose named instances.
	namedInstances, browserErr := probeSQLBrowser(ctx, host)
	if browserErr != nil {
		log.Info("SQL Browser probe failed",
			svc1log.SafeParam("target", host),
			svc1log.SafeParam("error", browserErr))
	} else if len(namedInstances) > 0 {
		details.NamedInstances = namedInstances
	}

	if loginErr != nil && !canConnect {
		errMsg := fmt.Sprintf("connection failed: %v", loginErr)
		details.Error = &errMsg
		errs = append(errs, errMsg)
		return &enumeratefern.EnumerateServiceDetails{EnumerateMssqlDetails: &details}, errs
	}

	if hostname != "" {
		details.Hostname = &hostname
	}
	if version != "" {
		details.Version = &version
	}
	if buildNumber != "" {
		details.BuildNumber = &buildNumber
	}
	if edition != "" {
		details.Edition = &edition
	}

	log.Info("MSSQL enumeration complete", svc1log.SafeParam("target", addr))
	return &enumeratefern.EnumerateServiceDetails{EnumerateMssqlDetails: &details}, errs
}

// ctxRemaining returns the time remaining until ctx's deadline, or fallback if no deadline is set.
// Callers use this to set per-probe deadlines that respect the overall context budget rather than
// reusing a stale duration computed at request start.
func ctxRemaining(ctx context.Context, fallback time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			return remaining
		}
		return time.Millisecond // context already expired — let subsequent ops fail fast
	}
	return fallback
}

// probePrelogin sends a raw TDS PRELOGIN packet and reads the ENCRYPTION token from the response.
func probePrelogin(ctx context.Context, host string, port int) (*mssqlfern.MssqlEncryptMode, error) {
	addr := utils.FormatHostPort(host, port)
	timeout := ctxRemaining(ctx, time.Duration(defaultTimeoutMs)*time.Millisecond)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := netdial.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Set connection deadline to the context's absolute deadline (not time.Now()+timeout) so
	// the deadline is accurate even if earlier probes consumed part of the budget.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	// Build TDS PRELOGIN packet.
	// Option list: 2 entries (VERSION + ENCRYPTION), each 5 bytes (1 type + 2 offset + 2 length),
	// plus a 1-byte TERMINATOR sentinel (0xFF — no offset/length fields).
	// Option list size: 2*5 + 1 = 11 bytes
	// Data: 6 bytes (version placeholder) + 1 byte (encrypt request) = 7 bytes
	// Total payload: 11 + 7 = 18 bytes
	// Packet header: 8 bytes
	// Total: 26 bytes

	const (
		tokenVersion    = 0x00
		tokenEncryption = 0x01
		tokenTerminator = 0xFF

		// The TERMINATOR is a single sentinel byte with no offset/length fields.
		// Only VERSION and ENCRYPTION are full option entries (5 bytes each).
		optionListSize = 2*5 + 1 // 2 options × 5 bytes + 1-byte TERMINATOR = 11
		versionDataLen = 6
		encryptDataLen = 1
		payloadLen     = optionListSize + versionDataLen + encryptDataLen
		headerLen      = 8
		totalLen       = headerLen + payloadLen
	)

	versionOffset := uint16(optionListSize)
	encryptOffset := versionOffset + versionDataLen

	pkt := make([]byte, totalLen)
	// TDS packet header
	pkt[0] = 0x12 // PRELOGIN message type
	pkt[1] = 0x01 // EOM status
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[4] = 0x00 // SPID high
	pkt[5] = 0x00 // SPID low
	pkt[6] = 0x00 // packet ID
	pkt[7] = 0x00 // window

	// Option list starting at byte 8
	off := 8
	// VERSION token
	pkt[off] = tokenVersion
	binary.BigEndian.PutUint16(pkt[off+1:off+3], versionOffset)
	binary.BigEndian.PutUint16(pkt[off+3:off+5], versionDataLen)
	off += 5
	// ENCRYPTION token
	pkt[off] = tokenEncryption
	binary.BigEndian.PutUint16(pkt[off+1:off+3], encryptOffset)
	binary.BigEndian.PutUint16(pkt[off+3:off+5], encryptDataLen)
	off += 5
	// TERMINATOR
	pkt[off] = tokenTerminator
	off++ // off = 8 + 5 + 5 + 1 = 19; data starts at off = 19

	// VERSION data (6 bytes, all zero — client version not meaningful for probe)
	// Already zeroed.
	off += versionDataLen

	// ENCRYPTION data (1 byte) — request encryption off (0)
	pkt[off] = 0x00

	// Send packet
	if _, err := conn.Write(pkt); err != nil {
		return nil, fmt.Errorf("write PRELOGIN: %w", err)
	}

	// Read response header (8 bytes)
	respHeader := make([]byte, 8)
	if err := readFull(conn, respHeader); err != nil {
		return nil, fmt.Errorf("read PRELOGIN response header: %w", err)
	}
	// The server's PRELOGIN response carries TDS packet type 0x04 (tabular data/general response),
	// not 0x12 (which is only used for the client's PRELOGIN request).
	if respHeader[0] != 0x04 {
		return nil, fmt.Errorf("unexpected TDS response type 0x%02x (expected 0x04)", respHeader[0])
	}
	respLen := int(binary.BigEndian.Uint16(respHeader[2:4]))
	if respLen <= headerLen {
		return nil, fmt.Errorf("PRELOGIN response too short: %d bytes", respLen)
	}

	// Read the rest of the response
	payload := make([]byte, respLen-headerLen)
	if err := readFull(conn, payload); err != nil {
		return nil, fmt.Errorf("read PRELOGIN response payload: %w", err)
	}

	// Parse option list from payload to find ENCRYPTION token offset and length
	idx := 0
	for idx < len(payload) {
		tokenType := payload[idx]
		if tokenType == tokenTerminator {
			break
		}
		if idx+5 > len(payload) {
			break
		}
		dataOffset := int(binary.BigEndian.Uint16(payload[idx+1 : idx+3]))
		dataLen := int(binary.BigEndian.Uint16(payload[idx+3 : idx+5]))
		idx += 5

		if tokenType == tokenEncryption {
			if dataOffset < len(payload) && dataOffset+dataLen <= len(payload) && dataLen >= 1 {
				encByte := payload[dataOffset]
				mode := byteToEncryptMode(encByte)
				return mode, nil
			}
		}
	}

	return nil, fmt.Errorf("ENCRYPTION token not found in PRELOGIN response")
}

// byteToEncryptMode converts a TDS encrypt byte to the Fern MssqlEncryptMode enum.
// Returns nil for unrecognized values (e.g. byte 4 = strict TLS in newer SQL Server versions)
// so that callers leave encryptMode unset rather than reporting a wrong value.
func byteToEncryptMode(b byte) *mssqlfern.MssqlEncryptMode {
	var mode mssqlfern.MssqlEncryptMode
	switch b {
	case encryptOff:
		mode = mssqlfern.MssqlEncryptModeOff
	case encryptOn:
		mode = mssqlfern.MssqlEncryptModeOn
	case encryptNotSup:
		mode = mssqlfern.MssqlEncryptModeNotSup
	case encryptReq:
		mode = mssqlfern.MssqlEncryptModeReq
	default:
		return nil // unknown byte — leave encryptMode unset rather than guessing
	}
	return &mode
}

// probeTDSLogin attempts a TDS login with dummy credentials, extracting server info from the error.
// Returns: canConnect, hostname, version, buildNumber, edition, error.
func probeTDSLogin(ctx context.Context, host string, port int) (bool, string, string, string, string, error) {
	timeout := ctxRemaining(ctx, time.Duration(defaultTimeoutMs)*time.Millisecond)
	query := url.Values{}
	query.Add("app name", "NetworkScan")
	query.Add("TrustServerCertificate", "true")
	timeoutSecs := int(timeout.Seconds())
	if timeoutSecs < 1 {
		timeoutSecs = 1
	}
	query.Add("connection timeout", fmt.Sprintf("%d", timeoutSecs))

	u := &url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword("probe_user_nx", "probe_pass_nx"),
		Host:     utils.FormatHostPort(host, port),
		RawQuery: query.Encode(),
	}

	db, err := sql.Open("sqlserver", u.String())
	if err != nil {
		return false, "", "", "", "", fmt.Errorf("open connection: %w", err)
	}
	defer func() { _ = db.Close() }()

	db.SetConnMaxLifetime(timeout)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pingErr := db.PingContext(pingCtx)
	if pingErr == nil {
		// Connected with dummy creds — try to get version via query.
		row := db.QueryRowContext(pingCtx, "SELECT @@VERSION")
		var versionStr string
		if scanErr := row.Scan(&versionStr); scanErr == nil {
			version, buildNumber, edition := parseVersionString(versionStr)
			return true, "", version, buildNumber, edition, nil
		}
		return true, "", "", "", "", nil
	}

	// Check for MSSQL driver error — server responded, login failed (expected).
	var mssqlErr mssqldriver.Error
	if errors.As(pingErr, &mssqlErr) {
		hostname := mssqlErr.ServerName
		version, buildNumber, edition := extractServerInfoFromAllErrors(mssqlErr)
		return true, hostname, version, buildNumber, edition, nil
	}

	// Non-MSSQL error — connection truly failed.
	return false, "", "", "", "", pingErr
}

// extractServerInfoFromAllErrors checks the mssqlErr.All slice for version info.
func extractServerInfoFromAllErrors(mssqlErr mssqldriver.Error) (version, buildNumber, edition string) {
	// Check the All field for any version-bearing messages.
	for _, e := range mssqlErr.All {
		if v, b, ed := parseVersionString(e.Message); v != "" {
			return v, b, ed
		}
	}
	// Also check the main message.
	return parseVersionString(mssqlErr.Message)
}

// versionLineRE matches lines like: "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)"
// or "Microsoft SQL Server 2019 - 15.0.2000.5 (X64)".
var versionLineRE = regexp.MustCompile(`(?i)Microsoft SQL Server\s+(\d{4}[^-\n]*?)\s*-\s*([\d]+\.[\d]+\.[\d]+)`)

// parseVersionString extracts version, buildNumber, and edition from a @@VERSION string.
func parseVersionString(s string) (version, buildNumber, edition string) {
	if s == "" {
		return
	}

	m := versionLineRE.FindStringSubmatch(s)
	if len(m) >= 3 {
		year := strings.TrimSpace(m[1])
		build := strings.TrimSpace(m[2])
		version = "Microsoft SQL Server " + year
		buildNumber = build
	}

	// Extract edition from common patterns.
	editions := []string{
		"Enterprise Edition", "Standard Edition", "Developer Edition",
		"Express Edition", "Web Edition", "Workgroup Edition",
		"Enterprise", "Standard", "Developer", "Express", "Web", "Workgroup",
	}
	for _, ed := range editions {
		if strings.Contains(s, ed) {
			edition = ed
			break
		}
	}
	return
}

// probeSQLBrowser sends an SSRP instance list request to SQL Browser on UDP/1434
// and returns any named instance names parsed from the response.
func probeSQLBrowser(ctx context.Context, host string) ([]string, error) {
	timeout := ctxRemaining(ctx, time.Duration(defaultTimeoutMs)*time.Millisecond)
	addr := utils.FormatHostPort(host, 1434)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(dialCtx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP 1434: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Use the context's absolute deadline so the connection deadline doesn't outlive the
	// overall per-target budget.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	// SSRP instance list request: single byte 0x02
	if _, err := conn.Write([]byte{0x02}); err != nil {
		return nil, fmt.Errorf("write SSRP request: %w", err)
	}

	// Read response (max 16KB is typical for SSRP)
	resp := make([]byte, 16384)

	n, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("read SSRP response: %w", err)
	}
	if n < 3 {
		return nil, fmt.Errorf("SSRP response too short: %d bytes", n)
	}

	// Response format: byte 0x05, uint16 LE length, then semicolon-delimited key=value pairs.
	if resp[0] != 0x05 {
		return nil, fmt.Errorf("unexpected SSRP response type 0x%02x (expected 0x05)", resp[0])
	}

	payload := string(resp[3:n])
	return parseSSRPInstanceNames(payload), nil
}

// parseSSRPInstanceNames extracts instance names from the semicolon-delimited SSRP payload.
// The format is: "ServerName;HOST;InstanceName;MSSQLSERVER;..." repeated per instance.
func parseSSRPInstanceNames(payload string) []string {
	parts := strings.Split(payload, ";")
	var instances []string
	seen := make(map[string]bool)

	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], "InstanceName") {
			name := strings.TrimSpace(parts[i+1])
			if name != "" && !seen[name] {
				seen[name] = true
				instances = append(instances, name)
			}
		}
	}
	return instances
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return err
		}
	}
	return nil
}
