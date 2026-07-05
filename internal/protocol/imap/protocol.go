// Package imap implements the IMAP4rev1/IMAP4rev2 wire protocol primitives
// shared between the enumerate (Mode A — fingerprint) and pentest (Mode B —
// authenticated actions) tools.
package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"

	imapfern "github.com/Method-Security/networkscan/generated/go/pentest/imap"
	"github.com/Method-Security/networkscan/internal/netdial"
)

// implicitTLSPeekTimeout caps how long we wait for an IMAP server to deliver
// its untagged "* OK" greeting before concluding the listener actually wants
// TLS (e.g. on port 993 / IMAPS).
const implicitTLSPeekTimeout = 2 * time.Second

// ErrImplicitTLSSuspected signals that a plain TCP dial succeeded but the
// listener did not send an IMAP greeting within implicitTLSPeekTimeout. The
// caller should close the connection and retry with implicit TLS.
var ErrImplicitTLSSuspected = fmt.Errorf("no IMAP greeting on plain socket; implicit TLS suspected")

// ErrSTARTTLSRejected signals that the server replied tagged NO/BAD to
// STARTTLS. The underlying plain IMAP connection is still usable — callers
// may continue cleartext (subject to their own plaintext policy) rather than
// teardown the session. Distinct from a TLS handshake failure, which leaves
// the socket mid-negotiation and unrecoverable. Wrap with %w so callers can
// use errors.Is.
var ErrSTARTTLSRejected = fmt.Errorf("STARTTLS rejected by server")

// DeadlineFromContext returns the absolute deadline from ctx. If the context
// has no deadline, it falls back to a 30 second budget from now. Using the
// absolute deadline (rather than re-computing now+duration on each call)
// ensures later commands cannot extend past the per-target timeout budget.
func DeadlineFromContext(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(30 * time.Second)
}

// isTimeout reports whether err is a net.Error with Timeout() == true.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

// bufferedConn wraps a net.Conn with a bufio.Reader so that bytes the reader
// pre-fetches during greeting detection are not discarded when the caller later
// creates a new textproto.Conn on the same underlying connection.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

// Read satisfies net.Conn — all reads go through the bufio.Reader.
func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// TryTCPConnection connects via plain TCP and peeks for the untagged IMAP
// greeting. An implicit-TLS listener never sends a plaintext greeting; if the
// first byte isn't '*', we fall back to TLS.
func TryTCPConnection(ctx context.Context, host string, port int) (net.Conn, string, error) {
	deadline := DeadlineFromContext(ctx)
	dialTimeout := time.Until(deadline)
	if dialTimeout <= 0 {
		dialTimeout = time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := netdial.DialContext(ctx, "tcp", addr, netdial.WithTimeout(dialTimeout))
	if err != nil {
		return nil, "", err
	}

	_ = conn.SetReadDeadline(time.Now().Add(implicitTLSPeekTimeout))
	reader := bufio.NewReader(conn)
	peek, peekErr := reader.Peek(1)

	switch {
	case peekErr == nil && len(peek) == 1 && peek[0] == '*':
		// IMAP greeting detected — proceed plaintext.
	case isTimeout(peekErr):
		// On the IANA-assigned IMAPS port a silent listener is almost
		// certainly implicit TLS; on other ports keep the connection and
		// let the full timeout apply for slow plaintext servers.
		if port == DefaultImapsPort {
			_ = conn.Close()
			return nil, "", ErrImplicitTLSSuspected
		}
	default:
		_ = conn.Close()
		return nil, "", ErrImplicitTLSSuspected
	}

	_ = conn.SetReadDeadline(deadline)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("failed to read greeting: %w", err)
	}
	return &bufferedConn{Conn: conn, r: reader}, strings.TrimRight(greeting, "\r\n"), nil
}

// TryTLSConnection connects directly via TLS (IMAPS) and reads the greeting.
//
// InsecureSkipVerify is intentional: this is a probe-style dial against
// pentest targets that routinely present self-signed certs, wrong CN /
// SAN, expired chains, or are intentionally vulnerable. Failing on cert
// validation would silently drop those targets from scope, which is the
// opposite of the tool's purpose. Matches the established repo pattern in
// internal/enumerate/imap/helpers.go, internal/enumerate/pop3/helpers.go,
// internal/enumerate/smtp/helpers.go, internal/discover/tls.go, etc.
func TryTLSConnection(ctx context.Context, host string, port int) (*tls.Conn, string, error) {
	deadline := DeadlineFromContext(ctx)
	dialTimeout := time.Until(deadline)
	if dialTimeout <= 0 {
		dialTimeout = time.Second
	}
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // see function doc — pentest probe, untrusted certs expected
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := netdial.DialContext(ctx, "tcp", addr, netdial.WithTimeout(dialTimeout))
	if err != nil {
		return nil, "", err
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, "", err
	}
	_ = tlsConn.SetReadDeadline(deadline)
	tconn := textproto.NewConn(tlsConn)
	greeting, err := tconn.ReadLine()
	if err != nil {
		_ = tlsConn.Close()
		return nil, "", fmt.Errorf("failed to read greeting: %w", err)
	}
	return tlsConn, greeting, nil
}

// DoSTARTTLS upgrades a plain connection to TLS via the IMAP STARTTLS command.
//
// Failure semantics: any non-nil error returned indicates the underlying
// `conn` is in an undefined state (the server may have started its TLS
// handshake mid-stream). Callers MUST close `conn` themselves on error —
// continuing to send cleartext IMAP on it will race the server's TLS
// expectation and corrupt protocol state. The function closes `conn` itself
// when the handshake started but failed (rejected STARTTLS command leaves
// the plain connection usable, so we don't close in that case).
func DoSTARTTLS(ctx context.Context, conn net.Conn, host string) (*tls.Conn, error) {
	const tag = "A001"
	tconn := textproto.NewConn(conn)
	if err := tconn.PrintfLine("%s STARTTLS", tag); err != nil {
		return nil, fmt.Errorf("STARTTLS send failed: %w", err)
	}
	_ = conn.SetReadDeadline(DeadlineFromContext(ctx))
	for {
		resp, err := tconn.ReadLine()
		if err != nil {
			return nil, fmt.Errorf("STARTTLS response read failed: %w", err)
		}
		if strings.HasPrefix(resp, tag+" OK") {
			break
		}
		if strings.HasPrefix(resp, tag+" NO") || strings.HasPrefix(resp, tag+" BAD") {
			// Server rejected STARTTLS — plain channel is still valid. Wrap
			// the sentinel so callers can detect this case via errors.Is and
			// keep using the plain connection (per ErrSTARTTLSRejected doc).
			return nil, fmt.Errorf("%w: %s", ErrSTARTTLSRejected, resp)
		}
	}
	// InsecureSkipVerify is intentional: same rationale as TryTLSConnection —
	// STARTTLS-served servers in pentest scope routinely present untrusted
	// certs and the tool's purpose is to enumerate them, not validate their
	// PKI. See repo-wide pattern at internal/enumerate/imap/helpers.go etc.
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // pentest probe — untrusted certs expected
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		// Server-side STARTTLS already accepted but our TLS handshake failed
		// — underlying socket is now mid-TLS-negotiation. Close it so the
		// caller can't accidentally reuse it.
		_ = conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

// parseLiteralCount returns the RFC 3501 literal octet count if line ends
// with "{N}" or "{N+}" (non-synchronising literal), otherwise 0.
func parseLiteralCount(line string) int {
	trimmed := strings.TrimRight(line, " \t")
	if !strings.HasSuffix(trimmed, "}") {
		return 0
	}
	start := strings.LastIndex(trimmed, "{")
	if start < 0 {
		return 0
	}
	inner := trimmed[start+1 : len(trimmed)-1]
	inner = strings.TrimSuffix(inner, "+")
	n, err := strconv.Atoi(inner)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// SendCommand sends a tagged IMAP command and reads response lines until the
// tagged completion (OK/NO/BAD). Returns all lines including the final tagged
// line. Tagged NO/BAD is surfaced as an error so partial output is not
// mistaken for success.
func SendCommand(ctx context.Context, conn net.Conn, tag, cmd string) ([]string, error) {
	_ = conn.SetDeadline(DeadlineFromContext(ctx))
	tconn := textproto.NewConn(conn)
	if err := tconn.PrintfLine("%s %s", tag, cmd); err != nil {
		return nil, fmt.Errorf("command send failed: %w", err)
	}
	var lines []string
	for {
		resp, err := tconn.ReadLine()
		if err != nil {
			return lines, fmt.Errorf("response read error: %w", err)
		}
		lines = append(lines, resp)
		if strings.HasPrefix(resp, tag+" OK") {
			break
		}
		if strings.HasPrefix(resp, tag+" NO") || strings.HasPrefix(resp, tag+" BAD") {
			return lines, fmt.Errorf("IMAP %s response: %s", strings.TrimSpace(strings.TrimPrefix(resp, tag)), resp)
		}
		// Handle RFC 3501 literal: when a line ends with "{N}" or "{N+}",
		// the next N bytes are literal data. Read them through the same
		// textproto bufio.Reader so the stream stays in sync.
		if n := parseLiteralCount(resp); n > 0 {
			literal := make([]byte, n)
			if _, err := io.ReadFull(tconn.R, literal); err != nil {
				return lines, fmt.Errorf("literal read (%d bytes) failed: %w", n, err)
			}
			litStr := strings.ReplaceAll(string(literal), "\r\n", "\n")
			litLines := strings.Split(litStr, "\n")
			if len(litLines) > 0 && litLines[len(litLines)-1] == "" {
				litLines = litLines[:len(litLines)-1]
			}
			lines = append(lines, litLines...)
		}
	}
	return lines, nil
}

// ParseCapabilities extracts capability tokens from a CAPABILITY response.
// Handles both "* CAPABILITY ..." and "A001 OK [CAPABILITY ...]" formats.
func ParseCapabilities(line string) []string {
	if idx := strings.Index(line, "[CAPABILITY "); idx >= 0 {
		end := strings.Index(line[idx:], "]")
		if end > 0 {
			inner := line[idx+len("[CAPABILITY ") : idx+end]
			return strings.Fields(inner)
		}
	}
	upper := strings.ToUpper(line)
	capIdx := strings.Index(upper, "CAPABILITY ")
	if capIdx >= 0 {
		rest := line[capIdx+len("CAPABILITY "):]
		return strings.Fields(rest)
	}
	return nil
}

// ParseFolders parses LIST response lines into ImapFolder values.
// LIST response format: * LIST (\HasNoChildren) "/" "INBOX"
func ParseFolders(lines []string) []*imapfern.ImapFolder {
	var folders []*imapfern.ImapFolder
	listRe := regexp.MustCompile(`^\* LIST \(([^)]*)\) ("(?:[^"\\]|\\.)*"|NIL) (.+)$`)
	for _, line := range lines {
		if !strings.HasPrefix(line, "* LIST ") {
			continue
		}
		matches := listRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		attrStr := matches[1]
		delimiter := strings.Trim(matches[2], `"`)
		if delimiter == "NIL" {
			delimiter = ""
		}
		nameStr := strings.Trim(strings.TrimSpace(matches[3]), `"`)

		var attrs []string
		if attrStr != "" {
			for _, a := range strings.Split(attrStr, " ") {
				a = strings.TrimSpace(a)
				if a != "" {
					attrs = append(attrs, a)
				}
			}
		}
		folder := &imapfern.ImapFolder{Name: nameStr}
		if delimiter != "" {
			folder.Delimiter = &delimiter
		}
		if len(attrs) > 0 {
			folder.Attributes = attrs
		}
		folders = append(folders, folder)
	}
	return folders
}

// ParseFolderStatus parses a single STATUS response line.
// STATUS response: * STATUS INBOX (MESSAGES 1234 RECENT 0 UNSEEN 42 UIDNEXT 5678 UIDVALIDITY 1234567890)
func ParseFolderStatus(line string) *imapfern.ImapFolderStatus {
	if !strings.HasPrefix(line, "* STATUS ") {
		return nil
	}
	rest := line[len("* STATUS "):]
	parenIdx := strings.Index(rest, "(")
	if parenIdx < 0 {
		return nil
	}
	folderName := strings.Trim(strings.TrimSpace(rest[:parenIdx]), `"`)

	inner := rest[parenIdx+1:]
	if closeIdx := strings.Index(inner, ")"); closeIdx >= 0 {
		inner = inner[:closeIdx]
	}
	status := &imapfern.ImapFolderStatus{FolderName: folderName}
	fields := strings.Fields(inner)
	for i := 0; i+1 < len(fields); i += 2 {
		key := strings.ToUpper(fields[i])
		val, err := strconv.Atoi(fields[i+1])
		if err != nil {
			continue
		}
		switch key {
		case "MESSAGES":
			status.Messages = &val
		case "RECENT":
			status.Recent = &val
		case "UNSEEN":
			status.Unseen = &val
		case "UIDNEXT":
			status.UidNext = &val
		case "UIDVALIDITY":
			status.UidValidity = &val
		}
	}
	return status
}

// ParseUIDFetchHeaders parses UID FETCH response lines into ImapMessageHeaders
// keyed by UID. Each message is delimited by "* N FETCH ( ... UID ... )".
func ParseUIDFetchHeaders(folderName string, lines []string, maxMessages int) []*imapfern.ImapMessageHeaders {
	var messages []*imapfern.ImapMessageHeaders
	var currentMsg *imapfern.ImapMessageHeaders
	inHeader := false
	uidRe := regexp.MustCompile(`UID (\d+)`)

	for _, line := range lines {
		if strings.HasPrefix(line, "* ") && strings.Contains(line, " FETCH ") {
			// Reset per-message UID so a missing UID on this FETCH doesn't
			// silently inherit the previous message's UID.
			uid := 0
			if uidMatch := uidRe.FindStringSubmatch(line); uidMatch != nil {
				if u, err := strconv.Atoi(uidMatch[1]); err == nil {
					uid = u
				}
			}
			currentMsg = &imapfern.ImapMessageHeaders{
				FolderName: folderName,
				Uid:        uid,
			}
			inHeader = true
			continue
		}
		if inHeader && currentMsg != nil {
			if line == ")" || strings.HasPrefix(line, ")") {
				messages = append(messages, currentMsg)
				currentMsg = nil
				inHeader = false
				if maxMessages > 0 && len(messages) >= maxMessages {
					break
				}
				continue
			}
			if idx := strings.Index(line, ": "); idx >= 0 {
				key := strings.ToLower(strings.TrimSpace(line[:idx]))
				val := strings.TrimSpace(line[idx+2:])
				switch key {
				case "from":
					currentMsg.From = &val
				case "to":
					currentMsg.To = &val
				case "subject":
					currentMsg.Subject = &val
				case "date":
					currentMsg.Date = &val
				}
			}
		}
	}
	return messages
}

// StripCRLF removes carriage-return and line-feed characters to prevent CRLF
// injection in IMAP command lines sent via textproto.PrintfLine.
func StripCRLF(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// ImapQuoteString wraps s in an IMAP double-quoted string literal per
// RFC 3501 §4.3. Backslash and double-quote are escaped; CR/LF are stripped.
func ImapQuoteString(s string) string {
	s = StripCRLF(s)
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return `"` + s + `"`
}
