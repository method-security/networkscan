package imap

import (
	// Standard
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"

	// Generated
	imapfern "github.com/Method-Security/networkscan/generated/go/enumerate/imap"
)

// implicitTLSPeekTimeout caps how long we wait for an IMAP server to deliver
// its untagged "* OK" greeting before concluding the listener actually wants
// TLS (e.g. on port 993 / IMAPS).
const implicitTLSPeekTimeout = 2 * time.Second

// errImplicitTLSSuspected signals that a plain TCP dial succeeded but the
// listener did not send an IMAP greeting within implicitTLSPeekTimeout. The
// caller should close the connection and retry with implicit TLS.
var errImplicitTLSSuspected = fmt.Errorf("no IMAP greeting on plain socket; implicit TLS suspected")

// bufferedConn wraps a net.Conn with a bufio.Reader so that bytes the reader
// pre-fetches during greeting detection are not discarded when the caller later
// creates a new textproto.Conn on the same underlying connection.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

// Read satisfies net.Conn — all reads go through the bufio.Reader so
// pre-fetched bytes are consumed before the underlying socket is read again.
func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// tryTCPConnection connects to host:port via plain TCP, then peeks for the
// untagged IMAP greeting. IMAP greetings start with "* " (e.g. "* OK ...",
// "* PREAUTH ...", "* BYE ..."). An implicit-TLS listener (IMAPS on 993, or
// any port hosting implicit TLS) accepts the TCP connection and waits for
// the client's TLS ClientHello — it never sends a plaintext greeting. To
// avoid hanging in that case we peek with a short deadline; if the first
// byte is not '*', we return errImplicitTLSSuspected so the caller falls
// back to TLS.
func tryTCPConnection(host string, port int, timeout int) (net.Conn, string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, "", err
	}

	// Quick peek for the leading '*' of an IMAP untagged response.
	_ = conn.SetReadDeadline(time.Now().Add(implicitTLSPeekTimeout))
	reader := bufio.NewReader(conn)
	peek, peekErr := reader.Peek(1)
	if peekErr != nil || len(peek) == 0 || peek[0] != '*' {
		_ = conn.Close()
		return nil, "", errImplicitTLSSuspected
	}

	// Greeting is on its way; restore the full timeout and consume the line.
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	greeting, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("failed to read greeting: %w", err)
	}
	return &bufferedConn{Conn: conn, r: reader}, strings.TrimRight(greeting, "\r\n"), nil
}

// tryTLSConnection connects to host:port directly via TLS, reads the IMAP greeting line,
// and returns the open TLS connection plus the greeting string.
func tryTLSConnection(host string, port int, timeout int) (*tls.Conn, string, error) {
	// networkscan is a probe — we want to observe and report on the cert
	// presented (subject, cipher), not validate it. Self-signed, expired,
	// or wrong-CN certs are normal targets. Match the POP3 enumerator.
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, "", err
	}
	_ = tlsConn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	tconn := textproto.NewConn(tlsConn)
	greeting, err := tconn.ReadLine()
	if err != nil {
		_ = tlsConn.Close()
		return nil, "", fmt.Errorf("failed to read greeting: %w", err)
	}
	return tlsConn, greeting, nil
}

// doSTARTTLS upgrades an existing plain TCP connection to TLS using the IMAP STARTTLS command.
// It sends the STARTTLS command, reads the server response, then wraps the connection in TLS.
func doSTARTTLS(conn net.Conn, host string, timeout int) (*tls.Conn, error) {
	tconn := textproto.NewConn(conn)
	// Send STARTTLS command
	if err := tconn.PrintfLine("A001 STARTTLS"); err != nil {
		return nil, fmt.Errorf("STARTTLS send failed: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	resp, err := tconn.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("STARTTLS response read failed: %w", err)
	}
	if !strings.Contains(resp, "OK") {
		return nil, fmt.Errorf("STARTTLS rejected: %s", resp)
	}
	// Upgrade to TLS. See tryTLSConnection — probes don't validate.
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

// parseLiteralCount returns the RFC 3501 literal octet count if line ends
// with "{N}" or "{N+}" (non-synchronising literal), otherwise returns 0.
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
	inner = strings.TrimSuffix(inner, "+") // non-synchronising literal
	n, err := strconv.Atoi(inner)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// sendCommand sends a tagged IMAP command and collects all response lines until the
// tagged completion line (tag + OK/NO/BAD). Returns all lines including the final tagged line.
func sendCommand(conn net.Conn, tag, cmd string, timeout int) ([]string, error) {
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	tconn := textproto.NewConn(conn)
	line := fmt.Sprintf("%s %s", tag, cmd)
	if err := tconn.PrintfLine("%s", line); err != nil {
		return nil, fmt.Errorf("command send failed: %w", err)
	}
	var lines []string
	for {
		resp, err := tconn.ReadLine()
		if err != nil {
			return lines, fmt.Errorf("response read error: %w", err)
		}
		lines = append(lines, resp)
		// Check for tagged completion.
		if strings.HasPrefix(resp, tag+" OK") ||
			strings.HasPrefix(resp, tag+" NO") ||
			strings.HasPrefix(resp, tag+" BAD") {
			break
		}
		// Handle RFC 3501 literal: when a line ends with "{N}" or "{N+}", the
		// next N bytes are literal data (not CRLF-delimited lines). Read them
		// through the same textproto bufio.Reader (tconn.R) so the stream stays
		// in sync, then split into lines for uniform downstream processing.
		if n := parseLiteralCount(resp); n > 0 {
			literal := make([]byte, n)
			if _, err := io.ReadFull(tconn.R, literal); err != nil {
				return lines, fmt.Errorf("literal read (%d bytes) failed: %w", n, err)
			}
			// Normalise CRLF → LF and split into individual lines.
			litStr := strings.ReplaceAll(string(literal), "\r\n", "\n")
			litLines := strings.Split(litStr, "\n")
			// Trim trailing empty element when literal ends with \n.
			if len(litLines) > 0 && litLines[len(litLines)-1] == "" {
				litLines = litLines[:len(litLines)-1]
			}
			lines = append(lines, litLines...)
		}
	}
	return lines, nil
}

// parseCapabilities extracts the list of capability tokens from a CAPABILITY response line.
// Handles both "* CAPABILITY ..." and "A001 OK [CAPABILITY ...]" formats.
func parseCapabilities(line string) []string {
	// Handle bracketed capability in OK response: A001 OK [CAPABILITY IMAP4rev1 ...]
	if idx := strings.Index(line, "[CAPABILITY "); idx >= 0 {
		end := strings.Index(line[idx:], "]")
		if end > 0 {
			inner := line[idx+len("[CAPABILITY ") : idx+end]
			return strings.Fields(inner)
		}
	}
	// Handle untagged response: * CAPABILITY IMAP4rev1 ...
	upper := strings.ToUpper(line)
	capIdx := strings.Index(upper, "CAPABILITY ")
	if capIdx >= 0 {
		rest := line[capIdx+len("CAPABILITY "):]
		return strings.Fields(rest)
	}
	return nil
}

// parseFolders parses a slice of LIST response lines into ImapFolder objects.
// LIST response format: * LIST (\HasNoChildren) "/" "INBOX"
func parseFolders(lines []string) []*imapfern.ImapFolder {
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
		delimiter := matches[2]
		nameStr := matches[3]

		// Clean up delimiter
		delimiter = strings.Trim(delimiter, `"`)
		if delimiter == "NIL" {
			delimiter = ""
		}

		// Clean up folder name (may be quoted)
		nameStr = strings.TrimSpace(nameStr)
		nameStr = strings.Trim(nameStr, `"`)

		var attrs []string
		if attrStr != "" {
			for _, a := range strings.Split(attrStr, " ") {
				a = strings.TrimSpace(a)
				if a != "" {
					attrs = append(attrs, a)
				}
			}
		}

		folder := &imapfern.ImapFolder{
			Name: nameStr,
		}
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

// parseFolderStatus parses a single STATUS response line into an ImapFolderStatus.
// STATUS response format: * STATUS INBOX (MESSAGES 1234 RECENT 0 UNSEEN 42 UIDNEXT 5678 UIDVALIDITY 1234567890)
func parseFolderStatus(line string) *imapfern.ImapFolderStatus {
	if !strings.HasPrefix(line, "* STATUS ") {
		return nil
	}
	// Extract folder name and items
	rest := line[len("* STATUS "):]
	// Find opening paren
	parenIdx := strings.Index(rest, "(")
	if parenIdx < 0 {
		return nil
	}
	folderName := strings.TrimSpace(rest[:parenIdx])
	folderName = strings.Trim(folderName, `"`)

	inner := rest[parenIdx+1:]
	closeIdx := strings.Index(inner, ")")
	if closeIdx >= 0 {
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

// parseExamineResponse parses the untagged responses from an EXAMINE command into
// an ImapSelectedFolderResult. Handles EXISTS, RECENT, OK [UNSEEN], OK [UIDNEXT],
// OK [UIDVALIDITY], and OK [PERMANENTFLAGS].
func parseExamineResponse(folderName string, lines []string) *imapfern.ImapSelectedFolderResult {
	result := &imapfern.ImapSelectedFolderResult{FolderName: folderName}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "* ") {
			rest := line[2:]
			fields := strings.Fields(rest)
			if len(fields) >= 2 {
				switch strings.ToUpper(fields[1]) {
				case "EXISTS":
					if n, err := strconv.Atoi(fields[0]); err == nil {
						result.Exists = &n
					}
				case "RECENT":
					if n, err := strconv.Atoi(fields[0]); err == nil {
						result.Recent = &n
					}
				}
			}
		}
		// Parse bracketed OK annotations
		if strings.Contains(line, "OK [") {
			bracketStart := strings.Index(line, "[")
			bracketEnd := strings.Index(line, "]")
			if bracketStart >= 0 && bracketEnd > bracketStart {
				bracketed := line[bracketStart+1 : bracketEnd]
				parts := strings.SplitN(bracketed, " ", 2)
				switch strings.ToUpper(parts[0]) {
				case "UNSEEN":
					if len(parts) > 1 {
						if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
							result.FirstUnseen = &n
						}
					}
				case "UIDNEXT":
					if len(parts) > 1 {
						if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
							result.UidNext = &n
						}
					}
				case "UIDVALIDITY":
					if len(parts) > 1 {
						if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
							result.UidValidity = &n
						}
					}
				case "PERMANENTFLAGS":
					if len(parts) > 1 {
						flagStr := strings.Trim(parts[1], "()")
						var flags []string
						for _, f := range strings.Fields(flagStr) {
							f = strings.TrimSpace(f)
							if f != "" {
								flags = append(flags, f)
							}
						}
						result.PermanentFlags = flags
					}
				}
			}
		}
	}
	return result
}

// parseMessageHeaders parses UID FETCH response lines into ImapMessage objects.
// Each message block is delimited by "* N FETCH (" ... ")" lines.
func parseMessageHeaders(lines []string, maxMessages int) []*imapfern.ImapMessage {
	var messages []*imapfern.ImapMessage
	var currentMsg *imapfern.ImapMessage
	var uid int
	inHeader := false

	for _, line := range lines {
		if strings.HasPrefix(line, "* ") && strings.Contains(line, " FETCH ") {
			// Extract UID from the FETCH line if present
			uidMatch := regexp.MustCompile(`UID (\d+)`).FindStringSubmatch(line)
			if uidMatch != nil {
				if u, err := strconv.Atoi(uidMatch[1]); err == nil {
					uid = u
				}
			}
			currentMsg = &imapfern.ImapMessage{Uid: uid}
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
			// Parse header fields
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
				case "message-id":
					currentMsg.MessageId = &val
				}
			}
		}
	}
	return messages
}

// extractTLSInfo extracts the certificate subject CN and the cipher suite name
// from an established TLS connection.
func extractTLSInfo(tlsConn *tls.Conn) (subject string, cipher string) {
	state := tlsConn.ConnectionState()
	cipher = tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		subject = certSubject(cert)
	}
	return subject, cipher
}

// certSubject returns a human-readable subject string from a certificate.
func certSubject(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return "CN=" + cert.Subject.CommonName
	}
	return cert.Subject.String()
}

// stripCRLF removes carriage-return and line-feed characters from s, preventing
// CRLF injection in IMAP command lines sent via textproto.PrintfLine.
func stripCRLF(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// imapQuoteString wraps s in an IMAP double-quoted string literal, escaping
// backslash and double-quote per RFC 3501 §4.3. This allows usernames and
// passwords that contain spaces, parentheses, or other special characters.
// CR and LF are stripped first to prevent CRLF injection.
func imapQuoteString(s string) string {
	s = stripCRLF(s)
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return `"` + s + `"`
}
