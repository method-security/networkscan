package imap

import (
	// Standard
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/internal/netdial"
)

// deadlineFromContext returns the absolute deadline from ctx. If the context
// has no deadline, it falls back to 30 seconds from now. Using the absolute
// deadline (rather than re-computing now+duration on each call) ensures that
// later commands in a long enumeration cannot extend past the engine's
// per-target timeout budget.
func deadlineFromContext(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(30 * time.Second)
}

// implicitTLSPeekTimeout caps how long we wait for an IMAP server to deliver
// its untagged "* OK" greeting before concluding the listener actually wants
// TLS (e.g. on port 993 / IMAPS).
const implicitTLSPeekTimeout = 2 * time.Second

// errImplicitTLSSuspected signals that a plain TCP dial succeeded but the
// listener did not send an IMAP greeting within implicitTLSPeekTimeout. The
// caller should close the connection and retry with implicit TLS.
var errImplicitTLSSuspected = fmt.Errorf("no IMAP greeting on plain socket; implicit TLS suspected")

// imapsPort is the IANA-assigned port for IMAP over implicit TLS (RFC 8314).
// On this port we treat a peek-timeout as a strong signal of implicit TLS;
// on other ports we assume a slow plain-text server and keep the connection.
const imapsPort = 993

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
func tryTCPConnection(host string, port int, ctx context.Context) (net.Conn, string, error) {
	deadline := deadlineFromContext(ctx)
	dialTimeout := time.Until(deadline)
	if dialTimeout <= 0 {
		dialTimeout = time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := netdial.DialContext(ctx, "tcp", addr, netdial.WithTimeout(dialTimeout))
	if err != nil {
		return nil, "", err
	}

	// Quick peek for the leading '*' of an IMAP untagged response.
	_ = conn.SetReadDeadline(time.Now().Add(implicitTLSPeekTimeout))
	reader := bufio.NewReader(conn)
	peek, peekErr := reader.Peek(1)

	switch {
	case peekErr == nil && len(peek) == 1 && peek[0] == '*':
		// Greeting on the wire — proceed plaintext (handled below).
	case isTimeout(peekErr):
		// Two cases produce the same timing signature: a slow plain-text
		// server that hasn't sent its greeting yet, or a silent implicit-TLS
		// listener waiting for the client's ClientHello. Port number is the
		// best disambiguator we have: :993 is the IANA-assigned IMAPS port
		// (RFC 8314), so a silent listener there is almost certainly TLS.
		// On any other port, keep the connection and let ReadString apply
		// the full timeout — a slow plain server will still succeed.
		if port == imapsPort {
			_ = conn.Close()
			return nil, "", errImplicitTLSSuspected
		}
		// Slow plain server — fall through and let ReadString handle it.
	default:
		// Hard read error or non-'*' first byte — assume TLS.
		_ = conn.Close()
		return nil, "", errImplicitTLSSuspected
	}

	// Greeting is on its way; restore to the absolute context deadline.
	_ = conn.SetReadDeadline(deadline)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("failed to read greeting: %w", err)
	}
	return &bufferedConn{Conn: conn, r: reader}, strings.TrimRight(greeting, "\r\n"), nil
}

// tryTLSConnection connects to host:port directly via TLS, reads the IMAP greeting line,
// and returns the open TLS connection plus the greeting string.
func tryTLSConnection(host string, port int, ctx context.Context) (*tls.Conn, string, error) {
	deadline := deadlineFromContext(ctx)
	dialTimeout := time.Until(deadline)
	if dialTimeout <= 0 {
		dialTimeout = time.Second
	}
	// networkscan is a probe — we want to observe and report on the cert
	// presented (subject, cipher), not validate it. Self-signed, expired,
	// or wrong-CN certs are normal targets. Match the POP3 enumerator.
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec
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

// doSTARTTLS upgrades an existing plain TCP connection to TLS using the IMAP STARTTLS command.
// It sends the STARTTLS command, reads the server response until the tagged
// completion, then wraps the connection in TLS.
func doSTARTTLS(conn net.Conn, host string, ctx context.Context) (*tls.Conn, error) {
	const tag = "A001"
	tconn := textproto.NewConn(conn)
	if err := tconn.PrintfLine("%s STARTTLS", tag); err != nil {
		return nil, fmt.Errorf("STARTTLS send failed: %w", err)
	}
	_ = conn.SetReadDeadline(deadlineFromContext(ctx))
	// Read until tagged completion. Servers may emit untagged data lines
	// before the tagged response — only the tagged OK confirms the upgrade.
	// Matching "OK" anywhere in the line would falsely accept untagged lines
	// such as "* OK still here" or "* BYE OK by".
	for {
		resp, err := tconn.ReadLine()
		if err != nil {
			return nil, fmt.Errorf("STARTTLS response read failed: %w", err)
		}
		if strings.HasPrefix(resp, tag+" OK") {
			break
		}
		if strings.HasPrefix(resp, tag+" NO") || strings.HasPrefix(resp, tag+" BAD") {
			return nil, fmt.Errorf("STARTTLS rejected: %s", resp)
		}
		// Untagged line — keep reading.
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
// The connection deadline is set to the absolute deadline from ctx (not now+duration) so
// that later commands in a sequence cannot extend past the engine's per-target timeout.
func sendCommand(conn net.Conn, tag, cmd string, ctx context.Context) ([]string, error) {
	_ = conn.SetDeadline(deadlineFromContext(ctx))
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
		// Tagged completion. OK is success; NO and BAD are failures and must
		// be surfaced to the caller so partial / empty results are not
		// mistaken for success (e.g. LIST against a folder the user can't
		// see, STATUS on a non-existent mailbox, FETCH on an unselected box).
		if strings.HasPrefix(resp, tag+" OK") {
			break
		}
		if strings.HasPrefix(resp, tag+" NO") || strings.HasPrefix(resp, tag+" BAD") {
			return lines, fmt.Errorf("IMAP %s response: %s", strings.TrimSpace(strings.TrimPrefix(resp, tag)), resp)
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
