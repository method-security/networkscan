package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	pop3util "github.com/Method-Security/networkscan/internal/protocol/pop3"
)

// dialTCP opens a plain TCP connection to the target.
func dialTCP(ctx context.Context, target string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, "tcp", target)
}

// dialTLS opens a TLS connection to the target (implicit TLS / port 995).
// Mirrors internal/enumerate/smtp/helpers.go::tryTLSConnection.
// InsecureSkipVerify is intentional: enumeration probes target mail servers that
// frequently present self-signed or expired certificates.
func dialTLS(target, hostname string) (net.Conn, error) {
	dialer := net.Dialer{}
	tlsCfg := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec
	}
	return tls.DialWithDialer(&dialer, "tcp", target, tlsCfg)
}

// sendCommand writes a POP3 command to conn and reads the single-line response
// from the shared reader.  Using the caller-supplied reader (rather than creating
// a new one) ensures no bytes are lost between calls.
func sendCommand(conn net.Conn, reader *bufio.Reader, cmd string) (string, error) {
	_, err := fmt.Fprintf(conn, "%s\r\n", cmd)
	if err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// sendCommandMultiLine writes a command and reads lines until the "." terminator.
// Returns the lines between +OK and ".".  The caller-supplied reader is shared
// across all reads on this connection so no buffered bytes are ever discarded.
func sendCommandMultiLine(conn net.Conn, reader *bufio.Reader, cmd string) ([]string, error) {
	_, err := fmt.Fprintf(conn, "%s\r\n", cmd)
	if err != nil {
		return nil, err
	}
	// Read status line
	first, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	first = strings.TrimSpace(first)
	if !strings.HasPrefix(first, "+OK") {
		return nil, fmt.Errorf("POP3 error: %s", first)
	}
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return lines, err
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "." {
			break
		}
		lines = append(lines, trimmed)
	}
	return lines, nil
}

// runCapa sends CAPA and returns parsed capabilities.
// capaErr is non-nil when the server returned -ERR (RFC 2449 not supported)
// or when the read failed; the caller should surface or log it so the absence
// of capabilities is distinguishable from "server has zero capabilities".
func runCapa(conn net.Conn, reader *bufio.Reader) (caps []string, authMechs []string, implementation string, loginDelay int, expireDays string, capaErr error) {
	lines, err := sendCommandMultiLine(conn, reader, "CAPA")
	if err != nil {
		capaErr = err
		return
	}
	caps, authMechs, implementation, loginDelay, expireDays = pop3util.ParseCapabilities(lines)
	return
}

// upgradeToTLS sends STLS, performs the TLS handshake, and resets reader to
// drain from the new TLS layer.  Resetting the shared reader here (rather than
// creating a new one after the upgrade) means that any bytes already buffered
// before the handshake are still available to subsequent reads.
//
// InsecureSkipVerify is intentional: the same rationale as dialTLS applies —
// enumeration probes must succeed even when the server presents a self-signed
// or expired certificate.
func upgradeToTLS(conn net.Conn, reader *bufio.Reader, hostname string) (*tls.Conn, error) {
	resp, err := sendCommand(conn, reader, "STLS")
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(resp, "+OK") {
		return nil, fmt.Errorf("STLS rejected: %s", resp)
	}
	tlsCfg := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		// The server is now in TLS-expectation mode; cleartext QUIT would be
		// protocol noise.  Close the connection here so the caller does not
		// need to distinguish handshake failure from a -ERR STLS rejection.
		_ = tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}
	// Point the shared reader at the TLS layer so all subsequent reads go
	// through the encrypted channel and no buffered bytes are lost.
	reader.Reset(tlsConn)
	return tlsConn, nil
}

// extractTLSInfo pulls cipher suite name and TLS version from a tls.Conn.
func extractTLSInfo(conn *tls.Conn) (cipher, version string) {
	state := conn.ConnectionState()
	cipher = tls.CipherSuiteName(state.CipherSuite)
	switch state.Version {
	case tls.VersionTLS10:
		version = "TLS 1.0"
	case tls.VersionTLS11:
		version = "TLS 1.1"
	case tls.VersionTLS12:
		version = "TLS 1.2"
	case tls.VersionTLS13:
		version = "TLS 1.3"
	default:
		version = fmt.Sprintf("0x%04x", state.Version)
	}
	return
}

// parseSaslMechanisms maps mechanism strings to Fern enum values, skipping unknowns.
func parseSaslMechanisms(mechs []string) []protocol.Pop3AuthMechanism {
	var result []protocol.Pop3AuthMechanism
	for _, m := range mechs {
		upper := strings.ToUpper(m)
		if v, ok := saslMechanismMap[upper]; ok {
			result = append(result, v)
		}
	}
	return result
}

// quit sends QUIT to the server gracefully.
func quit(conn net.Conn) {
	_, _ = fmt.Fprintf(conn, "QUIT\r\n")
}
