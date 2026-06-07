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
func dialTLS(target, hostname string) (net.Conn, error) {
	d := net.Dialer{}
	tlsCfg := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec
	}
	return tls.DialWithDialer(&d, "tcp", target, tlsCfg)
}

// sendCommand sends a POP3 command and reads the response line.
func sendCommand(conn net.Conn, cmd string) (string, error) {
	_, err := fmt.Fprintf(conn, "%s\r\n", cmd)
	if err != nil {
		return "", err
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// sendCommandMultiLine sends a command and reads lines until "." terminator.
// Returns lines between +OK and ".".
func sendCommandMultiLine(conn net.Conn, cmd string) ([]string, error) {
	_, err := fmt.Fprintf(conn, "%s\r\n", cmd)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
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
func runCapa(conn net.Conn) (caps []string, authMechs []string, implementation string, loginDelay int, expireDays string) {
	lines, err := sendCommandMultiLine(conn, "CAPA")
	if err != nil {
		return
	}
	caps, authMechs, implementation, loginDelay, expireDays = pop3util.ParseCapabilities(lines)
	return
}

// upgradeToTLS sends STLS and performs the TLS handshake.
// Returns a new TLS connection on success.
func upgradeToTLS(conn net.Conn, hostname string) (*tls.Conn, error) {
	resp, err := sendCommand(conn, "STLS")
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
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}
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
