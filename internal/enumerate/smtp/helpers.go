package smtp

import (
	// Standard
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	netsmtp "net/smtp"
	"strings"

	// Generated
	smtp "github.com/Method-Security/networkscan/generated/go/enumerate/smtp"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func tryTCPConnection(ctx context.Context, target string) (net.Conn, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// readBanner reads the SMTP 220 banner by peeking at the connection data
// without consuming it, so net/smtp.NewClient can still read it.
// Returns a wrapped conn that replays the banner bytes.
func readBanner(conn net.Conn) (net.Conn, string, error) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return conn, "", err
	}
	data := buf[:n]

	// Extract banner from the first line
	banner := ""
	lines := strings.Split(string(data), "\r\n")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "220") {
		banner = strings.TrimSpace(lines[0])
	}

	// Wrap the connection so NewClient can re-read the banner
	wrapped := &replayConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(data), conn),
	}
	return wrapped, banner, nil
}

// replayConn wraps a net.Conn, replaying buffered data before reading from the real connection.
type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// parseSMTPBanner extracts server name and software info from a 220 banner.
func parseSMTPBanner(banner string) (serverName, softwareName, softwareVersion string) {
	line := banner
	if strings.HasPrefix(line, "220-") {
		line = line[4:]
	} else if strings.HasPrefix(line, "220 ") {
		line = line[4:]
	} else {
		return
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	serverName = parts[0]

	idx := 1
	for idx < len(parts) {
		upper := strings.ToUpper(parts[idx])
		if upper == "ESMTP" || upper == "SMTP" {
			idx++
			break
		}
		idx++
	}

	if idx < len(parts) {
		remaining := parts[idx:]
		for i, token := range remaining {
			if len(token) > 0 && token[0] >= '0' && token[0] <= '9' {
				softwareName = strings.Join(remaining[:i], " ")
				softwareVersion = strings.Join(remaining[i:], " ")
				return
			}
		}
		softwareName = strings.Join(remaining, " ")
	}

	return
}

// collectExtensions checks for common SMTP extensions via the client's Extension method.
func collectExtensions(c *netsmtp.Client) []string {
	knownExtensions := []string{
		"8BITMIME", "AUTH", "BINARYMIME", "CHUNKING", "DSN",
		"ENHANCEDSTATUSCODES", "ETRN", "PIPELINING", "SIZE",
		"STARTTLS", "TURN", "VRFY",
	}
	var found []string
	for _, ext := range knownExtensions {
		if ok, param := c.Extension(ext); ok {
			if param != "" {
				found = append(found, ext+" "+param)
			} else {
				found = append(found, ext)
			}
		}
	}
	return found
}

func tryTLSConnection(target string, hostname string) (net.Conn, error) {
	dialer := net.Dialer{}
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	}
	return tls.DialWithDialer(&dialer, "tcp", target, tlsConfig)
}

func parseAuthMethods(methods []string) []smtp.AuthCommand {
	var result []smtp.AuthCommand
	for _, method := range methods {
		if auth, ok := authCommands[strings.ToUpper(method)]; ok {
			result = append(result, auth)
		}
	}
	return result
}

func testUnauthenticatedEmail(ctx context.Context, c *netsmtp.Client, hostname string) bool {
	// Initialize
	log := svc1log.FromContext(ctx)

	// Form proper email addresses
	testEmail := fmt.Sprintf("test@%s", hostname)

	// Try to send an email without authentication
	err := c.Mail(testEmail)
	if err != nil {
		log.Debug("Mail From command failed", svc1log.SafeParam("error", err))
		return false
	}

	err = c.Rcpt(testEmail)
	if err != nil {
		log.Debug("Rcpt To command failed", svc1log.SafeParam("error", err))
		return false
	}

	// Reset the session
	err = c.Reset()
	if err != nil {
		log.Debug("Failed to reset SMTP client", svc1log.SafeParam("error", err))
	}

	return true
}
