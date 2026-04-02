package smtp

import (
	// Standard
	"context"
	"crypto/tls"
	"fmt"
	"net"
	netsmtp "net/smtp"
	"strings"

	// Generated
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func tryTCPConnection(ctx context.Context, target string) (net.Conn, error) {
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, "tcp", target)
}

func tryTLSConnection(target string, hostname string) (net.Conn, error) {
	dialer := net.Dialer{}
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	}
	return tls.DialWithDialer(&dialer, "tcp", target, tlsConfig)
}

func parseAuthMethods(methods []string) []protocol.SmtpAuthCommand {
	var result []protocol.SmtpAuthCommand
	for _, method := range methods {
		if auth, ok := authCommands[strings.ToUpper(method)]; ok {
			result = append(result, auth)
		}
	}
	return result
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
