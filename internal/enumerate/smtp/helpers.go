package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	netsmtp "net/smtp"
	"strings"

	smtpFern "github.com/Method-Security/networkscan/generated/go/enumerate/smtp"
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

func parseAuthMethods(methods []string) []smtpFern.AuthCommand {
	var result []smtpFern.AuthCommand
	for _, method := range methods {
		if auth, ok := authCommands[strings.ToUpper(method)]; ok {
			result = append(result, auth)
		}
	}
	return result
}

func testUnauthenticatedEmail(c *netsmtp.Client, hostname string) bool {
	// Form proper email addresses
	testEmail := fmt.Sprintf("test@%s", hostname)

	// Try to send an email without authentication
	err := c.Mail(testEmail)
	if err != nil {
		log.Printf("[DEBUG] Mail From command failed: %v", err)
		return false
	}

	err = c.Rcpt(testEmail)
	if err != nil {
		log.Printf("[DEBUG] Rcpt To command failed: %v", err)
		return false
	}

	// Reset the session
	err = c.Reset()
	if err != nil {
		log.Printf("[DEBUG] Failed to reset SMTP client: %v", err)
	}

	return true
}
