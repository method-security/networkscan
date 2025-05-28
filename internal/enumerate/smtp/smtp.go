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
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	smtp "github.com/Method-Security/networkscan/generated/go/enumerate/smtp"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateSMTP implements NetworkApplicationLibrary for SMTP enumeration.
type LibraryEnumerateSMTP struct{}

// EnumerateTarget Overview
//  1. Try to connect to service
//     a. Try TCP, if successful continue, if not try TLS
//     b. If TLS succeeds, set TLSSupported and ForceTLS to true
//  2. Try STARTTLS if TLS connection not forced
//     a. If STARTTLS fails, set TLSSupported and ForceTLS to false
//  3. Check authentication methods
//     a. Parse data returned from 'AUTH' command
//  4. Test unauthenticated email
//     a. If unauthenticated email is not allowed, set AllowsUnauthenticatedEmail to false
func (s *LibraryEnumerateSMTP) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	// Initialize
	log := svc1log.FromContext(ctx)

	log.Info("Starting enumeration for target", svc1log.SafeParam("target", target))
	detail := smtp.EnumerateSmtpDetails{
		Target: target,
	}
	errors := []string{}

	// Get hostname for HELLO command and TLS
	hostname, _, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target format: %v", err))
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSmtpDetails(&detail), errors
	}
	config := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	}

	var conn net.Conn
	// Try to connect to service
	log.Debug("Attempting plain TCP connection to target", svc1log.SafeParam("target", target))
	conn, err = tryTCPConnection(ctx, target)
	if err == nil {
		tlsForce := false
		detail.ForceTls = &tlsForce
		log.Debug("Plain TCP connection successful")
	} else {
		log.Debug("Plain TCP connection failed, trying TLS", svc1log.SafeParam("error", err))
		// If TCP fails, try TLS
		conn, err = tryTLSConnection(target, hostname)
		if err != nil {
			canConnect := false
			detail.CanConnect = &canConnect
			errors = append(errors, fmt.Sprintf("both TCP and TLS connections failed: %v", err))
			return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSmtpDetails(&detail), errors
		}
		log.Debug("TLS connection successful")
		TLSSupported := true
		forceTLS := true
		detail.TlsSupported = &TLSSupported
		detail.ForceTls = &forceTLS
	}

	canConnect := true
	detail.CanConnect = &canConnect
	log.Info("Connected to target", svc1log.SafeParam("target", target))

	// Create SMTP client
	client, err := netsmtp.NewClient(conn, hostname)
	if err != nil {
		errors = append(errors, fmt.Sprintf("SMTP client creation failed: %v", err))
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSmtpDetails(&detail), errors
	}

	// Try STARTTLS if TLS connection established above
	if detail.TlsSupported == nil {
		log.Debug("Attempting STARTTLS")
		err = client.StartTLS(config)
		if err != nil {
			errors = append(errors, fmt.Sprintf("TLS upgrade failed: %v", err))
			TLSSupported := false
			detail.TlsSupported = &TLSSupported
			log.Debug("STARTTLS failed")
		} else {
			log.Debug("STARTTLS successful")
			TLSSupported := true
			detail.TlsSupported = &TLSSupported
		}
	}

	// Check authentication methods
	log.Debug("Checking authentication methods")
	if ok, param := client.Extension("AUTH"); ok {
		authMethods := parseAuthMethods(strings.Split(param, " "))
		detail.AuthCommands = authMethods
		log.Debug("Supported auth methods", svc1log.SafeParam("authMethods", authMethods))
	} else {
		log.Debug("No authentication methods found")
	}

	// Test if unauthenticated email is allowed
	log.Debug("Testing unauthenticated email")
	allowsUnauthenticatedEmail := testUnauthenticatedEmail(ctx, client, hostname)
	detail.AllowsUnauthenticatedEmail = &allowsUnauthenticatedEmail
	log.Debug("Unauthenticated email", svc1log.SafeParam("allowsUnauthenticatedEmail", allowsUnauthenticatedEmail))

	err = conn.Close()
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to close connection: %v", err))
	}

	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSmtpDetails(&detail), errors
}
