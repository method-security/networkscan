package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	netsmtp "net/smtp"
	"strings"

	enumerateFern "github.com/Method-Security/networkscan/generated/go/enumerate"
	smtpFern "github.com/Method-Security/networkscan/generated/go/enumerate/smtp"
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
func (s *LibraryEnumerateSMTP) EnumerateTarget(ctx context.Context, target string) (*enumerateFern.NetworkApplicationEnumerateDetails, []string) {
	log.Printf("[INFO] Starting enumeration for target: %s", target)
	detail := smtpFern.SmtpEnumerateDetails{
		Target: target,
	}
	errors := []string{}

	// Get hostname for HELLO command and TLS
	hostname, _, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target format: %v", err))
		return enumerateFern.NewNetworkApplicationEnumerateDetailsFromSmtpEnumerateDetails(&detail), errors
	}
	config := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	}

	var conn net.Conn
	// Try to connect to service
	log.Printf("[DEBUG] Attempting plain TCP connection to %s", target)
	conn, err = tryTCPConnection(ctx, target)
	if err == nil {
		tlsForce := false
		detail.ForceTls = &tlsForce
		log.Printf("[DEBUG] Plain TCP connection successful")
	} else {
		log.Printf("[DEBUG] Plain TCP connection failed, trying TLS: %v", err)
		// If TCP fails, try TLS
		conn, err = tryTLSConnection(target, hostname)
		if err != nil {
			canConnect := false
			detail.CanConnect = &canConnect
			errors = append(errors, fmt.Sprintf("both TCP and TLS connections failed: %v", err))
			return enumerateFern.NewNetworkApplicationEnumerateDetailsFromSmtpEnumerateDetails(&detail), errors
		}
		log.Printf("[DEBUG] TLS connection successful")
		TLSSupported := true
		forceTLS := true
		detail.TlsSupported = &TLSSupported
		detail.ForceTls = &forceTLS
	}

	canConnect := true
	detail.CanConnect = &canConnect
	log.Printf("[INFO] Connected to %s", target)

	// Create SMTP client
	client, err := netsmtp.NewClient(conn, hostname)
	if err != nil {
		errors = append(errors, fmt.Sprintf("SMTP client creation failed: %v", err))
		return enumerateFern.NewNetworkApplicationEnumerateDetailsFromSmtpEnumerateDetails(&detail), errors
	}

	// Try STARTTLS if TLS connection established above
	if detail.TlsSupported == nil {
		log.Printf("[DEBUG] Attempting STARTTLS")
		err = client.StartTLS(config)
		if err != nil {
			errors = append(errors, fmt.Sprintf("TLS upgrade failed: %v", err))
			TLSSupported := false
			detail.TlsSupported = &TLSSupported
			log.Printf("[DEBUG] STARTTLS failed")
		} else {
			log.Printf("[DEBUG] STARTTLS successful")
			TLSSupported := true
			detail.TlsSupported = &TLSSupported
		}
	}

	// Check authentication methods
	log.Printf("[INFO] Checking authentication methods")
	if ok, param := client.Extension("AUTH"); ok {
		authMethods := parseAuthMethods(strings.Split(param, " "))
		detail.AuthCommands = authMethods
		log.Printf("[INFO] Supported auth methods: %v", authMethods)
	} else {
		log.Printf("[INFO] No authentication methods found")
	}

	// Test if unauthenticated email is allowed
	log.Printf("[INFO] Testing unauthenticated email")
	allowsUnauthenticatedEmail := testUnauthenticatedEmail(client, hostname)
	detail.AllowsUnauthenticatedEmail = &allowsUnauthenticatedEmail
	log.Printf("[INFO] Unauthenticated email %s supported",
		map[bool]string{true: "is", false: "is not"}[allowsUnauthenticatedEmail])

	err = conn.Close()
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to close connection: %v", err))
	}

	return enumerateFern.NewNetworkApplicationEnumerateDetailsFromSmtpEnumerateDetails(&detail), errors
}
