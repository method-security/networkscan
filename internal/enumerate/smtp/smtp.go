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
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	smtp "github.com/Method-Security/networkscan/generated/go/enumerate/smtp"

	// Internal
	smtputil "github.com/Method-Security/networkscan/internal/protocol/smtp"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateSMTP implements NetworkApplicationLibrary for SMTP enumeration.
type LibraryEnumerateSMTP struct {
	Wordlist []string
}

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
	serverInfo := &protocol.SmtpServerInfo{}
	errors := []string{}

	// Get hostname for HELLO command and TLS
	hostname, _, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target format: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateSmtpDetails: &detail}, errors
	}
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	}

	var conn net.Conn
	// Try to connect to service
	log.Debug("Attempting plain TCP connection to target", svc1log.SafeParam("target", target))
	conn, err = TryTCPConnection(ctx, target)
	if err == nil {
		tlsForce := false
		detail.ForceTls = &tlsForce
		log.Debug("Plain TCP connection successful")
	} else {
		log.Debug("Plain TCP connection failed, trying TLS", svc1log.SafeParam("error", err))
		// If TCP fails, try TLS
		conn, err = tryTLSConnection(ctx, target, hostname)
		if err != nil {
			canConnect := false
			detail.CanConnect = &canConnect
			errors = append(errors, fmt.Sprintf("both TCP and TLS connections failed: %v", err))
			return &enumeratefern.EnumerateServiceDetails{EnumerateSmtpDetails: &detail}, errors
		}
		log.Debug("TLS connection successful")
		tlsSupported := true
		forceTLS := true
		serverInfo.TlsSupported = &tlsSupported
		detail.ForceTls = &forceTLS
	}

	canConnect := true
	detail.CanConnect = &canConnect
	log.Info("Connected to target", svc1log.SafeParam("target", target))

	// Read the SMTP banner, wrapping the connection so NewClient can replay it
	conn, banner, bannerErr := smtputil.ReadBannerFromConn(conn)
	if bannerErr == nil && banner != "" {
		serverInfo.Banner = &banner
		serverName, softwareName, softwareVersion := smtputil.ParseBanner(banner)
		if serverName != "" {
			serverInfo.ServerName = &serverName
		}
		if softwareName != "" {
			serverInfo.SoftwareName = &softwareName
		}
		if softwareVersion != "" {
			serverInfo.SoftwareVersion = &softwareVersion
		}
		esmtp := strings.Contains(banner, "ESMTP")
		serverInfo.EsmtpSupported = &esmtp
	}

	// Create SMTP client from existing connection (banner already consumed)
	client, err := netsmtp.NewClient(conn, hostname)
	if err != nil {
		errors = append(errors, fmt.Sprintf("SMTP client creation failed: %v", err))
		detail.ServerInfo = serverInfo
		return &enumeratefern.EnumerateServiceDetails{EnumerateSmtpDetails: &detail}, errors
	}

	// Try STARTTLS if TLS connection established above
	if serverInfo.TlsSupported == nil {
		log.Debug("Attempting STARTTLS")
		err = client.StartTLS(tlsConfig)
		if err != nil {
			errors = append(errors, fmt.Sprintf("TLS upgrade failed: %v", err))
			tlsSupported := false
			serverInfo.TlsSupported = &tlsSupported
			log.Debug("STARTTLS failed")
		} else {
			log.Debug("STARTTLS successful")
			tlsSupported := true
			serverInfo.TlsSupported = &tlsSupported
		}
	}

	// Check authentication methods and collect supported extensions
	log.Debug("Checking authentication methods")
	if ok, param := client.Extension("AUTH"); ok {
		authMethods := parseAuthMethods(strings.Split(param, " "))
		serverInfo.AuthMethods = authMethods
		log.Debug("Supported auth methods", svc1log.SafeParam("authMethods", authMethods))
	} else {
		log.Debug("No authentication methods found")
	}

	// Collect supported EHLO extensions
	extensions := collectExtensions(client)
	if len(extensions) > 0 {
		serverInfo.SupportedExtensions = extensions
	}

	detail.ServerInfo = serverInfo

	// Enumerate users via VRFY, EXPN, and RCPT TO
	wordlist := s.Wordlist
	if len(wordlist) == 0 {
		wordlist = defaultUsernames
	}
	enumeratedUsers := enumerateUsers(ctx, client, hostname, extensions, wordlist)
	if len(enumeratedUsers) > 0 {
		detail.EnumeratedUsers = enumeratedUsers
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

	return &enumeratefern.EnumerateServiceDetails{EnumerateSmtpDetails: &detail}, errors
}
