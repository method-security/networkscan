package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strings"
	"time"

	smtpfern "github.com/Method-Security/networkscan/generated/go/smtp"
)

var authCommands = map[string]smtpfern.AuthCommand{
	"XOAUTH2":  smtpfern.AuthCommandXoauth2,
	"PLAIN":    smtpfern.AuthCommandPlain,
	"LOGIN":    smtpfern.AuthCommandLogin,
	"CRAM_MD5": smtpfern.AuthCommandCrammd5,
	"NTLM":     smtpfern.AuthCommandNtlm,
}

func RunSMTPEnumerate(ctx context.Context, targets []string, connectionTimeout int, targetDomain string) (smtpfern.SmtpEnumerateReport, error) {
	log.Printf("[INFO] Starting SMTP enumeration for %d targets with a timeout of %ds", len(targets), connectionTimeout)
	report := smtpfern.SmtpEnumerateReport{Targets: targets}
	errors := []string{}

	details := []*smtpfern.SmtpEnumerateDetails{}
	for i, target := range targets {
		targetCtx, targetCancel := context.WithTimeout(ctx, time.Duration(connectionTimeout)*time.Second)
		defer targetCancel()

		log.Printf("[INFO] [%d/%d] Processing target: %s", i+1, len(targets), target)
		detail, err := enumerateTarget(targetCtx, target, connectionTimeout, targetDomain)
		if err != nil {
			if targetCtx.Err() == context.DeadlineExceeded {
				log.Printf("[ERROR] Parameter timeout while enumerating %s", target)
				errors = append(errors, fmt.Sprintf("Parameter timeout while enumerating %s", target))
			} else {
				log.Printf("[ERROR] Error enumerating target %s: %v", target, err)
				errors = append(errors, fmt.Sprintf("%s: %v", target, err))
			}
			continue
		}
		details = append(details, &detail)
		log.Printf("[INFO] Successfully enumerated target %s", target)

		if targetCtx.Err() != nil {
			continue
		}
	}

	log.Printf("[INFO] Enumeration complete. Processed %d targets with %d errors", len(targets), len(errors))
	report.SmtpDetails = details
	report.Errors = errors
	return report, nil
}

func enumerateTarget(ctx context.Context, target string, timeout int, targetDomain string) (smtpfern.SmtpEnumerateDetails, error) {
	log.Printf("[INFO] Starting enumeration for target: %s", target)
	detail := smtpfern.SmtpEnumerateDetails{
		Target: target,
	}

	// Parse host and port
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		canConnect := false
		detail.CanConnect = &canConnect
		return detail, fmt.Errorf("invalid target format: %v", err)
	}

	var conn net.Conn
	tlsConfig := &tls.Config{
		ServerName:         targetDomain,
		InsecureSkipVerify: true,
	}

	// For port 465, use TLS directly
	if port == "465" {
		dialer := &net.Dialer{
			Timeout: time.Duration(timeout) * time.Second,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
		if err != nil {
			canConnect := false
			detail.CanConnect = &canConnect
			return detail, fmt.Errorf("TLS connection failed: %v", err)
		}
		forceTls := true
		detail.ForceTls = &forceTls
		tlsSupported := true
		detail.TlsSupported = &tlsSupported
	} else {
		// For other ports, use regular TCP connection first
		dialer := net.Dialer{
			Timeout: time.Duration(timeout) * time.Second,
		}
		conn, err = dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			canConnect := false
			detail.CanConnect = &canConnect
			return detail, fmt.Errorf("connection failed: %v", err)
		}
	}

	defer conn.Close()
	canConnect := true
	detail.CanConnect = &canConnect
	log.Printf("[INFO] Connected to %s", target)

	// Create SMTP client
	log.Printf("[INFO] Creating SMTP client for %s", target)
	c, err := smtp.NewClient(conn, targetDomain)
	if err != nil {
		log.Printf("[WARNING] Failed to create SMTP client for %s: %v", target, err)
		return detail, fmt.Errorf("SMTP client creation failed: %v", err)
	}
	log.Printf("[INFO] SMTP client created for %s", target)

	// Check TLS support for non-465 ports
	if port != "465" {
		tlsSupported := false
		detail.TlsSupported = &tlsSupported
		log.Printf("[INFO] Checking TLS support for %s", target)
		if ok, _ := c.Extension("STARTTLS"); ok {
			tlsSupported = true
			log.Printf("[INFO] TLS supported on %s", target)

			// Try to start TLS
			log.Printf("[INFO] Starting TLS session for %s", target)
			if err := c.StartTLS(tlsConfig); err == nil {
				forceTls := true
				detail.ForceTls = &forceTls
				log.Printf("[INFO] TLS session established with %s", target)
			} else {
				log.Printf("[ERROR] Failed to start TLS session for %s: %v", target, err)
			}
		} else {
			log.Printf("[INFO] TLS not supported on %s", target)
		}
	}

	// Check authentication methods
	log.Printf("[INFO] Checking authentication methods for %s", target)
	if ok, param := c.Extension("AUTH"); ok {
		authMethods := parseAuthMethods(strings.Split(param, " "))
		detail.AuthCommands = authMethods
		log.Printf("[INFO] Supported auth methods for %s: %v", target, authMethods)
	} else {
		log.Printf("[INFO] No authentication methods found for %s", target)
	}

	// Test if unauthenticated email is allowed
	log.Printf("[INFO] Testing unauthenticated email for %s", target)
	allowsUnauthenticatedEmail := testUnauthenticatedEmail(c, targetDomain)
	detail.AllowsUnauthenticatedEmail = &allowsUnauthenticatedEmail
	log.Printf("[INFO] Unauthenticated email %s supported on %s",
		map[bool]string{true: "is", false: "is not"}[allowsUnauthenticatedEmail],
		target)

	log.Printf("[INFO] Completed enumeration for target: %s", target)

	err = c.Close()
	if err != nil {
		log.Printf("[ERROR] Failed to close SMTP client for %s: %v", target, err)
	}

	return detail, nil
}

func parseAuthMethods(methods []string) []smtpfern.AuthCommand {
	var result []smtpfern.AuthCommand
	for _, method := range methods {
		if auth, ok := authCommands[strings.ToUpper(method)]; ok {
			result = append(result, auth)
		}
	}
	return result
}

func testUnauthenticatedEmail(c *smtp.Client, targetDomain string) bool {
	// Try to send an email without authentication
	err := c.Mail(targetDomain)
	if err != nil {
		log.Printf("[ERROR] Mail From command failed: %v", err)
		return false
	}

	err = c.Rcpt(targetDomain)
	if err != nil {
		log.Printf("[ERROR] Rcpt To command failed: %v", err)
		return false
	}

	// Reset the session
	c.Reset()

	return true
}
