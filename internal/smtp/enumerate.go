package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strings"
	"sync"
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

// RunSMTPEnumerate Overview
// 1. Try to connect to service
//   a. Try TCP, if successful continue, if not try TLS
//   b. If TLS succeeds, set TLSSupported and ForceTLS to true
// 2. Try STARTTLS if TLS connection not forced
//   a. If STARTTLS fails, set TLSSupported and ForceTLS to false
// 3. Check authentication methods
//   a. Parse data returned from 'AUTH' command
// 4. Test unauthenticated email
//   a. If unauthenticated email is not allowed, set AllowsUnauthenticatedEmail to false

func RunSMTPEnumerate(ctx context.Context, targets []string, timeout int) (smtpfern.SmtpEnumerateReport, error) {
	log.Printf("[INFO] Starting SMTP enumeration for %d targets with a timeout of %ds", len(targets), timeout)
	report := smtpfern.SmtpEnumerateReport{Targets: targets}

	// Create channels for collecting results and errors
	detailsChan := make(chan *smtpfern.SmtpEnumerateDetails, len(targets))
	errorsChan := make(chan string, len(targets))
	var wg sync.WaitGroup

	// Process each target concurrently
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()

			// Create a context with timeout for each target
			targetCtx, targetCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
			defer targetCancel()

			// Start enumeration in a separate goroutine
			resultChan := make(chan struct {
				detail *smtpfern.SmtpEnumerateDetails
				errs   []string
			}, 1)

			go func() {
				detail, errs := enumerateTarget(targetCtx, target)
				resultChan <- struct {
					detail *smtpfern.SmtpEnumerateDetails
					errs   []string
				}{detail, errs}
			}()

			// Wait for either completion or timeout
			select {
			case <-targetCtx.Done():
				if targetCtx.Err() == context.DeadlineExceeded {
					errMsg := fmt.Sprintf("Parameter timeout (%ds) while enumerating %s", timeout, target)
					errorsChan <- errMsg
					log.Printf("[ERROR] %s", errMsg)
				}
			case result := <-resultChan:
				// Always add details if we have them
				if result.detail != nil {
					detailsChan <- result.detail
					log.Printf("[INFO] Collected enumeration details for target %s", target)
				}

				// Only add errors if the slice is not empty
				if len(result.errs) > 0 {
					for _, err := range result.errs {
						errorsChan <- err
						log.Printf("[ERROR] Error while enumerating target: %s", err)
					}
				} else {
					log.Printf("[INFO] Successfully enumerated target %s", target)
				}
			}
		}(i, target)
	}

	// Create a goroutine to close channels after all workers are done
	go func() {
		wg.Wait()
		close(detailsChan)
		close(errorsChan)
	}()

	// Collect results
	var details []*smtpfern.SmtpEnumerateDetails
	var errors []string

	// Read from channels until they're closed
	for detail := range detailsChan {
		details = append(details, detail)
	}
	for err := range errorsChan {
		errors = append(errors, err)
	}

	log.Printf("[INFO] Enumeration complete. Processed %d targets with %d errors", len(targets), len(errors))
	report.SmtpDetails = details
	report.Errors = errors
	return report, nil
}

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

func enumerateTarget(ctx context.Context, target string) (*smtpfern.SmtpEnumerateDetails, []string) {
	log.Printf("[INFO] Starting enumeration for target: %s", target)
	detail := smtpfern.SmtpEnumerateDetails{
		Target: target,
	}
	errors := []string{}

	// Get hostname for HELLO command and TLS
	hostname, _, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target format: %v", err))
		return &detail, errors
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
			return &detail, errors
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
	client, err := smtp.NewClient(conn, hostname)
	if err != nil {
		errors = append(errors, fmt.Sprintf("SMTP client creation failed: %v", err))
		return &detail, errors
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

	return &detail, errors
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

func testUnauthenticatedEmail(c *smtp.Client, hostname string) bool {
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
