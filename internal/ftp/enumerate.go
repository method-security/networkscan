package ftp

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	ftpFern "github.com/Method-Security/networkscan/generated/go/ftp"
)

var bufferSize = 2048

func RunFTPEnumerate(ctx context.Context, targets []string, connectionTimeout int) (ftpFern.FtpEnumerateReport, error) {
	// Initialize the report
	report := ftpFern.FtpEnumerateReport{Targets: targets}
	errors := []string{}

	details := []*ftpFern.FtpEnumerateDetails{}
	for _, target := range targets {
		// Set a new clock for each target
		targetCtx, targetCancel := context.WithTimeout(ctx, time.Duration(connectionTimeout)*time.Second)
		defer targetCancel()

		detail, errs := enumerateTarget(targetCtx, target, connectionTimeout)
		if len(errs) > 0 {
			for _, err := range errs {
				if targetCtx.Err() == context.DeadlineExceeded {
					log.Printf("[ERROR] Parameter timeout while enumerating %s\n", target)
					errors = append(errors, fmt.Sprintf("Parameter timeout while enumerating %s", target))
				} else {
					log.Printf("[ERROR] Error enumerating %s: %v\n", target, err)
					errors = append(errors, err)
				}
			}
		}
		if detail != nil {
			details = append(details, detail)
		}
	}

	report.FtpDetails = details
	report.Errors = errors
	return report, nil
}

func enumerateTarget(ctx context.Context, target string, timeout int) (*ftpFern.FtpEnumerateDetails, []string) {
	var details ftpFern.FtpEnumerateDetails
	details.Target = target
	errors := []string{}
	log.Printf("[INFO] Enumerating target: %s", target)

	conn, err := attemptConnection(ctx, target, timeout)
	if err != nil {
		log.Printf("[ERROR] Failed to connect to %s: %v", target, err)
		errors = append(errors, fmt.Sprintf("Failed to connect to %s: %v", target, err))
		return &details, errors
	}

	bannerStr, err := grabBanner(conn)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error reading banner from %s: %v", target, err))
	}
	if bannerStr == "" {
		errors = append(errors, fmt.Sprintf("No banner received from %s", target))
		return &details, errors
	}
	details.Banner = &bannerStr

	// Check TLS and anonymous login
	if err := checkTLSImplemented(conn, &details); err != nil {
		errors = append(errors, fmt.Sprintf("Error checking if TLS is implemented for %s: %v", target, err))
	}

	if details.TlsImplemented != nil && !*details.TlsImplemented {
		details.TlsForced = new(bool)
		*details.TlsForced = false
	}

	//Only check TLS forced if TLS is implemented
	if details.TlsForced == nil {
		errs := checkTLSForced(conn, &details)
		if len(errs) > 0 {
			errors = append(errors, errs...)
		}
	}

	errs := checkAnonymousLoginWithRetry(ctx, target, conn, &details, timeout)
	if len(errs) > 0 {
		errors = append(errors, errs...)
	}

	if isSuccessfulConnection(conn, bannerStr) {
		success := true
		details.SuccessfulConnection = &success
		log.Printf("[INFO] Success: Valid FTP connection for %s", target)
	} else {
		log.Printf("[WARNING] Unexpected greeting from %s", target)
		errors = append(errors, fmt.Sprintf("Unexpected greeting from %s: %s", target, strings.TrimSpace(bannerStr)))
	}

	err = conn.Close()
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to close connection: %v", err))
	}

	return &details, errors
}

// Function to attempt connection with retry on timeout or broken pipe errors
func attemptConnection(ctx context.Context, target string, timeout int) (net.Conn, error) {
	dialer := net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Printf("[ERROR] Initial connection failed: %v", err)
		// Retry once if it was a broken pipe error
		if strings.Contains(err.Error(), "broken pipe") {
			log.Printf("[INFO] Retrying connection to %s", target)
			conn, err = dialer.DialContext(ctx, "tcp", target)
		}
	}
	return conn, err
}

// Function to check if the connection is successful by sending HELP
func isSuccessfulConnection(conn net.Conn, banner string) bool {
	// First check for the banner to ensure it's a valid FTP greeting
	if strings.HasPrefix(banner, "220") {
		return true
	}

	// Send the HELP command to check if the server responds
	_, err := conn.Write([]byte("HELP\r\n"))
	if err != nil {
		log.Printf("[ERROR] Failed to send HELP command: %v", err)
		return false
	}

	// Prepare to read the response from the server
	response := make([]byte, bufferSize)
	n, err := conn.Read(response)
	if err != nil {
		log.Printf("[ERROR] failed reading HELP response: %v", err)
		return false
	}

	// If we got a response, return true (indicating successful connection)
	if n > 0 {
		log.Printf("[INFO] HELP response received")
		return true
	}

	// If no response, return false
	log.Printf("[WARNING] No response to HELP command.")
	return false
}

// Function to grab the FTP banner
func grabBanner(conn net.Conn) (string, error) {
	var bannerStr string
	response := make([]byte, bufferSize)
	for {
		n, err := conn.Read(response)
		if err != nil {
			return "", fmt.Errorf("error reading initial banner: %v", err)
		}
		bannerStr += string(response[:n])
		log.Printf("[INFO] Reading banner, current content: %s", bannerStr) // Log intermediate results

		if strings.Contains(bannerStr, "220") {
			break
		}
	}
	log.Printf("[INFO] Initial banner: %s", strings.TrimSpace(bannerStr))
	return bannerStr, nil
}

// Function to check for anonymous login with retry on failure
func checkAnonymousLoginWithRetry(ctx context.Context, target string, conn net.Conn, details *ftpFern.FtpEnumerateDetails, timeout int) []string {
	errors := []string{}
	if err := checkAnonymousLogin(conn, details); err != nil {
		log.Printf("[WARNING] Error checking anonymous login, retrying...")

		// Reconnect and retry
		conn, err = attemptConnection(ctx, target, timeout)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to reconnect: %v", err))
			return errors
		}

		// Retry checking anonymous login after reconnect
		err = checkAnonymousLogin(conn, details)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to reconnect: %v", err))
		}
		err = conn.Close()
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to close connection: %v", err))
		}
	}

	return errors
}

// Function to check for anonymous login
func checkAnonymousLogin(conn net.Conn, details *ftpFern.FtpEnumerateDetails) error {
	log.Printf("[INFO] Checking for anonymous login...")

	// Send the USER anonymous command
	_, err := conn.Write([]byte("USER anonymous\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send USER command: %v", err)
	}

	// Read the response from the server
	response := make([]byte, bufferSize)
	n, err := conn.Read(response)
	if err != nil {
		return fmt.Errorf("error reading anonymous login response: %v", err)
	}

	if n > 0 {
		responseStr := string(response[:n])
		log.Printf("[INFO] Anonymous login response received")

		if strings.HasPrefix(responseStr, "331") {
			_, err = conn.Write([]byte("PASS anonymous\r\n"))
			if err != nil {
				return fmt.Errorf("failed to send PASS command: %v", err)
			}

			// Read the response from the server after sending the password
			n, err = conn.Read(response)
			if err != nil {
				return fmt.Errorf("error reading response after sending password: %v", err)
			}

			if n > 0 {
				responseStr = string(response[:n])
				log.Printf("[INFO] Password response received")

				// Check for response indicating anonymous login status
				if strings.HasPrefix(responseStr, "530") {
					details.AllowsAnonymousLogin = new(bool)
					*details.AllowsAnonymousLogin = false
					log.Printf("[INFO] Anonymous login not supported (530 response)")
				} else if strings.HasPrefix(responseStr, "230") {
					details.AllowsAnonymousLogin = new(bool)
					*details.AllowsAnonymousLogin = true
					log.Printf("[INFO] Anonymous login supported")
				} else {
					details.AllowsAnonymousLogin = new(bool)
					*details.AllowsAnonymousLogin = false
					log.Printf("[WARNING] Unexpected response: %s", strings.TrimSpace(responseStr))
				}
			}
		} else {
			details.AllowsAnonymousLogin = new(bool)
			*details.AllowsAnonymousLogin = false
			log.Printf("[INFO] Anonymous login not supported (no 331 response)")
		}
	}

	return nil
}

// Function to check if TLS is implemented (supported) using the FEAT command
func checkTLSImplemented(conn net.Conn, details *ftpFern.FtpEnumerateDetails) error {
	log.Printf("[INFO] Sending FEAT command to check if TLS is implemented...")
	_, err := conn.Write([]byte("FEAT\r\n"))
	if err != nil {
		return fmt.Errorf("error sending FEAT command: %v", err)
	}

	var featResponse string
	response := make([]byte, bufferSize)
	timeout := time.After(10 * time.Second) // Ensure timeout is set correctly

readLoop: // Label for the outer loop
	for {
		select {
		case <-timeout:
			log.Printf("[ERROR] Timeout while reading FEAT response.")
			return fmt.Errorf("timeout while reading FEAT response")
		default:
			err = conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Set a read deadline
			if err != nil {
				log.Printf("[ERROR] failed to set read deadline: %v", err)
				return fmt.Errorf("failed to set read deadline: %v", err)
			}
			n, err := conn.Read(response)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if err.Error() == "EOF" {
					log.Printf("[INFO] EOF encountered: TLS not implemented (no response from server).")
					return nil
				}
				return fmt.Errorf("error reading FEAT response: %v", err)
			}
			featResponse += string(response[:n])
			if strings.Contains(featResponse, "211 End") || n == 0 {
				break readLoop
			}
		}
	}

	fmt.Println("[DEBUG] featResponse: ", featResponse) // Ensure this is outside the loop

	// RFC 2228 and 4217 both enable TLS commands
	if strings.Contains(featResponse, "TLS") || strings.Contains(featResponse, "SSL") || (strings.Contains(featResponse, "RFC") && (strings.Contains(featResponse, "2228") || strings.Contains(featResponse, "4217"))) {
		details.TlsImplemented = new(bool)
		*details.TlsImplemented = true
		log.Printf("[INFO] TLS Implemented")
	} else {
		details.TlsImplemented = new(bool)
		*details.TlsImplemented = false
		log.Printf("[INFO] TLS not implemented")
	}

	return nil
}

// Function to check if TLS is forced (i.e., required by the server)
func checkTLSForced(conn net.Conn, details *ftpFern.FtpEnumerateDetails) []string {
	log.Printf("[INFO] Sending TLS commands to check if TLS is forced...")
	errors := []string{}
	_, err := conn.Write([]byte("AUTH TLS\r\n"))
	if err != nil {
		errors = append(errors, fmt.Sprintf("error sending AUTH TLS command: %v", err))
		_, err = conn.Write([]byte("STARTTLS\r\n"))
		if err != nil {
			errors = append(errors, fmt.Sprintf("error sending STARTTLS command: %v", err))
			return errors
		}

	}

	response := make([]byte, bufferSize)
	n, err := conn.Read(response)
	if err != nil {
		errors = append(errors, fmt.Sprintf("error reading TLS response: %v", err))
		return errors
	}

	if n > 0 {
		tlsResponse := string(response[:n])
		log.Printf("[INFO] TLS response received")

		tlsForced := strings.HasPrefix(tlsResponse, "234")
		details.TlsForced = &tlsForced
		log.Printf("[INFO] TLS Forced: %v", tlsForced)
	} else {
		details.TlsForced = new(bool)
		*details.TlsForced = false
		log.Printf("[WARNING] No response or unexpected response for TLS, TLS not forced.")
	}

	return nil
}
