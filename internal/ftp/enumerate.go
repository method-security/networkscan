package ftp

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	ftpFern "github.com/Method-Security/networkscan/generated/go/ftp"
)

var bufferSize = 2048

// RunFTPEnumerate Overview:
//  1. Connect to the target
//     a. Exit if connection isnt established
//  2. Grab the FTP banner
//     a. Exit if no banner is returned (assume FTP is not implemented)
//     b. Else set successful connection to true
//  3. Check if TLS is implemented
//     a. Send a 'FEAT' command
//     b. Check if the response contains TLS, SSL or RFC 2228 or 4217
//  4. Check if TLS is forced
//     a. Send a 'AUTH TLS' command
//     b. Check if the response contains 234 which indicates TLS forced
//  5. Check if anonymous login is supported with retry on broken pipe errors
//     (This happens when the connection has been open for too long or too many invalid commands have been sent
//     The connection is closed by the server)
//     a. Send a 'USER anonymous' command
//     b. Check if the response contains 331 which indicates anonymous login supported
//     c. Send a 'PASS anonymous' command
//     d. Check if the response contains 230 which indicates anonymous login successful
//  6. Return the details
//     a. Banner
//     b. Successful Connection
//     c. TLS Implemented
//     d. TLS Forced
//     e. Allows Anonymous Login

func RunFTPEnumerate(ctx context.Context, targets []string, timeout int) (ftpFern.FtpEnumerateReport, error) {
	log.Printf("[INFO] Starting FTP enumeration for %d targets with a timeout of %ds", len(targets), timeout)
	report := ftpFern.FtpEnumerateReport{Targets: targets}

	// Create channels for collecting results and errors
	detailsChan := make(chan *ftpFern.FtpEnumerateDetails, len(targets))
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
				detail *ftpFern.FtpEnumerateDetails
				errs   []string
			}, 1)

			go func() {
				detail, errs := enumerateTarget(targetCtx, target)
				resultChan <- struct {
					detail *ftpFern.FtpEnumerateDetails
					errs   []string
				}{detail, errs}
			}()

			// Wait for either completion or timeout
			select {
			case <-targetCtx.Done():
				if targetCtx.Err() == context.DeadlineExceeded {
					errMsg := fmt.Sprintf("parameter timeout (%ds) while enumerating %s", timeout, target)
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
	var details []*ftpFern.FtpEnumerateDetails
	var errors []string

	// Read from channels until they're closed
	for detail := range detailsChan {
		details = append(details, detail)
	}
	for err := range errorsChan {
		errors = append(errors, err)
	}

	log.Printf("[INFO] Enumeration complete. Processed %d targets with %d errors", len(targets), len(errors))
	report.FtpDetails = details
	report.Errors = errors
	return report, nil
}

func enumerateTarget(ctx context.Context, target string) (*ftpFern.FtpEnumerateDetails, []string) {
	var details ftpFern.FtpEnumerateDetails
	details.Target = target
	errors := []string{}
	log.Printf("[INFO] Enumerating target: %s", target)

	// Attempt to connect to the target
	conn, err := attemptConnection(ctx, target)
	if err != nil {
		log.Printf("[ERROR] Failed to connect to %s: %v", target, err)
		errors = append(errors, fmt.Sprintf("Failed to connect to %s: %v", target, err))
		return &details, errors
	}

	// Grab the FTP banner
	bannerStr, err := grabBanner(conn)
	if err != nil {
		errors = append(errors, fmt.Sprintf("error reading banner from %s: %v", target, err))
		return &details, errors
	}
	details.Banner = &bannerStr
	successFulConnection := true
	details.SuccessfulConnection = &successFulConnection

	// Check TLS implemented
	if err := checkTLSImplemented(conn, &details); err != nil {
		errors = append(errors, fmt.Sprintf("error checking if TLS is implemented for %s: %v", target, err))
	}
	if details.TlsImplemented != nil && !*details.TlsImplemented {
		tlsForced := false
		details.TlsForced = &tlsForced
	}

	// Check TLS forced (Only check if TLS is implemented)
	if details.TlsForced == nil {
		errs := checkTLSForced(conn, &details)
		if len(errs) > 0 {
			errors = append(errors, errs...)
		}
	}

	// Check if anonymous login is supported
	errs := checkAnonymousLoginWithRetry(ctx, target, conn, &details)
	if len(errs) > 0 {
		errors = append(errors, errs...)
	}

	err = conn.Close()
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to close connection: %v", err))
	}

	return &details, errors
}

// Function to attempt connection with retry on timeout or broken pipe errors
func attemptConnection(ctx context.Context, target string) (net.Conn, error) {
	dialer := net.Dialer{}
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

// Function to grab the FTP banner
func grabBanner(conn net.Conn) (string, error) {
	var bannerStr string
	response := make([]byte, bufferSize)
	for {
		n, err := conn.Read(response)
		if err != nil {
			return "", fmt.Errorf("error reading initial banner: %v", err)
		}
		// Safely append raw bytes without assuming ASCII encoding
		bannerStr += string(response[:n])

		log.Printf("[INFO] Reading banner, current content (partial): %x", response[:n]) // Log as hex to handle non-ASCII characters

		if strings.Contains(bannerStr, "220") {
			break
		}
	}
	log.Printf("[INFO] Final banner: %s", strings.TrimSpace(bannerStr))
	return bannerStr, nil
}

// Function to check for anonymous login with retry on failure
func checkAnonymousLoginWithRetry(ctx context.Context, target string, conn net.Conn, details *ftpFern.FtpEnumerateDetails) []string {
	errors := []string{}
	if err := checkAnonymousLogin(conn, details); err != nil {
		log.Printf("[WARNING] Error checking anonymous login, retrying...")

		// Reconnect and retry
		conn, err = attemptConnection(ctx, target)
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
	timeout := time.After(5 * time.Second)

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
