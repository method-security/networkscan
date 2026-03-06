package ftp

import (
	// Standard
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	// Generated
	ftp "github.com/Method-Security/networkscan/generated/go/enumerate/ftp"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// Function to attempt connection with retry on timeout or broken pipe errors
func attemptConnection(ctx context.Context, target string) (net.Conn, error) {
	// Initialize
	log := svc1log.FromContext(ctx)

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Error("Initial connection failed", svc1log.SafeParam("error", err.Error()))
		// Retry once if it was a broken pipe error
		if strings.Contains(err.Error(), "broken pipe") {
			log.Info("Retrying connection due to broken pipe", svc1log.SafeParam("target", target))
			conn, err = dialer.DialContext(ctx, "tcp", target)
		}
	}
	return conn, err
}

// Function to grab the FTP banner
func grabBanner(ctx context.Context, conn net.Conn) (string, error) {
	log := svc1log.FromContext(ctx)

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", fmt.Errorf("failed to set read deadline: %v", err)
	}

	var bannerStr string
	response := make([]byte, bufferSize)
	for {
		n, err := conn.Read(response)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return "", fmt.Errorf("timeout reading FTP banner")
			}
			return "", fmt.Errorf("error reading initial banner: %v", err)
		}
		bannerStr += string(response[:n])

		log.Info("Reading banner, current content (partial)", svc1log.SafeParam("content", string(response[:n])))

		if strings.Contains(bannerStr, "220") {
			break
		}
	}

	err := conn.SetReadDeadline(time.Time{})
	if err != nil {
		return "", fmt.Errorf("failed to clear read deadline: %v", err)
	}

	log.Info("Final banner", svc1log.SafeParam("banner", strings.TrimSpace(bannerStr)))
	return bannerStr, nil
}

// Function to check for anonymous login with retry on failure
func checkAnonymousLoginWithRetry(ctx context.Context, target string, conn net.Conn, details *ftp.EnumerateFtpDetails) []string {
	log := svc1log.FromContext(ctx)

	errors := []string{}
	if err := checkAnonymousLogin(ctx, conn, details); err != nil {
		log.Warn("Error checking anonymous login, retrying...", svc1log.SafeParam("error", err.Error()))

		conn, err = attemptConnection(ctx, target)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to reconnect: %v", err))
			return errors
		}

		// Consume the banner from the new connection before retrying
		if _, bannerErr := grabBanner(ctx, conn); bannerErr != nil {
			errors = append(errors, fmt.Sprintf("failed to read banner after reconnect: %v", bannerErr))
			_ = conn.Close()
			return errors
		}

		err = checkAnonymousLogin(ctx, conn, details)
		if err != nil {
			errors = append(errors, fmt.Sprintf("anonymous login check failed after retry: %v", err))
		}
		if closeErr := conn.Close(); closeErr != nil {
			errors = append(errors, fmt.Sprintf("failed to close connection: %v", closeErr))
		}
	}

	return errors
}

// Function to check for anonymous login
func checkAnonymousLogin(ctx context.Context, conn net.Conn, details *ftp.EnumerateFtpDetails) error {
	log := svc1log.FromContext(ctx)

	log.Info("Checking for anonymous login...")

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("failed to set read deadline: %v", err)
	}

	_, err := conn.Write([]byte("USER anonymous\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send USER command: %v", err)
	}

	response := make([]byte, bufferSize)
	n, err := conn.Read(response)
	if err != nil {
		return fmt.Errorf("error reading anonymous login response: %v", err)
	}

	if n > 0 {
		responseStr := string(response[:n])
		log.Info("Anonymous login response received", svc1log.SafeParam("response", responseStr))

		if containsFTPCode(responseStr, "331") {
			_, err = conn.Write([]byte("PASS anonymous\r\n"))
			if err != nil {
				return fmt.Errorf("failed to send PASS command: %v", err)
			}

			n, err = conn.Read(response)
			if err != nil {
				return fmt.Errorf("error reading response after sending password: %v", err)
			}

			if n > 0 {
				responseStr = string(response[:n])
				log.Info("Password response received", svc1log.SafeParam("response", responseStr))

				if containsFTPCode(responseStr, "530") {
					details.AllowsAnonymousLogin = new(bool)
					*details.AllowsAnonymousLogin = false
					log.Info("Anonymous login not supported (530 response)")
				} else if containsFTPCode(responseStr, "230") {
					details.AllowsAnonymousLogin = new(bool)
					*details.AllowsAnonymousLogin = true
					log.Info("Anonymous login supported")
				} else {
					details.AllowsAnonymousLogin = new(bool)
					*details.AllowsAnonymousLogin = false
					log.Warn("Unexpected response", svc1log.SafeParam("response", strings.TrimSpace(responseStr)))
				}
			}
		} else {
			details.AllowsAnonymousLogin = new(bool)
			*details.AllowsAnonymousLogin = false
			log.Info("Anonymous login not supported (no 331 response)")
		}
	}

	if err = conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("failed to clear read deadline: %v", err)
	}

	return nil
}

// containsFTPCode checks if any line in a multi-line FTP response starts with the given code.
func containsFTPCode(response string, code string) bool {
	for _, line := range strings.Split(response, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), code) {
			return true
		}
	}
	return false
}

// Function to check if TLS is implemented (supported) using the FEAT command
func checkTLSImplemented(ctx context.Context, conn net.Conn, details *ftp.EnumerateFtpDetails) error {
	log := svc1log.FromContext(ctx)

	log.Info("Sending FEAT command to check if TLS is implemented...")
	_, err := conn.Write([]byte("FEAT\r\n"))
	if err != nil {
		return fmt.Errorf("error sending FEAT command: %v", err)
	}

	var featResponse string
	response := make([]byte, bufferSize)

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("failed to set read deadline: %v", err)
	}

	for {
		n, err := conn.Read(response)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Error("Timeout while reading FEAT response.")
				return fmt.Errorf("timeout while reading FEAT response")
			}
			if err.Error() == "EOF" {
				log.Info("EOF encountered: TLS not implemented (no response from server).")
				return nil
			}
			return fmt.Errorf("error reading FEAT response: %v", err)
		}
		featResponse += string(response[:n])
		if strings.Contains(featResponse, "211 End") || n == 0 {
			break
		}
	}

	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("failed to clear read deadline: %v", err)
	}

	log.Debug("FEAT response received", svc1log.SafeParam("response", featResponse))

	// RFC 2228 and 4217 both enable TLS commands
	if strings.Contains(featResponse, "TLS") || strings.Contains(featResponse, "SSL") || (strings.Contains(featResponse, "RFC") && (strings.Contains(featResponse, "2228") || strings.Contains(featResponse, "4217"))) {
		details.TlsImplemented = new(bool)
		*details.TlsImplemented = true
		log.Info("TLS Implemented")
	} else {
		details.TlsImplemented = new(bool)
		*details.TlsImplemented = false
		log.Info("TLS not implemented")
	}

	return nil
}

// Function to check if TLS is forced (i.e., required by the server)
func checkTLSForced(ctx context.Context, conn net.Conn, details *ftp.EnumerateFtpDetails) []string {
	log := svc1log.FromContext(ctx)

	log.Info("Sending TLS commands to check if TLS is forced...")
	errors := []string{}
	_, err := conn.Write([]byte("AUTH TLS\r\n"))
	if err != nil {
		errors = append(errors, fmt.Sprintf("error sending AUTH TLS command: %v", err))
		// AUTH TLS failed to send, try STARTTLS as fallback
		_, err = conn.Write([]byte("STARTTLS\r\n"))
		if err != nil {
			errors = append(errors, fmt.Sprintf("error sending STARTTLS command: %v", err))
			return errors
		}
	} else {
		// AUTH TLS was sent successfully, also try STARTTLS as a separate attempt
		_, starttlsErr := conn.Write([]byte("STARTTLS\r\n"))
		if starttlsErr != nil {
			errors = append(errors, fmt.Sprintf("error sending STARTTLS command: %v", starttlsErr))
		}
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		errors = append(errors, fmt.Sprintf("failed to set read deadline: %v", err))
		return errors
	}

	response := make([]byte, bufferSize)
	n, err := conn.Read(response)
	if err != nil {
		errors = append(errors, fmt.Sprintf("error reading TLS response: %v", err))
		return errors
	}

	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to clear read deadline: %v", err))
		return errors
	}

	if n > 0 {
		tlsResponse := string(response[:n])
		log.Info("TLS response received", svc1log.SafeParam("response", tlsResponse))

		tlsForced := strings.HasPrefix(tlsResponse, "234")
		details.TlsForced = &tlsForced
		log.Info("TLS Forced", svc1log.SafeParam("forced", tlsForced))
	} else {
		details.TlsForced = new(bool)
		*details.TlsForced = false
		log.Warn("No response or unexpected response for TLS, TLS not forced.")
	}

	return nil
}
