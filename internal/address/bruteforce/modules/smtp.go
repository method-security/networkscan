package host

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/address/bruteforce"
)

type SMTPLibrary struct{}

func (SMTP *SMTPLibrary) StandardPorts() []int {
	return []int{25, 587, 465}
}

// readResponse reads from the connection with a timeout
func readResponse(conn net.Conn) (string, error) {
	if conn == nil {
		return "", errors.New("connection is nil")
	}

	response := make([]byte, bufferSize)
	n, err := conn.Read(response)
	if err != nil {
		if err == io.EOF {
			log.Printf("[ERROR] Connection closed by server")
			return "", errors.New("connection closed by server")
		}
		log.Printf("[ERROR] Failed to read response: %v", err)
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	responseStr := string(response[:n])
	log.Printf("[DEBUG] Received response: %s", strings.TrimSpace(responseStr))
	return responseStr, nil
}

// sendCommand sends a command to the SMTP server and reads the response
func sendCommand(conn net.Conn, command string, isCredential bool) (string, error) {
	if conn == nil {
		return "", errors.New("connection is nil")
	}

	if isCredential {
		log.Printf("[DEBUG] Sending credential data...")
	} else {
		log.Printf("[DEBUG] Sending command: %s", command)
	}

	_, err := conn.Write([]byte(command + "\r\n"))
	if err != nil {
		log.Printf("[ERROR] Failed to send command: %v", err)
		return "", fmt.Errorf("failed to send command: %v", err)
	}

	time.Sleep(2 * time.Second)
	return readResponse(conn)
}

// upgradeTLS upgrades the connection to TLS
func upgradeTLS(conn net.Conn, host string) (net.Conn, error) {
	// Send STARTTLS command
	response, err := sendCommand(conn, "STARTTLS", false)
	if err != nil {
		return nil, fmt.Errorf("STARTTLS failed: %v", err)
	}

	if !strings.Contains(response, "220") {
		return nil, fmt.Errorf("server does not support STARTTLS: %s", response)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // Note: This is for testing purposes only
	}

	// Upgrade connection to TLS
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	return tlsConn, nil
}

// BruteForce attempts to authenticate with the SMTP server
func (SMTP *SMTPLibrary) BruteForce(host string, port int, credPair *bruteforce.CredentialPair, config *bruteforce.BruteForceRunConfig) (*bruteforce.AttemptInfo, []string) {
	log.Printf("[INFO] Starting SMTP bruteforce attempt on %s:%d", host, port)

	attempt := &bruteforce.AttemptInfo{
		Timestamp: time.Now(),
	}
	var errors []string

	// Initialize credentials
	username, password := "", ""
	if credPair != nil {
		username = fmt.Sprintf("%s@%s", credPair.Username, host)
		password = credPair.Password
		log.Printf("[INFO] Attempting authentication with username: %s", username)
	}

	// Create connection with timeout
	address := fmt.Sprintf("%s:%d", host, port)
	log.Printf("[DEBUG] Creating connection to %s", address)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Timeout)*time.Millisecond)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		log.Printf("[ERROR] Connection failed: %v", err)
		errors = append(errors, fmt.Sprintf("connection failed: %v", err))
		attempt.Request = bruteforce.NewRequestUnionFromGeneralRequest(&bruteforce.GeneralRequestInfo{
			Host: host,
			Port: port,
		})
		return attempt, errors
	}
	log.Printf("[INFO] Connection established to %s", address)

	// Read banner
	log.Printf("[DEBUG] Reading server banner")
	_, err = readResponse(conn)
	if err != nil {
		log.Printf("[ERROR] Banner read failed: %v", err)
		errors = append(errors, fmt.Sprintf("banner read failed: %v", err))
		return attempt, errors
	}
	log.Printf("[DEBUG] Banner read successfully")

	// Send initial EHLO
	log.Printf("[DEBUG] Sending initial EHLO command")
	ehloResponse, err := sendCommand(conn, fmt.Sprintf("EHLO %s", host), false)
	if err != nil {
		log.Printf("[ERROR] Initial EHLO failed: %v", err)
		errors = append(errors, fmt.Sprintf("EHLO failed: %v", err))
		return attempt, errors
	}

	if !strings.Contains(ehloResponse, "250") {
		log.Printf("[ERROR] Server rejected initial EHLO")
		errors = append(errors, "server rejected EHLO")
		return attempt, errors
	}
	log.Printf("[INFO] Initial EHLO successful")

	// Upgrade to TLS
	log.Printf("[INFO] Attempting to upgrade connection to TLS")
	conn, err = upgradeTLS(conn, host)
	if err != nil {
		log.Printf("[ERROR] TLS upgrade failed: %v", err)
		errors = append(errors, fmt.Sprintf("TLS upgrade failed: %v", err))
		return attempt, errors
	}
	log.Printf("[INFO] TLS upgrade successful")

	// Send EHLO again after TLS upgrade
	log.Printf("[DEBUG] Sending EHLO after TLS upgrade")
	ehloResponse, err = sendCommand(conn, fmt.Sprintf("EHLO %s", host), false)
	if err != nil {
		log.Printf("[ERROR] Post-TLS EHLO failed: %v", err)
		errors = append(errors, fmt.Sprintf("post-TLS EHLO failed: %v", err))
		return attempt, errors
	}

	if !strings.Contains(ehloResponse, "250") {
		log.Printf("[ERROR] Server rejected post-TLS EHLO")
		errors = append(errors, "server rejected post-TLS EHLO")
		return attempt, errors
	}
	log.Printf("[INFO] Post-TLS EHLO successful")

	// Try AUTH LOGIN first
	log.Printf("[DEBUG] Attempting AUTH LOGIN")
	authResponse, err := sendCommand(conn, "AUTH LOGIN", false)

	// If AUTH LOGIN fails with 504, try AUTH PLAIN
	if err == nil && strings.Contains(authResponse, "504") {
		log.Printf("[INFO] AUTH LOGIN not supported, trying AUTH PLAIN")

		// Format for AUTH PLAIN: \0username\0password
		authStr := fmt.Sprintf("\x00%s\x00%s", username, password)
		encodedAuth := base64.StdEncoding.EncodeToString([]byte(authStr))

		authResponse, err = sendCommand(conn, fmt.Sprintf("AUTH PLAIN %s", encodedAuth), true)
		if err != nil {
			log.Printf("[ERROR] AUTH PLAIN failed: %v", err)
			errors = append(errors, fmt.Sprintf("AUTH PLAIN failed: %v", err))
			return attempt, errors
		}
		log.Printf("[DEBUG] AUTH PLAIN sequence completed")
	} else if err != nil {
		log.Printf("[ERROR] AUTH LOGIN failed: %v", err)
		errors = append(errors, fmt.Sprintf("AUTH LOGIN failed: %v", err))
		return attempt, errors
	} else {
		// Continue with AUTH LOGIN sequence
		log.Printf("[DEBUG] AUTH LOGIN accepted, continuing sequence")

		// Send username (base64 encoded)
		encodedUsername := base64.StdEncoding.EncodeToString([]byte(username))
		log.Printf("[DEBUG] Sending encoded username")
		usernameResponse, err := sendCommand(conn, encodedUsername, true)
		if err != nil {
			log.Printf("[ERROR] Username auth failed: %v", err)
			errors = append(errors, fmt.Sprintf("username auth failed: %v", err))
			return attempt, errors
		}
		log.Printf("[DEBUG] Username sent successfully: %s", usernameResponse)

		// Send password (base64 encoded)
		encodedPassword := base64.StdEncoding.EncodeToString([]byte(password))
		log.Printf("[DEBUG] Sending encoded password")
		authResponse, err = sendCommand(conn, encodedPassword, true)
		if err != nil {
			log.Printf("[ERROR] Password auth failed: %v", err)
			errors = append(errors, fmt.Sprintf("password auth failed: %v", err))
			return attempt, errors
		}
		log.Printf("[DEBUG] Password sent successfully: %s", authResponse)
	}

	// Close connection
	err = conn.Close()
	if err != nil {
		log.Printf("[ERROR] Error closing connection: %v", err)
		errors = append(errors, fmt.Sprintf("error closing connection: %v", err))
	}

	// Prepare attempt info
	request := &bruteforce.GeneralRequestInfo{
		Username: &username,
		Password: &password,
		Host:     host,
		Port:     port,
	}
	responseInfo := &bruteforce.GeneralResponseInfo{
		Message: authResponse,
	}

	attempt.Request = bruteforce.NewRequestUnionFromGeneralRequest(request)
	attempt.Response = bruteforce.NewResponseUnionFromGeneralResponse(responseInfo)
	attempt.Result = SMTP.AnalyzeResponse(attempt.Response)

	log.Printf("[INFO] Authentication attempt completed. Success: %v, Ratelimited: %v",
		attempt.Result.Login,
		attempt.Result.Ratelimit)

	return attempt, errors
}

// AnalyzeResponse analyzes the server response to determine authentication result
func (SMTP *SMTPLibrary) AnalyzeResponse(response *bruteforce.ResponseUnion) *bruteforce.ResultInfo {
	if response == nil || response.GeneralResponse == nil {
		log.Printf("[WARN] Invalid response object received")
		return &bruteforce.ResultInfo{Login: false, Ratelimit: false}
	}

	result := &bruteforce.ResultInfo{
		Login: strings.Contains(response.GeneralResponse.Message, "235"), // 235 = Authentication successful
		Ratelimit: strings.Contains(strings.ToLower(response.GeneralResponse.Message), "rate limit") ||
			strings.Contains(strings.ToLower(response.GeneralResponse.Message), "too many connections"),
	}

	log.Printf("[DEBUG] Response analysis - Login: %v, Ratelimit: %v", result.Login, result.Ratelimit)
	return result
}
