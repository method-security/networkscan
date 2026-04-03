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

// listDirectory retrieves the directory listing using PASV + LIST after a successful anonymous login.
func listDirectory(ctx context.Context, conn net.Conn) ([]*ftp.FtpDirectoryEntry, []string) {
	log := svc1log.FromContext(ctx)
	var errors []string

	// Enter passive mode
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, []string{fmt.Sprintf("failed to set read deadline for PASV: %v", err)}
	}

	_, err := conn.Write([]byte("PASV\r\n"))
	if err != nil {
		return nil, []string{fmt.Sprintf("failed to send PASV command: %v", err)}
	}

	response := make([]byte, bufferSize)
	n, err := conn.Read(response)
	if err != nil {
		return nil, []string{fmt.Sprintf("failed to read PASV response: %v", err)}
	}

	pasvResponse := string(response[:n])
	log.Debug("PASV response", svc1log.SafeParam("response", pasvResponse))

	if !containsFTPCode(pasvResponse, "227") {
		return nil, []string{fmt.Sprintf("PASV not supported: %s", strings.TrimSpace(pasvResponse))}
	}

	// Parse PASV response to get data connection address
	dataAddr, err := parsePASVResponse(pasvResponse)
	if err != nil {
		return nil, []string{fmt.Sprintf("failed to parse PASV response: %v", err)}
	}

	// Open data connection
	dataConn, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		return nil, []string{fmt.Sprintf("failed to connect to data port %s: %v", dataAddr, err)}
	}
	defer func() { _ = dataConn.Close() }()

	// Send LIST command on control connection
	_, err = conn.Write([]byte("LIST\r\n"))
	if err != nil {
		return nil, []string{fmt.Sprintf("failed to send LIST command: %v", err)}
	}

	// Read LIST response code from control connection
	n, err = conn.Read(response)
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to read LIST response: %v", err))
	} else {
		listResponse := string(response[:n])
		log.Debug("LIST response", svc1log.SafeParam("response", listResponse))
		if !containsFTPCode(listResponse, "150") && !containsFTPCode(listResponse, "125") {
			return nil, []string{fmt.Sprintf("LIST command failed: %s", strings.TrimSpace(listResponse))}
		}
	}

	// Read directory data from data connection
	if err := dataConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, []string{fmt.Sprintf("failed to set data read deadline: %v", err)}
	}

	var listingData strings.Builder
	buf := make([]byte, 4096)
	for {
		rn, readErr := dataConn.Read(buf)
		if rn > 0 {
			listingData.Write(buf[:rn])
		}
		if readErr != nil {
			break
		}
	}

	// Read transfer complete from control connection
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Read(response)
	_ = conn.SetReadDeadline(time.Time{})

	// Parse directory listing
	entries := parseDirectoryListing(listingData.String())
	log.Info("Directory listing retrieved", svc1log.SafeParam("entries", len(entries)))

	return entries, errors
}

// parsePASVResponse extracts the data connection address from a 227 PASV response.
// Format: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
func parsePASVResponse(response string) (string, error) {
	start := strings.Index(response, "(")
	end := strings.Index(response, ")")
	if start == -1 || end == -1 || end <= start {
		return "", fmt.Errorf("invalid PASV response format: %s", response)
	}

	parts := strings.Split(response[start+1:end], ",")
	if len(parts) != 6 {
		return "", fmt.Errorf("invalid PASV address parts: %s", response)
	}

	host := fmt.Sprintf("%s.%s.%s.%s", parts[0], parts[1], parts[2], parts[3])
	p1 := 0
	p2 := 0
	if _, err := fmt.Sscanf(parts[4], "%d", &p1); err != nil {
		return "", fmt.Errorf("invalid PASV port high byte: %v", err)
	}
	if _, err := fmt.Sscanf(parts[5], "%d", &p2); err != nil {
		return "", fmt.Errorf("invalid PASV port low byte: %v", err)
	}
	port := p1*256 + p2

	return fmt.Sprintf("%s:%d", host, port), nil
}

// parseDirectoryListing parses Unix-style FTP LIST output into FtpDirectoryEntry structs.
func parseDirectoryListing(data string) []*ftp.FtpDirectoryEntry {
	var entries []*ftp.FtpDirectoryEntry
	lines := strings.Split(strings.TrimSpace(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "total ") {
			continue
		}

		entry := parseListLine(line)
		if entry != nil {
			entries = append(entries, entry)
		}
	}

	return entries
}

// parseListLine parses a single Unix-style ls -l line into an FtpDirectoryEntry.
// Format: drwxr-xr-x  2 user group  4096 Jan  1 12:00 dirname
func parseListLine(line string) *ftp.FtpDirectoryEntry {
	fields := strings.Fields(line)
	if len(fields) < 9 {
		// Try to at least extract the name from short lines
		if len(fields) > 0 {
			return &ftp.FtpDirectoryEntry{
				Name: fields[len(fields)-1],
				Type: ftp.FtpEntryTypeUnknown,
			}
		}
		return nil
	}

	perms := fields[0]
	name := strings.Join(fields[8:], " ")

	// Determine entry type from permission string
	entryType := ftp.FtpEntryTypeFile
	if len(perms) > 0 {
		switch perms[0] {
		case 'd':
			entryType = ftp.FtpEntryTypeDirectory
		case 'l':
			entryType = ftp.FtpEntryTypeLink
			// Strip symlink target (name -> target)
			if idx := strings.Index(name, " -> "); idx != -1 {
				name = name[:idx]
			}
		case '-':
			entryType = ftp.FtpEntryTypeFile
		default:
			entryType = ftp.FtpEntryTypeUnknown
		}
	}

	// Parse size
	var size *int64
	var sizeVal int64
	if _, err := fmt.Sscanf(fields[4], "%d", &sizeVal); err == nil {
		size = &sizeVal
	}

	// Construct last modified from date fields
	lastModified := fmt.Sprintf("%s %s %s", fields[5], fields[6], fields[7])

	return &ftp.FtpDirectoryEntry{
		Name:         name,
		Type:         entryType,
		Size:         size,
		Permissions:  &perms,
		LastModified: &lastModified,
	}
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

	// Track which command was sent so we check the correct response code
	sentSTARTTLS := false
	_, err := conn.Write([]byte("AUTH TLS\r\n"))
	if err != nil {
		errors = append(errors, fmt.Sprintf("error sending AUTH TLS command: %v", err))
		// AUTH TLS failed to send, try STARTTLS as fallback
		_, err = conn.Write([]byte("STARTTLS\r\n"))
		if err != nil {
			errors = append(errors, fmt.Sprintf("error sending STARTTLS command: %v", err))
			return errors
		}
		sentSTARTTLS = true
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

		if sentSTARTTLS {
			// We sent STARTTLS (AUTH TLS write failed); check for 220 success
			tlsForced := strings.HasPrefix(tlsResponse, "220")
			details.TlsForced = &tlsForced
			log.Info("STARTTLS response", svc1log.SafeParam("forced", tlsForced))
		} else if strings.HasPrefix(tlsResponse, "234") {
			// AUTH TLS accepted
			tlsForced := true
			details.TlsForced = &tlsForced
			log.Info("TLS Forced", svc1log.SafeParam("forced", tlsForced))
		} else {
			// AUTH TLS rejected by server, try STARTTLS as protocol-level fallback
			log.Info("AUTH TLS rejected, trying STARTTLS")
			// Drain any remaining multi-line response data before sending next command
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			drainBuf := make([]byte, bufferSize)
			_, _ = conn.Read(drainBuf)
			_ = conn.SetReadDeadline(time.Time{})

			tlsForced := false
			if _, writeErr := conn.Write([]byte("STARTTLS\r\n")); writeErr == nil {
				if setErr := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); setErr == nil {
					starttlsResp := make([]byte, bufferSize)
					sn, readErr := conn.Read(starttlsResp)
					_ = conn.SetReadDeadline(time.Time{})
					if readErr == nil && sn > 0 {
						starttlsResponse := string(starttlsResp[:sn])
						tlsForced = strings.HasPrefix(starttlsResponse, "220")
						log.Info("STARTTLS response", svc1log.SafeParam("response", starttlsResponse), svc1log.SafeParam("forced", tlsForced))
					}
				}
			}
			details.TlsForced = &tlsForced
		}
	} else {
		details.TlsForced = new(bool)
		*details.TlsForced = false
		log.Warn("No response or unexpected response for TLS, TLS not forced.")
	}

	return nil
}
