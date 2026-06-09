// Package socket implements raw TCP/UDP socket send and receive functionality.
package socket

import (
	// Standard
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// Logging
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// parseHexEscaped converts a string that may contain \x-escaped hex sequences into raw bytes.
// For example, "\x00\x01hello" becomes []byte{0x00, 0x01, 0x68, 0x65, 0x6c, 0x6c, 0x6f}.
// Returns an error if an incomplete or invalid \x escape sequence is encountered.
func parseHexEscaped(s string) ([]byte, error) {
	var result []byte
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == 'x' {
			// Require exactly 2 hex digits after \x
			if i+3 >= len(s) {
				return nil, fmt.Errorf("incomplete \\x escape at position %d", i)
			}
			hexStr := s[i+2 : i+4]
			b, err := hex.DecodeString(hexStr)
			if err != nil {
				return nil, fmt.Errorf("invalid hex escape \\x%s at position %d: %v", hexStr, i, err)
			}
			result = append(result, b...)
			i += 4
			continue
		}
		result = append(result, s[i])
		i++
	}
	return result, nil
}

// extractBanner filters out non-printable characters from bytes and returns a readable ASCII string.
func extractBanner(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		r := rune(b)
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}

// RunSocketSend opens a raw TCP or UDP socket to the target, optionally sends data,
// reads the response, and returns a structured report.
func RunSocketSend(ctx context.Context, config discoverfern.DiscoverSocketConfig) (*discoverfern.DiscoverSocketReport, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Running socket send",
		svc1log.SafeParam("target", config.Target),
		svc1log.SafeParam("protocol", config.Protocol))

	// Apply defaults and enforce caps directly to config so the report reflects effective values used.
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 5
	}
	const maxResponseBytesLimit = 10240
	if config.MaxResponseBytes <= 0 {
		config.MaxResponseBytes = maxResponseBytesLimit
	} else if config.MaxResponseBytes > maxResponseBytesLimit {
		// Cap at the documented 10 KB response limit regardless of caller input.
		config.MaxResponseBytes = maxResponseBytesLimit
	}

	report := &discoverfern.DiscoverSocketReport{
		Config: &config,
		Result: &discoverfern.DiscoverSocketResult{},
		Errors: []string{},
	}

	// Parse target into host and port
	host, portStr, err := net.SplitHostPort(config.Target)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("failed to parse target %q: %v", config.Target, err))
		connFailed := false
		report.Result.Response = &discoverfern.SocketResponseDetails{
			Ip:                   host,
			Port:                 0,
			Protocol:             config.Protocol,
			ConnectionSuccessful: connFailed,
		}
		return report, nil
	}

	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("failed to parse port %q: %v", portStr, err))
		connFailed := false
		report.Result.Response = &discoverfern.SocketResponseDetails{
			Ip:                   host,
			Port:                 0,
			Protocol:             config.Protocol,
			ConnectionSuccessful: connFailed,
		}
		return report, nil
	}

	// Reject ports outside the valid TCP/UDP range before dialing.
	if portInt < 1 || portInt > 65535 {
		report.Errors = append(report.Errors, fmt.Sprintf("port %d is outside the valid range [1, 65535]", portInt))
		connFailed := false
		report.Result.Response = &discoverfern.SocketResponseDetails{
			Ip:                   host,
			Port:                 portInt,
			Protocol:             config.Protocol,
			ConnectionSuccessful: connFailed,
		}
		return report, nil
	}

	// Parse and validate send data BEFORE dialing so malformed escapes or
	// oversized payloads never open a network connection (Fixes: invalid payload
	// dials first + no outbound payload size cap).
	const maxSendBytes = 10240
	var sendBytes []byte
	if config.SendData != nil && *config.SendData != "" {
		parsed, parseErr := parseHexEscaped(*config.SendData)
		if parseErr != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("invalid send data: %v", parseErr))
			connFalse := false
			report.Result.Response = &discoverfern.SocketResponseDetails{
				Ip:                   host,
				Port:                 portInt,
				Protocol:             config.Protocol,
				ConnectionSuccessful: connFalse,
			}
			return report, nil
		}
		if len(parsed) > maxSendBytes {
			report.Errors = append(report.Errors, fmt.Sprintf("send data too large: %d bytes (max %d)", len(parsed), maxSendBytes))
			connFalse := false
			report.Result.Response = &discoverfern.SocketResponseDetails{
				Ip:                   host,
				Port:                 portInt,
				Protocol:             config.Protocol,
				ConnectionSuccessful: connFalse,
			}
			return report, nil
		}
		sendBytes = parsed
	}

	// Determine network type
	network := "tcp"
	if config.Protocol == discoverfern.SocketTransportProtocolUdp {
		network = "udp"
	}

	// Single deadline context shared by dial AND read.
	// DialContext honours ctx cancellation (Ctrl-C / parent timeout).
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(config.ReadTimeout)*time.Second)
	defer cancel()

	log.Debug("Dialing target",
		svc1log.SafeParam("network", network),
		svc1log.SafeParam("target", config.Target),
		svc1log.SafeParam("timeoutSeconds", config.ReadTimeout))

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, network, config.Target)
	if err != nil {
		log.Info("Socket dial failed",
			svc1log.SafeParam("target", config.Target),
			svc1log.SafeParam("error", err.Error()))
		report.Errors = append(report.Errors, fmt.Sprintf("connection failed: %v", err))
		connFailed := false
		report.Result.Response = &discoverfern.SocketResponseDetails{
			Ip:                   host,
			Port:                 portInt,
			Protocol:             config.Protocol,
			ConnectionSuccessful: connFailed,
		}
		return report, nil
	}
	defer func() { _ = conn.Close() }()
	log.Debug("Socket dial successful", svc1log.SafeParam("target", config.Target))

	// Fix 1: Resolve the real IP from the established connection's remote address.
	// host may be a hostname; conn.RemoteAddr() gives us the actual resolved IP.
	resolvedIP := host
	if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
		if h, _, splitErr := net.SplitHostPort(remoteAddr.String()); splitErr == nil {
			resolvedIP = h
		}
	}

	// Extract deadline before write section so SetWriteDeadline can use it.
	deadline, ok := dialCtx.Deadline()
	if !ok {
		deadline = time.Now().Add(time.Duration(config.ReadTimeout) * time.Second)
	}

	// Send pre-validated payload if provided.
	if len(sendBytes) > 0 {
		// Set write deadline before calling conn.Write.
		if writeDeadlineErr := conn.SetWriteDeadline(deadline); writeDeadlineErr != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("failed to set write deadline: %v", writeDeadlineErr))
			connTrue := true
			report.Result.Response = &discoverfern.SocketResponseDetails{
				Ip:                   resolvedIP,
				Port:                 portInt,
				Protocol:             config.Protocol,
				ConnectionSuccessful: connTrue,
			}
			return report, nil
		}

		if _, writeErr := conn.Write(sendBytes); writeErr != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("send failed: %v", writeErr))
			connTrue := true
			report.Result.Response = &discoverfern.SocketResponseDetails{
				Ip:                   resolvedIP,
				Port:                 portInt,
				Protocol:             config.Protocol,
				ConnectionSuccessful: connTrue,
			}
			return report, nil
		}
		log.Debug("Sent payload",
			svc1log.SafeParam("bytesSent", len(sendBytes)))
	}

	// Read deadline comes from the same context deadline — no doubling.
	// Return early if SetReadDeadline fails — don't Read without a deadline.
	if err := conn.SetReadDeadline(deadline); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("failed to set read deadline: %v", err))
		connTrue := true
		report.Result.Response = &discoverfern.SocketResponseDetails{
			Ip:                   resolvedIP,
			Port:                 portInt,
			Protocol:             config.Protocol,
			ConnectionSuccessful: connTrue,
		}
		return report, nil
	}

	// Read loop — accumulate until timeout, EOF, or max bytes.
	var responseBytes []byte
	readBuf := make([]byte, 4096)
	for len(responseBytes) < config.MaxResponseBytes {
		remaining := config.MaxResponseBytes - len(responseBytes)
		chunk := readBuf
		if remaining < len(chunk) {
			chunk = chunk[:remaining]
		}
		n, readErr := conn.Read(chunk)
		if n > 0 {
			responseBytes = append(responseBytes, chunk[:n]...)
		}
		if readErr != nil {
			// Timeout and EOF are normal terminators — not errors.
			var netErr net.Error
			isTimeout := errors.As(readErr, &netErr) && netErr.Timeout()
			if isTimeout {
				log.Debug("Read deadline exceeded",
					svc1log.SafeParam("target", config.Target),
					svc1log.SafeParam("bytesReceived", len(responseBytes)))
			} else if !errors.Is(readErr, io.EOF) {
				report.Errors = append(report.Errors, fmt.Sprintf("read error: %v", readErr))
			}
			break
		}
	}
	log.Info("Socket read complete",
		svc1log.SafeParam("target", config.Target),
		svc1log.SafeParam("bytesReceived", len(responseBytes)))

	// Build response details — connection was successful even if read had partial/timeout error
	hexEncoded := hex.EncodeToString(responseBytes)
	banner := extractBanner(responseBytes)
	byteCount := len(responseBytes)

	connTrue := true
	details := &discoverfern.SocketResponseDetails{
		Ip:                   resolvedIP,
		Port:                 portInt,
		Protocol:             config.Protocol,
		ConnectionSuccessful: connTrue,
	}

	if byteCount > 0 {
		details.ResponseData = &hexEncoded
		details.ResponseBytes = &byteCount
		if banner != "" {
			details.Banner = &banner
		}
	}

	report.Result.Response = details
	return report, nil
}
