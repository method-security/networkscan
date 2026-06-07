// Package socket implements raw TCP/UDP socket send and receive functionality.
package socket

import (
	// Standard
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

// parseHexEscaped converts a string that may contain \x-escaped hex sequences into raw bytes.
// For example, "\x00\x01hello" becomes []byte{0x00, 0x01, 0x68, 0x65, 0x6c, 0x6c, 0x6f}.
func parseHexEscaped(s string) []byte {
	var result []byte
	i := 0
	for i < len(s) {
		if i+3 < len(s) && s[i] == '\\' && s[i+1] == 'x' {
			hexStr := s[i+2 : i+4]
			b, err := hex.DecodeString(hexStr)
			if err == nil {
				result = append(result, b...)
				i += 4
				continue
			}
		}
		result = append(result, s[i])
		i++
	}
	return result
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

	// Determine timeout
	readTimeout := config.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = 5
	}

	// Determine max response bytes
	maxResponseBytes := config.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = 10240
	}

	// Determine network type
	network := "tcp"
	if config.Protocol == discoverfern.SocketTransportProtocolUdp {
		network = "udp"
	}

	// Connect
	dialTimeout := time.Duration(readTimeout) * time.Second
	conn, err := net.DialTimeout(network, config.Target, dialTimeout)
	if err != nil {
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
	defer conn.Close()

	// Send data if specified
	if config.SendData != nil && *config.SendData != "" {
		sendBytes := parseHexEscaped(*config.SendData)
		if _, writeErr := conn.Write(sendBytes); writeErr != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("send failed: %v", writeErr))
			connTrue := true
			report.Result.Response = &discoverfern.SocketResponseDetails{
				Ip:                   host,
				Port:                 portInt,
				Protocol:             config.Protocol,
				ConnectionSuccessful: connTrue,
			}
			return report, nil
		}
	}

	// Set read deadline
	deadline := time.Now().Add(time.Duration(readTimeout) * time.Second)
	if err := conn.SetReadDeadline(deadline); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("failed to set read deadline: %v", err))
	}

	// Read response
	buf := make([]byte, maxResponseBytes)
	n, readErr := conn.Read(buf)

	// Build response details — connection was successful even if read had partial/timeout error
	responseBytes := buf[:n]
	hexEncoded := hex.EncodeToString(responseBytes)
	banner := extractBanner(responseBytes)
	byteCount := n

	connTrue := true
	details := &discoverfern.SocketResponseDetails{
		Ip:                   host,
		Port:                 portInt,
		Protocol:             config.Protocol,
		ConnectionSuccessful: connTrue,
	}

	if n > 0 {
		details.ResponseData = &hexEncoded
		details.ResponseBytes = &byteCount
		if banner != "" {
			details.Banner = &banner
		}
	}

	if readErr != nil {
		// Timeout or EOF is common and expected; only add non-EOF errors
		if !strings.Contains(readErr.Error(), "EOF") && !strings.Contains(readErr.Error(), "timeout") {
			report.Errors = append(report.Errors, fmt.Sprintf("read error: %v", readErr))
		}
	}

	report.Result.Response = details
	return report, nil
}
