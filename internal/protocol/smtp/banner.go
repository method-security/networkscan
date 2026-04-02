// Package smtp provides shared SMTP protocol utilities used across discover and enumerate modules.
package smtp

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
)

// ParseBanner extracts server name and software info from a 220 banner.
// Common formats:
//
//	"220 mail.example.com ESMTP Postfix"
//	"220 mail.example.com ESMTP hMailServer 5.6.9"
//	"220-mail.example.com ESMTP"
func ParseBanner(banner string) (serverName, softwareName, softwareVersion string) {
	line := banner
	if strings.HasPrefix(line, "220-") {
		line = line[4:]
	} else if strings.HasPrefix(line, "220 ") {
		line = line[4:]
	} else {
		return
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	serverName = parts[0]

	// Skip ESMTP/SMTP marker to find software name
	idx := 1
	for idx < len(parts) {
		upper := strings.ToUpper(parts[idx])
		if upper == "ESMTP" || upper == "SMTP" {
			idx++
			break
		}
		idx++
	}

	if idx < len(parts) {
		remaining := parts[idx:]
		// Try to find version-like token (starts with digit)
		for i, token := range remaining {
			if len(token) > 0 && token[0] >= '0' && token[0] <= '9' {
				softwareName = strings.Join(remaining[:i], " ")
				softwareVersion = strings.Join(remaining[i:], " ")
				return
			}
		}
		softwareName = strings.Join(remaining, " ")
	}

	return
}

// ReadBannerFromConn reads the SMTP 220 banner using a bufio.Reader for reliable
// line-oriented reading, then wraps the connection so the banner bytes can be
// replayed by net/smtp.NewClient.
func ReadBannerFromConn(conn net.Conn) (net.Conn, string, error) {
	var buf bytes.Buffer
	tee := io.TeeReader(conn, &buf)
	reader := bufio.NewReader(tee)

	banner := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return conn, "", err
		}
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(trimmed, "220") {
			break
		}
		if banner == "" {
			banner = trimmed
		}

		// "220 " (space at index 3) is the final banner line
		if len(trimmed) >= 4 && trimmed[3] == ' ' {
			break
		}
		if len(trimmed) < 4 {
			break
		}
	}

	// Wrap connection: replay buffered data, then continue reading from conn
	// The bufio.Reader may have buffered extra bytes beyond what TeeReader wrote,
	// so we need to include any remaining buffered data too.
	remaining := make([]byte, reader.Buffered())
	if len(remaining) > 0 {
		_, _ = reader.Read(remaining)
	}

	wrapped := &replayConn{
		Conn:   conn,
		reader: io.MultiReader(&buf, bytes.NewReader(remaining), conn),
	}
	return wrapped, banner, nil
}

// replayConn wraps a net.Conn, replaying buffered data before reading from the real connection.
type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
