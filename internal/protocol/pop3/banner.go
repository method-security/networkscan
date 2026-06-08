// Package pop3 provides shared POP3 protocol utilities.
package pop3

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

var apopTimestampRE = regexp.MustCompile(`<[^>]+@[^>]+>`)

// ReadGreeting reads the initial POP3 +OK greeting from a buffered reader.
// The caller must supply the persistent reader so no bytes are lost to discard.
func ReadGreeting(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// ParseGreeting extracts the greeting message text from a "+OK ..." line.
func ParseGreeting(line string) string {
	if strings.HasPrefix(line, "+OK ") {
		return strings.TrimSpace(line[4:])
	}
	return line
}

// ExtractApopTimestamp looks for an APOP timestamp token (<...@...>) in the greeting.
func ExtractApopTimestamp(greeting string) (string, bool) {
	match := apopTimestampRE.FindString(greeting)
	if match != "" {
		return match, true
	}
	return "", false
}

// ParseCapabilities parses the multi-line response from a CAPA command.
// Input is the full response body (lines after +OK, before the terminating ".").
func ParseCapabilities(lines []string) (caps []string, authMechanisms []string, implementation string, loginDelay int, expireDays string) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "." {
			break
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "SASL "):
			// "SASL PLAIN LOGIN CRAM-MD5"
			mechs := strings.Fields(line[5:])
			authMechanisms = append(authMechanisms, mechs...)
			caps = append(caps, line)
		case strings.HasPrefix(upper, "IMPLEMENTATION "):
			implementation = strings.TrimSpace(line[15:])
			caps = append(caps, line)
		case strings.HasPrefix(upper, "LOGIN-DELAY "):
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				var d int
				_, _ = fmt.Sscanf(parts[1], "%d", &d)
				loginDelay = d
			}
			caps = append(caps, line)
		case strings.HasPrefix(upper, "EXPIRE "):
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				expireDays = parts[1]
			}
			caps = append(caps, line)
		default:
			caps = append(caps, line)
		}
	}
	return
}
