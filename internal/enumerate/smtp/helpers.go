package smtp

import (
	// Standard
	"context"
	"crypto/tls"
	"fmt"
	"net"
	netsmtp "net/smtp"
	"strings"

	// Generated
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	smtp "github.com/Method-Security/networkscan/generated/go/enumerate/smtp"
	"github.com/Method-Security/networkscan/internal/netdial"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func tryTCPConnection(ctx context.Context, target string) (net.Conn, error) {
	return netdial.DialContext(ctx, "tcp", target)
}

func tryTLSConnection(ctx context.Context, target string, hostname string) (net.Conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	}
	conn, err := netdial.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func parseAuthMethods(methods []string) []protocol.SmtpAuthCommand {
	var result []protocol.SmtpAuthCommand
	for _, method := range methods {
		if auth, ok := authCommands[strings.ToUpper(method)]; ok {
			result = append(result, auth)
		}
	}
	return result
}

// collectExtensions checks for common SMTP extensions via the client's Extension method.
func collectExtensions(c *netsmtp.Client) []string {
	knownExtensions := []string{
		"8BITMIME", "AUTH", "BINARYMIME", "CHUNKING", "DSN",
		"ENHANCEDSTATUSCODES", "ETRN", "EXPN", "PIPELINING", "SIZE",
		"STARTTLS", "TURN", "VRFY",
	}
	var found []string
	for _, ext := range knownExtensions {
		if ok, param := c.Extension(ext); ok {
			if param != "" {
				found = append(found, ext+" "+param)
			} else {
				found = append(found, ext)
			}
		}
	}
	return found
}

// enumerateUsers probes for valid users using VRFY, EXPN, and RCPT TO methods.
// It tries VRFY first if supported, then EXPN, then falls back to RCPT TO.
func enumerateUsers(ctx context.Context, c *netsmtp.Client, hostname string, extensions []string, usernames []string) []*smtp.SmtpEnumeratedUser {
	log := svc1log.FromContext(ctx)
	var results []*smtp.SmtpEnumeratedUser

	vrfySupported := extensionSupported(extensions, "VRFY")
	expnSupported := extensionSupported(extensions, "EXPN")

	// Try VRFY if supported
	if vrfySupported {
		log.Info("VRFY supported, enumerating users via VRFY")
		for _, username := range usernames {
			exists, response := probeVRFY(c, username)
			results = append(results, &smtp.SmtpEnumeratedUser{
				Username: username,
				Exists:   exists,
				Method:   smtp.SmtpUserEnumerationMethodVrfy,
				Response: &response,
			})
		}
	}

	// Try EXPN if supported (for mailing list expansion)
	if expnSupported {
		log.Info("EXPN supported, probing via EXPN")
		for _, username := range usernames {
			exists, response := probeEXPN(c, username)
			results = append(results, &smtp.SmtpEnumeratedUser{
				Username: username,
				Exists:   exists,
				Method:   smtp.SmtpUserEnumerationMethodExpn,
				Response: &response,
			})
		}
	}

	// Fall back to RCPT TO probing if VRFY is not supported
	if !vrfySupported {
		log.Info("VRFY not supported, falling back to RCPT TO enumeration")
		for _, username := range usernames {
			exists, response := probeRCPTTO(c, username, hostname)
			results = append(results, &smtp.SmtpEnumeratedUser{
				Username: username,
				Exists:   exists,
				Method:   smtp.SmtpUserEnumerationMethodRcptTo,
				Response: &response,
			})
		}
	}

	return results
}

// extensionSupported checks if a given extension name is in the collected extensions list.
func extensionSupported(extensions []string, name string) bool {
	for _, ext := range extensions {
		if strings.HasPrefix(ext, name) {
			return true
		}
	}
	return false
}

// probeVRFY sends a VRFY command for the given username and interprets the response.
// 250/251 = user exists, 252 = cannot verify but will attempt delivery, 550/551/553 = does not exist.
func probeVRFY(c *netsmtp.Client, username string) (bool, string) {
	id, err := c.Text.Cmd("VRFY %s", username)
	if err != nil {
		return false, fmt.Sprintf("error: %v", err)
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	code, msg, err := c.Text.ReadResponse(-1)
	if err != nil {
		return false, fmt.Sprintf("%d %s", code, msg)
	}
	response := fmt.Sprintf("%d %s", code, msg)
	// 250 = exact match, 251 = will forward
	return code == 250 || code == 251, response
}

// probeEXPN sends an EXPN command for the given mailing list name.
// 250 = list exists and members returned (possibly multi-line), 550 = list does not exist.
func probeEXPN(c *netsmtp.Client, listName string) (bool, string) {
	id, err := c.Text.Cmd("EXPN %s", listName)
	if err != nil {
		return false, fmt.Sprintf("error: %v", err)
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	// Use ReadResponse to properly drain multi-line 250 responses (one member per line)
	code, msg, err := c.Text.ReadResponse(-1)
	if err != nil {
		return false, fmt.Sprintf("%d %s", code, msg)
	}
	response := fmt.Sprintf("%d %s", code, msg)
	return code == 250, response
}

// probeRCPTTO uses MAIL FROM + RCPT TO to check if a user exists.
// 250 = accepted, 550/551/553 = rejected. Resets the session after each probe.
func probeRCPTTO(c *netsmtp.Client, username string, hostname string) (bool, string) {
	email := fmt.Sprintf("%s@%s", username, hostname)

	err := c.Mail(fmt.Sprintf("probe@%s", hostname))
	if err != nil {
		_ = c.Reset()
		return false, fmt.Sprintf("MAIL FROM error: %v", err)
	}

	err = c.Rcpt(email)
	response := ""
	exists := false
	if err != nil {
		response = err.Error()
	} else {
		exists = true
		response = "250 OK"
	}

	_ = c.Reset()
	return exists, response
}

func testUnauthenticatedEmail(ctx context.Context, c *netsmtp.Client, hostname string) bool {
	// Initialize
	log := svc1log.FromContext(ctx)

	// Form proper email addresses
	testEmail := fmt.Sprintf("test@%s", hostname)

	// Try to send an email without authentication
	err := c.Mail(testEmail)
	if err != nil {
		log.Debug("Mail From command failed", svc1log.SafeParam("error", err))
		return false
	}

	err = c.Rcpt(testEmail)
	if err != nil {
		log.Debug("Rcpt To command failed", svc1log.SafeParam("error", err))
		return false
	}

	// Reset the session
	err = c.Reset()
	if err != nil {
		log.Debug("Failed to reset SMTP client", svc1log.SafeParam("error", err))
	}

	return true
}
