// Package imap implements IMAP4rev1/IMAP4rev2 mail server enumeration.
package imap

import (
	// Standard
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"

	// Generated
	protocol "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	imapfern "github.com/Method-Security/networkscan/generated/go/enumerate/imap"

	// Internal
	sasl "github.com/Method-Security/networkscan/internal/protocol/sasl"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateIMAP implements NetworkApplicationLibrary for IMAP enumeration.
// Mode A only (pre-auth fingerprinting): greeting, CAPABILITY pre/post STARTTLS,
// advertised SASL mechanisms, TLS cert/cipher. Mode B (auth + folder/message
// enumeration) lives under `internal/pentest/imap/` and `pentest service imap`.
type LibraryEnumerateIMAP struct{}

// EnumerateTarget performs IMAP enumeration against a single target.
//
// Flow:
//  1. Parse target (host:port, default port 143)
//  2. Try plain TCP; on failure try implicit TLS (port 993 or any port with TLS)
//  3. Run CAPABILITY; detect STARTTLS; upgrade if available
//  4. Re-CAPABILITY after TLS upgrade
//  5. Detect IMAP version, extract TLS cert info
func (l *LibraryEnumerateIMAP) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting IMAP enumeration", svc1log.SafeParam("target", target))

	detail := imapfern.EnumerateImapDetails{Target: target}
	serverInfo := &protocol.ImapServerInfo{}
	errors := []string{}

	// Parse target
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		// No port specified — default to 143
		host = target
		portStr = strconv.Itoa(DefaultImapPort)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid port in target '%s': %v", target, err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateImapDetails: &detail}, errors
	}

	// tagCounter tracks the next command tag number
	tagCounter := 2 // A001 used for STARTTLS

	nextTag := func() string {
		tag := fmt.Sprintf("A%03d", tagCounter)
		tagCounter++
		return tag
	}

	var conn net.Conn
	var tlsConn *tls.Conn
	tlsActive := false

	// Step 1: Try plain TCP connection
	log.Debug("Attempting plain TCP connection", svc1log.SafeParam("target", target))
	plainConn, greeting, plainErr := tryTCPConnection(host, port, ctx)
	if plainErr != nil {
		// Step 1b: Try implicit TLS (IMAPS)
		log.Debug("Plain TCP failed, trying implicit TLS", svc1log.SafeParam("error", plainErr))
		tlsC, tlsGreeting, tlsErr := tryTLSConnection(host, port, ctx)
		if tlsErr != nil {
			canConnect := false
			detail.CanConnect = &canConnect
			errors = append(errors, fmt.Sprintf("both TCP and TLS connections failed: TCP=%v TLS=%v", plainErr, tlsErr))
			return &enumeratefern.EnumerateServiceDetails{EnumerateImapDetails: &detail}, errors
		}
		tlsConn = tlsC
		conn = tlsC
		greeting = tlsGreeting
		tlsActive = true
		tlsEnforced := true
		detail.TlsEnforced = &tlsEnforced
		tlsSupported := true
		serverInfo.TlsSupported = &tlsSupported
		log.Debug("Implicit TLS connection established")
	} else {
		conn = plainConn
		// greeting already set by tryTCPConnection above
		log.Debug("Plain TCP connection established")
		tlsEnforced := false
		detail.TlsEnforced = &tlsEnforced
	}

	canConnect := true
	detail.CanConnect = &canConnect

	if greeting != "" {
		serverInfo.Greeting = &greeting
		// Extract server name from greeting if present (e.g. "* OK [CAPABILITY ...] Dovecot ready.")
		if idx := strings.Index(greeting, "* OK"); idx >= 0 {
			rest := strings.TrimSpace(greeting[idx+4:])
			// Skip bracketed section
			if strings.HasPrefix(rest, "[") {
				closeIdx := strings.Index(rest, "]")
				if closeIdx >= 0 {
					rest = strings.TrimSpace(rest[closeIdx+1:])
				}
			}
			if rest != "" {
				serverName := rest
				serverInfo.ServerName = &serverName
			}
		}
	}

	// Step 2: Run CAPABILITY command
	tag := nextTag()
	capLines, capErr := sendCommand(conn, tag, "CAPABILITY", ctx)
	if capErr != nil {
		log.Debug("CAPABILITY command failed", svc1log.SafeParam("error", capErr))
	}

	var capabilities []string
	for _, line := range capLines {
		if strings.HasPrefix(line, "* CAPABILITY") || strings.Contains(line, "[CAPABILITY") {
			caps := parseCapabilities(line)
			if len(caps) > 0 {
				capabilities = caps
			}
		}
	}

	// Step 3: STARTTLS if not already TLS and STARTTLS is advertised
	if !tlsActive {
		starttlsSupported := false
		for _, cap := range capabilities {
			if strings.ToUpper(cap) == "STARTTLS" {
				starttlsSupported = true
				break
			}
		}
		detail.StarttlsSupported = &starttlsSupported

		if starttlsSupported {
			log.Debug("STARTTLS supported, upgrading connection")
			upgraded, stlsErr := doSTARTTLS(conn, host, ctx)
			if stlsErr != nil {
				log.Debug("STARTTLS upgrade failed", svc1log.SafeParam("error", stlsErr))
				errors = append(errors, fmt.Sprintf("STARTTLS upgrade failed: %v", stlsErr))
			} else {
				tlsConn = upgraded
				conn = upgraded
				tlsActive = true
				tlsSupported := true
				serverInfo.TlsSupported = &tlsSupported
				log.Debug("STARTTLS upgrade successful")

				// Re-CAPABILITY after TLS upgrade
				tag = nextTag()
				capLines2, capErr2 := sendCommand(conn, tag, "CAPABILITY", ctx)
				if capErr2 == nil {
					for _, line := range capLines2 {
						if strings.HasPrefix(line, "* CAPABILITY") || strings.Contains(line, "[CAPABILITY") {
							caps := parseCapabilities(line)
							if len(caps) > 0 {
								capabilities = caps
							}
						}
					}
				}
			}
		}
	}

	// Step 4: Populate capabilities and auth mechanisms
	if len(capabilities) > 0 {
		serverInfo.Capabilities = capabilities
	}

	// Detect IMAP version
	imapVersion := ""
	for _, cap := range capabilities {
		upper := strings.ToUpper(cap)
		if upper == "IMAP4REV2" {
			imapVersion = "IMAP4rev2"
			break
		} else if upper == "IMAP4REV1" {
			imapVersion = "IMAP4rev1"
		}
	}
	if imapVersion != "" {
		serverInfo.ImapVersion = &imapVersion
	}

	// Parse AUTH mechanisms from capabilities
	saslMechs := sasl.ParseMechanisms(capabilities)
	var authMechs []protocol.ImapAuthMechanismType
	for _, m := range saslMechs {
		switch m {
		case sasl.MechanismPlain:
			authMechs = append(authMechs, protocol.ImapAuthMechanismTypePlain)
		case sasl.MechanismLogin:
			authMechs = append(authMechs, protocol.ImapAuthMechanismTypeLogin)
		case sasl.MechanismCramMD5:
			authMechs = append(authMechs, protocol.ImapAuthMechanismTypeCramMd5)
		case sasl.MechanismGSSAPI:
			authMechs = append(authMechs, protocol.ImapAuthMechanismTypeGssapi)
		case sasl.MechanismXOAuth2:
			authMechs = append(authMechs, protocol.ImapAuthMechanismTypeXoauth2)
		}
	}
	if len(authMechs) > 0 {
		serverInfo.AuthMechanisms = authMechs
	}

	// Extract TLS info if TLS is active
	if tlsActive && tlsConn != nil {
		subject, cipher := extractTLSInfo(tlsConn)
		if subject != "" {
			serverInfo.TlsCertSubject = &subject
		}
		if cipher != "" {
			serverInfo.TlsCipher = &cipher
		}
	}

	detail.ServerInfo = serverInfo

	// Mode B (authenticated folder/message enumeration) is handled by the
	// pentest IMAP tool (`internal/pentest/imap/`) — see AITF-66. Mode A here
	// stops at pre-auth fingerprinting.
	authenticated := false
	detail.Authenticated = &authenticated

	// Logout
	tag = nextTag()
	_, _ = sendCommand(conn, tag, "LOGOUT", ctx)
	_ = conn.Close()

	log.Info("IMAP enumeration complete", svc1log.SafeParam("target", target))
	return &enumeratefern.EnumerateServiceDetails{EnumerateImapDetails: &detail}, errors
}
