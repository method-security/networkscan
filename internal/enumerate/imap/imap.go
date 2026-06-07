// Package imap implements IMAP4rev1/IMAP4rev2 mail server enumeration.
package imap

import (
	// Standard
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

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
type LibraryEnumerateIMAP struct {
	Username                  string
	Password                  string
	Mechanism                 string
	MaxMessages               int
	Search                    string
	TargetFolder              string
	AllowDestructive          bool
	AllowPlaintextCredentials bool
}

// EnumerateTarget performs IMAP enumeration against a single target.
//
// Flow:
//  1. Parse target (host:port, default port 143)
//  2. Try plain TCP; on failure try implicit TLS (port 993 or any port with TLS)
//  3. Run CAPABILITY; detect STARTTLS; upgrade if available
//  4. Re-CAPABILITY after TLS upgrade
//  5. Detect IMAP version, extract TLS cert info
//  6. If Username set: authenticate and enumerate folders, statuses, messages
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

	timeout := 30
	if deadline, ok := ctx.Deadline(); ok {
		remaining := int(time.Until(deadline).Seconds())
		if remaining > 0 && remaining < timeout {
			timeout = remaining
		}
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
	plainConn, greeting, plainErr := tryTCPConnection(host, port, timeout)
	if plainErr != nil {
		// Step 1b: Try implicit TLS (IMAPS)
		log.Debug("Plain TCP failed, trying implicit TLS", svc1log.SafeParam("error", plainErr))
		tlsC, tlsGreeting, tlsErr := tryTLSConnection(host, port, timeout)
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
	capLines, capErr := sendCommand(conn, tag, "CAPABILITY", timeout)
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
			upgraded, stlsErr := doSTARTTLS(conn, host, timeout)
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
				capLines2, capErr2 := sendCommand(conn, tag, "CAPABILITY", timeout)
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

	// Step 5: Authenticated enumeration
	if l.Username != "" {
		authenticated := false
		authErr := l.authenticate(conn, nextTag, saslMechs, tlsActive, timeout)
		if authErr != nil {
			errors = append(errors, fmt.Sprintf("authentication failed: %v", authErr))
			detail.Authenticated = &authenticated
		} else {
			authenticated = true
			detail.Authenticated = &authenticated
			log.Info("IMAP authentication successful", svc1log.SafeParam("username", l.Username))

			// ENABLE IMAP4rev2 if supported
			if imapVersion == "IMAP4rev2" {
				tag = nextTag()
				_, _ = sendCommand(conn, tag, "ENABLE IMAP4rev2 UTF8=ACCEPT", timeout)
			}

			// LIST folders
			tag = nextTag()
			listLines, listErr := sendCommand(conn, tag, `LIST "" "*"`, timeout)
			if listErr == nil {
				folders := parseFolders(listLines)
				if len(folders) > 0 {
					detail.Folders = folders
				}

				// STATUS for each folder
				var statuses []*imapfern.ImapFolderStatus
				for _, folder := range folders {
					tag = nextTag()
					statusLines, statusErr := sendCommand(conn, tag,
						fmt.Sprintf(`STATUS "%s" (MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY)`, folder.Name),
						timeout)
					if statusErr != nil {
						continue
					}
					for _, line := range statusLines {
						if s := parseFolderStatus(line); s != nil {
							statuses = append(statuses, s)
						}
					}
				}
				if len(statuses) > 0 {
					detail.FolderStatuses = statuses
				}
			}

			// EXAMINE target folder
			targetFolder := l.TargetFolder
			if targetFolder == "" {
				targetFolder = "INBOX"
			}
			tag = nextTag()
			examineLines, examineErr := sendCommand(conn, tag, fmt.Sprintf(`EXAMINE "%s"`, targetFolder), timeout)
			if examineErr == nil {
				examineResult := parseExamineResponse(targetFolder, examineLines)
				detail.SelectedFolder = examineResult
			}

			// UID FETCH message headers
			if l.MaxMessages > 0 {
				tag = nextTag()
				fetchLines, fetchErr := sendCommand(conn, tag,
					`UID FETCH 1:* (BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)])`,
					timeout)
				if fetchErr == nil {
					msgs := parseMessageHeaders(fetchLines, l.MaxMessages)
					if len(msgs) > 0 {
						detail.Messages = msgs
					}
				}
			}

			// UID SEARCH
			if l.Search != "" {
				tag = nextTag()
				searchLines, searchErr := sendCommand(conn, tag, fmt.Sprintf("UID SEARCH %s", l.Search), timeout)
				if searchErr == nil {
					var uids []int
					for _, line := range searchLines {
						if strings.HasPrefix(line, "* SEARCH") {
							fields := strings.Fields(line)
							for _, f := range fields[2:] {
								if uid, err := strconv.Atoi(f); err == nil {
									uids = append(uids, uid)
								}
							}
						}
					}
					detail.SearchResult = &imapfern.ImapSearchResult{
						FolderName:       targetFolder,
						SearchExpression: l.Search,
						MatchingUids:     uids,
					}
				}
			}
		}
	} else {
		authenticated := false
		detail.Authenticated = &authenticated
	}

	// Logout
	tag = nextTag()
	_, _ = sendCommand(conn, tag, "LOGOUT", timeout)
	_ = conn.Close()

	log.Info("IMAP enumeration complete", svc1log.SafeParam("target", target))
	return &enumeratefern.EnumerateServiceDetails{EnumerateImapDetails: &detail}, errors
}

// authenticate performs SASL authentication against the IMAP server.
// It selects the strongest available mechanism unless overridden by l.Mechanism.
func (l *LibraryEnumerateIMAP) authenticate(
	conn net.Conn,
	nextTag func() string,
	available []sasl.Mechanism,
	tlsActive bool,
	timeout int,
) error {
	// Determine mechanism
	var mech sasl.Mechanism
	if l.Mechanism != "" {
		mech = sasl.Mechanism(strings.ToUpper(l.Mechanism))
	} else {
		selected, ok := sasl.SelectStrongest(available, l.AllowPlaintextCredentials || tlsActive)
		if !ok {
			// No strong mechanism; fall back to LOGIN if TLS is active or plaintext allowed
			if tlsActive || l.AllowPlaintextCredentials {
				mech = sasl.MechanismLogin
			} else {
				return fmt.Errorf("no supported SASL mechanism available (use --imap-allow-plaintext-credentials or ensure TLS is active)")
			}
		} else {
			mech = selected
		}
	}

	switch mech {
	case sasl.MechanismPlain:
		return l.authPlain(conn, nextTag, timeout)
	case sasl.MechanismLogin:
		return l.authLogin(conn, nextTag, timeout)
	default:
		// For unsupported complex mechanisms, try LOGIN as fallback
		return l.authLogin(conn, nextTag, timeout)
	}
}

// authPlain performs AUTHENTICATE PLAIN.
// The encoded value is base64(\0username\0password).
func (l *LibraryEnumerateIMAP) authPlain(conn net.Conn, nextTag func() string, timeout int) error {
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	tconn := textproto.NewConn(conn)

	tag := nextTag()
	if err := tconn.PrintfLine("%s AUTHENTICATE PLAIN", tag); err != nil {
		return fmt.Errorf("AUTHENTICATE PLAIN send failed: %w", err)
	}
	// Read continuation challenge ("+")
	challenge, err := tconn.ReadLine()
	if err != nil {
		return fmt.Errorf("challenge read failed: %w", err)
	}
	if !strings.HasPrefix(challenge, "+") {
		return fmt.Errorf("unexpected AUTHENTICATE response: %s", challenge)
	}
	// Send credentials
	creds := "\x00" + l.Username + "\x00" + l.Password
	encoded := base64.StdEncoding.EncodeToString([]byte(creds))
	if err := tconn.PrintfLine("%s", encoded); err != nil {
		return fmt.Errorf("PLAIN credentials send failed: %w", err)
	}
	// Read final response
	resp, err := tconn.ReadLine()
	if err != nil {
		return fmt.Errorf("PLAIN auth response read failed: %w", err)
	}
	if !strings.Contains(resp, tag+" OK") {
		return fmt.Errorf("PLAIN auth failed: %s", resp)
	}
	return nil
}

// authLogin performs LOGIN username password (plain-text login command).
func (l *LibraryEnumerateIMAP) authLogin(conn net.Conn, nextTag func() string, timeout int) error {
	tag := nextTag()
	lines, err := sendCommand(conn, tag,
		fmt.Sprintf("LOGIN %s %s", l.Username, l.Password),
		timeout)
	if err != nil {
		return fmt.Errorf("LOGIN command failed: %w", err)
	}
	for _, line := range lines {
		if strings.HasPrefix(line, tag+" OK") {
			return nil
		}
		if strings.HasPrefix(line, tag+" NO") || strings.HasPrefix(line, tag+" BAD") {
			return fmt.Errorf("LOGIN failed: %s", line)
		}
	}
	return fmt.Errorf("LOGIN: no OK response received")
}
