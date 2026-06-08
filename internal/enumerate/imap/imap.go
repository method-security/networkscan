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
	Config *imapfern.ImapEnumerateConfig
}

// username returns the configured IMAP username (empty if unset).
func (l *LibraryEnumerateIMAP) username() string {
	if l.Config == nil || l.Config.Username == nil {
		return ""
	}
	return *l.Config.Username
}

// password returns the configured IMAP password (empty if unset).
func (l *LibraryEnumerateIMAP) password() string {
	if l.Config == nil || l.Config.Password == nil {
		return ""
	}
	return *l.Config.Password
}

// mechanism returns the configured SASL mechanism override (empty if unset).
func (l *LibraryEnumerateIMAP) mechanism() string {
	if l.Config == nil || l.Config.Mechanism == nil {
		return ""
	}
	return *l.Config.Mechanism
}

// maxMessages returns the configured max-messages cap (0 = none).
func (l *LibraryEnumerateIMAP) maxMessages() int {
	if l.Config == nil || l.Config.MaxMessages == nil {
		return 0
	}
	return *l.Config.MaxMessages
}

// search returns the configured IMAP SEARCH expression (empty if unset).
func (l *LibraryEnumerateIMAP) search() string {
	if l.Config == nil || l.Config.Search == nil {
		return ""
	}
	return *l.Config.Search
}

// targetFolder returns the configured target folder (empty if unset).
func (l *LibraryEnumerateIMAP) targetFolder() string {
	if l.Config == nil || l.Config.TargetFolder == nil {
		return ""
	}
	return *l.Config.TargetFolder
}

// allowPlaintextCredentials returns whether PLAIN/LOGIN auth is permitted
// over an unencrypted transport.
func (l *LibraryEnumerateIMAP) allowPlaintextCredentials() bool {
	if l.Config == nil || l.Config.AllowPlaintextCredentials == nil {
		return false
	}
	return *l.Config.AllowPlaintextCredentials
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

	// Step 5: Authenticated enumeration
	if l.username() != "" {
		authenticated := false
		authErr := l.authenticate(conn, nextTag, saslMechs, tlsActive, ctx)
		if authErr != nil {
			errors = append(errors, fmt.Sprintf("authentication failed: %v", authErr))
			detail.Authenticated = &authenticated
		} else {
			authenticated = true
			detail.Authenticated = &authenticated
			log.Info("IMAP authentication successful", svc1log.SafeParam("username", l.username()))

			// ENABLE IMAP4rev2 if supported
			if imapVersion == "IMAP4rev2" {
				tag = nextTag()
				_, _ = sendCommand(conn, tag, "ENABLE IMAP4rev2 UTF8=ACCEPT", ctx)
			}

			// LIST folders
			tag = nextTag()
			listLines, listErr := sendCommand(conn, tag, `LIST "" "*"`, ctx)
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
						fmt.Sprintf("STATUS %s (MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY)", imapQuoteString(folder.Name)),
						ctx)
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

			// EXAMINE target folder (only if one was specified; the CLI flag
			// defaults to "INBOX" in cmd/enumerate.go — no internal default here).
			if l.targetFolder() != "" {
				tag = nextTag()
				examineLines, examineErr := sendCommand(conn, tag, fmt.Sprintf("EXAMINE %s", imapQuoteString(l.targetFolder())), ctx)
				if examineErr == nil {
					examineResult := parseExamineResponse(l.targetFolder(), examineLines)
					detail.SelectedFolder = examineResult
				}
			}

			// UID FETCH message headers
			if l.maxMessages() > 0 {
				tag = nextTag()
				fetchLines, fetchErr := sendCommand(conn, tag,
					fmt.Sprintf("FETCH 1:%d (UID BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)])", l.maxMessages()),
					ctx)
				if fetchErr == nil {
					msgs := parseMessageHeaders(fetchLines, l.maxMessages())
					if len(msgs) > 0 {
						detail.Messages = msgs
					}
				}
			}

			// UID SEARCH
			if l.search() != "" {
				tag = nextTag()
				searchLines, searchErr := sendCommand(conn, tag, fmt.Sprintf("UID SEARCH %s", stripCRLF(l.search())), ctx)
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
						FolderName:       l.targetFolder(),
						SearchExpression: l.search(),
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
	_, _ = sendCommand(conn, tag, "LOGOUT", ctx)
	_ = conn.Close()

	log.Info("IMAP enumeration complete", svc1log.SafeParam("target", target))
	return &enumeratefern.EnumerateServiceDetails{EnumerateImapDetails: &detail}, errors
}

// authenticate performs SASL authentication against the IMAP server.
// It selects the strongest available mechanism unless overridden by l.mechanism().
func (l *LibraryEnumerateIMAP) authenticate(
	conn net.Conn,
	nextTag func() string,
	available []sasl.Mechanism,
	tlsActive bool,
	ctx context.Context,
) error {
	// Determine mechanism
	var mech sasl.Mechanism
	if l.mechanism() != "" {
		mech = sasl.Mechanism(strings.ToUpper(l.mechanism()))
		// Enforce plaintext credential policy even when mechanism is explicitly set.
		if (mech == sasl.MechanismPlain || mech == sasl.MechanismLogin) && !tlsActive && !l.allowPlaintextCredentials() {
			return fmt.Errorf("refusing %s over unencrypted transport (use --imap-allow-plaintext-credentials or ensure TLS is active)", mech)
		}
	} else {
		// Filter to mechanisms this client implements (PLAIN and LOGIN only).
		var implementedAvailable []sasl.Mechanism
		for _, m := range available {
			if m == sasl.MechanismPlain || m == sasl.MechanismLogin {
				implementedAvailable = append(implementedAvailable, m)
			}
		}
		selected, ok := sasl.SelectStrongest(implementedAvailable, l.allowPlaintextCredentials() || tlsActive)
		if !ok {
			// No strong mechanism; fall back to LOGIN if TLS is active or plaintext allowed
			if tlsActive || l.allowPlaintextCredentials() {
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
		return l.authPlain(conn, nextTag, ctx)
	case sasl.MechanismLogin:
		return l.authLogin(conn, nextTag, ctx)
	default:
		return fmt.Errorf("SASL mechanism %q is not implemented; supported: PLAIN, LOGIN", mech)
	}
}

// authPlain performs AUTHENTICATE PLAIN.
// The encoded value is base64(\0username\0password).
func (l *LibraryEnumerateIMAP) authPlain(conn net.Conn, nextTag func() string, ctx context.Context) error {
	_ = conn.SetDeadline(deadlineFromContext(ctx))
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
	creds := "\x00" + l.username() + "\x00" + l.password()
	encoded := base64.StdEncoding.EncodeToString([]byte(creds))
	if err := tconn.PrintfLine("%s", encoded); err != nil {
		return fmt.Errorf("PLAIN credentials send failed: %w", err)
	}
	// Read until tagged completion. Servers may emit untagged data lines
	// (e.g. "* CAPABILITY ...") between the continuation and the final tag,
	// per RFC 3501 § 7.
	for {
		resp, err := tconn.ReadLine()
		if err != nil {
			return fmt.Errorf("PLAIN auth response read failed: %w", err)
		}
		if strings.HasPrefix(resp, tag+" OK") {
			return nil
		}
		if strings.HasPrefix(resp, tag+" NO") || strings.HasPrefix(resp, tag+" BAD") {
			return fmt.Errorf("PLAIN auth failed: %s", resp)
		}
		// Untagged line (e.g. "* CAPABILITY ..."); keep reading.
	}
}

// authLogin performs LOGIN username password (plain-text login command).
func (l *LibraryEnumerateIMAP) authLogin(conn net.Conn, nextTag func() string, ctx context.Context) error {
	tag := nextTag()
	lines, err := sendCommand(conn, tag,
		fmt.Sprintf("LOGIN %s %s", imapQuoteString(l.username()), imapQuoteString(l.password())),
		ctx)
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
