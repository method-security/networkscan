package imap

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"strings"

	sasl "github.com/Method-Security/networkscan/internal/protocol/sasl"
	"github.com/Method-Security/networkscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// Session is a connected, capability-detected IMAP control channel that the
// per-action helpers reuse for AUTH / LIST_FOLDERS / FETCH_HEADERS / SEARCH.
type Session struct {
	Conn         net.Conn
	Host         string
	TLSActive    bool
	Capabilities []string
	SASLMechs    []sasl.Mechanism
	tagCounter   int
}

// NextTag returns the next IMAP command tag (A001, A002, ...) and increments
// the session's internal counter.
func (s *Session) NextTag() string {
	s.tagCounter++
	return fmt.Sprintf("A%03d", s.tagCounter)
}

// Close issues IMAP LOGOUT and closes the underlying connection. Safe to call
// on nil or a session with no connection.
func (s *Session) Close(ctx context.Context) {
	if s == nil || s.Conn == nil {
		return
	}
	_, _ = SendCommand(ctx, s.Conn, s.NextTag(), "LOGOUT")
	_ = s.Conn.Close()
}

// NewSession dials target, optionally upgrades via STARTTLS, and runs
// CAPABILITY so the caller can use s.SASLMechs / s.TLSActive to choose an
// auth mechanism safely.
func NewSession(ctx context.Context, target string) (*Session, error) {
	log := svc1log.FromContext(ctx)
	host, port := utils.ParseHostPort(target, DefaultImapPort)

	s := &Session{
		Host:       host,
		tagCounter: 1, // STARTTLS uses A001
	}

	plainConn, _, err := TryTCPConnection(ctx, host, port)
	if err != nil {
		log.Debug("Plain TCP failed, trying implicit TLS",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("error", err.Error()))
		tlsC, _, tlsErr := TryTLSConnection(ctx, host, port)
		if tlsErr != nil {
			return nil, fmt.Errorf("both TCP and TLS connections failed: TCP=%v TLS=%v", err, tlsErr)
		}
		s.Conn = tlsC
		s.TLSActive = true
	} else {
		s.Conn = plainConn
	}

	// Initial CAPABILITY
	tag := s.NextTag()
	if capLines, capErr := SendCommand(ctx, s.Conn, tag, "CAPABILITY"); capErr == nil {
		s.Capabilities = extractCapabilities(capLines)
	}

	// STARTTLS upgrade if available and not yet TLS
	if !s.TLSActive && hasCapability(s.Capabilities, "STARTTLS") {
		upgraded, stlsErr := DoSTARTTLS(ctx, s.Conn, host)
		if stlsErr != nil {
			// Server accepted STARTTLS but the TLS handshake failed — the
			// underlying TCP socket is now in an undefined state (cleartext
			// IMAP commands would race against the server expecting TLS).
			// Close it and surface the error so the caller doesn't send
			// further traffic on a corrupted channel.
			log.Debug("STARTTLS upgrade failed; closing session", svc1log.SafeParam("error", stlsErr.Error()))
			_ = s.Conn.Close()
			return nil, fmt.Errorf("STARTTLS upgrade failed: %w", stlsErr)
		}
		s.Conn = upgraded
		s.TLSActive = true
		// Re-CAPABILITY after TLS upgrade — servers commonly advertise
		// extra AUTH mechanisms only on encrypted transports.
		tag = s.NextTag()
		if capLines, capErr := SendCommand(ctx, s.Conn, tag, "CAPABILITY"); capErr == nil {
			s.Capabilities = extractCapabilities(capLines)
		}
	}

	s.SASLMechs = sasl.ParseMechanisms(s.Capabilities)
	return s, nil
}

func extractCapabilities(lines []string) []string {
	var caps []string
	for _, line := range lines {
		if strings.HasPrefix(line, "* CAPABILITY") || strings.Contains(line, "[CAPABILITY") {
			if parsed := ParseCapabilities(line); len(parsed) > 0 {
				caps = parsed
			}
		}
	}
	return caps
}

func hasCapability(caps []string, target string) bool {
	for _, c := range caps {
		if strings.EqualFold(c, target) {
			return true
		}
	}
	return false
}

// Authenticate runs SASL authentication using the session's negotiated
// mechanisms. It honors mechanismOverride, the plaintext policy, and returns
// the mechanism actually used so the caller can surface it in AuthResult.
func (s *Session) Authenticate(ctx context.Context, username, password, mechanismOverride string, allowPlaintext bool) (sasl.Mechanism, error) {
	mech, err := s.selectMechanism(mechanismOverride, allowPlaintext)
	if err != nil {
		return "", err
	}

	switch mech {
	case sasl.MechanismPlain:
		return mech, s.authPlain(ctx, username, password)
	case sasl.MechanismLogin:
		return mech, s.authLogin(ctx, username, password)
	default:
		return mech, fmt.Errorf("SASL mechanism %q is not implemented; supported: PLAIN, LOGIN", mech)
	}
}

func (s *Session) selectMechanism(override string, allowPlaintext bool) (sasl.Mechanism, error) {
	if override != "" && !strings.EqualFold(override, "auto") {
		mech := sasl.Mechanism(strings.ToUpper(override))
		if (mech == sasl.MechanismPlain || mech == sasl.MechanismLogin) && !s.TLSActive && !allowPlaintext {
			return "", fmt.Errorf("refusing %s over unencrypted transport (use --allow-plaintext-credentials or ensure TLS is active)", mech)
		}
		return mech, nil
	}

	// Filter advertised mechanisms to ones this client implements.
	var implemented []sasl.Mechanism
	for _, m := range s.SASLMechs {
		if m == sasl.MechanismPlain || m == sasl.MechanismLogin {
			implemented = append(implemented, m)
		}
	}
	selected, ok := sasl.SelectStrongest(implemented, allowPlaintext || s.TLSActive)
	if ok {
		return selected, nil
	}
	if s.TLSActive || allowPlaintext {
		return sasl.MechanismLogin, nil
	}
	return "", fmt.Errorf("no supported SASL mechanism available (use --allow-plaintext-credentials or ensure TLS is active)")
}

// authPlain performs AUTHENTICATE PLAIN. The encoded value is
// base64(\0username\0password) per RFC 4616.
func (s *Session) authPlain(ctx context.Context, username, password string) error {
	_ = s.Conn.SetDeadline(DeadlineFromContext(ctx))
	tconn := textproto.NewConn(s.Conn)

	tag := s.NextTag()
	if err := tconn.PrintfLine("%s AUTHENTICATE PLAIN", tag); err != nil {
		return fmt.Errorf("AUTHENTICATE PLAIN send failed: %w", err)
	}
	challenge, err := tconn.ReadLine()
	if err != nil {
		return fmt.Errorf("challenge read failed: %w", err)
	}
	if !strings.HasPrefix(challenge, "+") {
		return fmt.Errorf("unexpected AUTHENTICATE response: %s", challenge)
	}
	creds := "\x00" + username + "\x00" + password
	encoded := base64.StdEncoding.EncodeToString([]byte(creds))
	if err := tconn.PrintfLine("%s", encoded); err != nil {
		return fmt.Errorf("PLAIN credentials send failed: %w", err)
	}
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
		// Untagged response (e.g. "* CAPABILITY ..."); keep reading.
	}
}

// authLogin performs the LOGIN <username> <password> command (plaintext).
func (s *Session) authLogin(ctx context.Context, username, password string) error {
	tag := s.NextTag()
	lines, err := SendCommand(ctx, s.Conn, tag,
		fmt.Sprintf("LOGIN %s %s", ImapQuoteString(username), ImapQuoteString(password)))
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
