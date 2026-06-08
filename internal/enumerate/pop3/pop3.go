// Package pop3 implements POP3 (RFC 1939) service enumeration.
package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	protocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	pop3fern "github.com/Method-Security/networkscan/generated/go/enumerate/pop3"
	pop3util "github.com/Method-Security/networkscan/internal/protocol/pop3"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// implicitTLSPeekTimeout caps how long we wait for a POP3 server to deliver
// its "+OK" greeting before concluding the listener actually wants TLS.
const implicitTLSPeekTimeout = 2 * time.Second

// pop3sPort is the IANA-assigned port for POP3 over implicit TLS (RFC 8314).
// On this port we treat a peek-timeout as a strong signal of implicit TLS
// rather than as a slow plain-text server.
const pop3sPort = "995"

// LibraryEnumeratePOP3 implements NetworkApplicationLibrary for POP3 enumeration.
type LibraryEnumeratePOP3 struct{}

// EnumerateTarget connects to a POP3 server and collects banner, CAPA, and TLS information.
// Mode A (unauthenticated): probes the server without credentials.
// It tries plain TCP first; if that fails it tries implicit TLS (port 995 style).
// If plain TCP succeeds, it also attempts STLS upgrade.
//
// A single bufio.Reader is created once per connection and threaded through every
// read helper.  This prevents bytes buffered in a discarded reader from being
// silently lost between calls — a particular risk during the STLS upgrade where
// read-ahead bytes could otherwise corrupt the TLS handshake.
func (p *LibraryEnumeratePOP3) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting POP3 enumeration", svc1log.SafeParam("target", target))

	detail := pop3fern.EnumeratePop3Details{Target: target}
	serverInfo := &protocolfern.Pop3ServerInfo{}
	errors := []string{}

	hostname, portStr, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target format: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumeratePop3Details: &detail}, errors
	}

	// Try plain TCP first.
	//
	// Important: a successful TCP dial does not mean the listener is speaking
	// plain POP3. Implicit-TLS POP3 servers (port 995 by convention, but any
	// port in practice) accept the TCP connection and then wait for the
	// client's TLS ClientHello — they never send a POP3 greeting in the
	// clear. To distinguish, we peek for the greeting with a short deadline.
	// POP3 status lines start with '+' ("+OK ...") or '-' ("-ERR ...", which
	// is a legitimate refusal banner per RFC 1939 § 3 — e.g. "-ERR server
	// busy"). If nothing readable arrives, or the first byte is neither,
	// we close and redial with implicit TLS.
	var conn net.Conn
	var reader *bufio.Reader
	var implicitTLS bool

	log.Debug("Attempting plain TCP to POP3 target", svc1log.SafeParam("target", target))
	plainConn, plainErr := dialTCP(ctx, target)
	if plainErr == nil {
		_ = plainConn.SetReadDeadline(time.Now().Add(implicitTLSPeekTimeout))
		plainReader := bufio.NewReader(plainConn)
		peek, peekErr := plainReader.Peek(1)
		_ = plainConn.SetReadDeadline(time.Time{})

		if peekErr == nil && len(peek) == 1 && (peek[0] == '+' || peek[0] == '-') {
			// Clear POP3 status line incoming (+OK or -ERR) — proceed plaintext.
			conn = plainConn
			reader = plainReader
			log.Debug("Plain POP3 greeting detected", svc1log.SafeParam("status", string(peek)))
		} else if netErr, ok := peekErr.(net.Error); peekErr != nil && ok && netErr.Timeout() {
			// Peek deadline elapsed before the server sent anything.  Two cases
			// look identical on timing alone: a slow plain-text server, or a
			// silent implicit-TLS listener waiting for the client's ClientHello.
			// Use the port number to disambiguate — :995 is the IANA-assigned
			// POP3S port, so a silent listener there is almost certainly TLS.
			// On other ports, assume a slow plain server and keep the
			// connection (ReadGreeting will apply its own deadline downstream).
			if portStr == pop3sPort {
				log.Debug("Peek timed out on :995 — assuming implicit TLS")
				_ = plainConn.Close()
			} else {
				conn = plainConn
				reader = plainReader
				log.Debug("Peek timed out — keeping plain TCP connection; ReadGreeting will determine if POP3")
			}
		} else {
			// Either the first byte arrived and is not '+' (e.g. a TLS ClientHello
			// response fragment), or there was a hard connection error.  Fall back
			// to implicit TLS.
			log.Debug("Non-POP3 first byte or connection error — assuming implicit TLS",
				svc1log.SafeParam("peekErr", fmt.Sprintf("%v", peekErr)))
			_ = plainConn.Close()
		}
	}

	if conn == nil {
		log.Debug("Dialing implicit TLS", svc1log.SafeParam("target", target))
		tlsConn, tlsErr := dialTLS(ctx, target, hostname)
		if tlsErr != nil {
			canConnect := false
			detail.CanConnect = &canConnect
			if plainErr != nil {
				errors = append(errors, fmt.Sprintf("connection failed (TCP=%v TLS=%v)", plainErr, tlsErr))
			} else {
				errors = append(errors, fmt.Sprintf("implicit TLS dial failed: %v", tlsErr))
			}
			return &enumeratefern.EnumerateServiceDetails{EnumeratePop3Details: &detail}, errors
		}
		conn = tlsConn
		reader = bufio.NewReader(conn)
		implicitTLS = true
		tlsSupported := true
		serverInfo.TlsSupported = &tlsSupported
		log.Debug("Implicit TLS connection succeeded")
	}

	canConnect := true
	detail.CanConnect = &canConnect
	detail.ImplicitTls = &implicitTLS

	// Apply the caller's deadline to every subsequent read/write on this
	// connection. Without this, ReadGreeting/CAPA/STLS only respect the OS
	// TCP timeout and can keep running after the engine has already reported
	// the target as deadline-exceeded. Use the context's deadline if set;
	// otherwise leave the deadline open and let socket-level timeouts apply.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Read greeting
	greeting, err := pop3util.ReadGreeting(reader)
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to read greeting: %v", err))
		_ = conn.Close()
		return &enumeratefern.EnumerateServiceDetails{EnumeratePop3Details: &detail}, errors
	}
	log.Info("POP3 greeting received", svc1log.SafeParam("greeting", greeting))
	serverInfo.Banner = &greeting

	greetingText := pop3util.ParseGreeting(greeting)
	serverInfo.Greeting = &greetingText

	// Check for APOP challenge in greeting
	if ts, ok := pop3util.ExtractApopTimestamp(greeting); ok {
		apopSupported := true
		serverInfo.ApopSupported = &apopSupported
		serverInfo.ApopTimestamp = &ts
	}

	// Run CAPA before STLS
	preCaps, preMechs, impl, loginDelay, expireDays, capaErr := runCapa(conn, reader)
	if capaErr != nil {
		// CAPA not supported (RFC 2449) or server returned -ERR.
		// Log and surface in errors so the caller can distinguish "zero
		// capabilities" from "server doesn't speak CAPA at all".
		log.Debug("CAPA not supported or failed", svc1log.SafeParam("error", capaErr))
		errors = append(errors, fmt.Sprintf("CAPA not supported: %v", capaErr))
	}
	if len(preCaps) > 0 {
		serverInfo.Capabilities = preCaps
	}
	if impl != "" {
		serverInfo.Implementation = &impl
	}
	if loginDelay > 0 {
		serverInfo.LoginDelay = &loginDelay
	}
	if expireDays != "" {
		serverInfo.ExpireDays = &expireDays
	}

	// Check if STLS is supported and attempt upgrade (only on plain TCP)
	stlsSupported := false
	for _, cap := range preCaps {
		if strings.ToUpper(strings.TrimSpace(cap)) == "STLS" {
			stlsSupported = true
			break
		}
	}

	if !implicitTLS && stlsSupported {
		log.Debug("STLS supported, attempting upgrade")
		// upgradeToTLS calls sendCommand via the shared reader and then resets
		// the reader to drain from the new TLS layer — no bytes are lost.
		tlsConn, err := upgradeToTLS(conn, reader, hostname)
		if err != nil {
			log.Debug("STLS upgrade failed", svc1log.SafeParam("error", err))
			errors = append(errors, fmt.Sprintf("STLS upgrade failed: %v", err))
			// Close the TCP connection in all failure sub-cases:
			//   - -ERR rejection: conn is still open (upgradeToTLS didn't close it)
			//   - I/O error on STLS command: conn may be in an unknown state
			//   - TLS handshake failure: upgradeToTLS already closed it; Close() is a no-op
			// In all cases skip the cleartext QUIT — the server may be in TLS mode.
			_ = conn.Close()
			conn = nil
		} else {
			log.Debug("STLS upgrade successful")
			tlsSupported := true
			serverInfo.TlsSupported = &tlsSupported

			cipher, version := extractTLSInfo(tlsConn)
			serverInfo.TlsCipher = &cipher
			serverInfo.TlsVersion = &version

			conn = tlsConn

			// Run CAPA again post-STLS to get updated capabilities.
			// reader was already reset to tlsConn inside upgradeToTLS.
			postCaps, postMechs, postImpl, _, _, _ := runCapa(conn, reader)
			if len(postCaps) > 0 {
				serverInfo.PostTlsCapabilities = postCaps
			}
			if postImpl != "" {
				// Post-TLS IMPLEMENTATION takes precedence: RFC 2449 §6.5
				// notes that servers may change capabilities after STLS,
				// and it is common for servers to reveal their true identity
				// only after the encrypted channel is established.
				serverInfo.Implementation = &postImpl
			}
			// Prefer post-TLS mechanisms for SASL
			if len(postMechs) > 0 {
				preMechs = postMechs
			}
		}
	} else if implicitTLS {
		// Get TLS info from the implicit TLS connection
		if tlsConn, ok := conn.(*tls.Conn); ok {
			cipher, version := extractTLSInfo(tlsConn)
			serverInfo.TlsCipher = &cipher
			serverInfo.TlsVersion = &version
		}
	}

	// Parse SASL mechanisms
	if len(preMechs) > 0 {
		serverInfo.AuthMechanisms = parseSaslMechanisms(preMechs)
	}

	detail.ServerInfo = serverInfo

	// conn is nil when STLS upgrade failed (upgradeToTLS already closed it).
	if conn != nil {
		quit(conn)
		_ = conn.Close()
	}

	log.Info("POP3 enumeration complete", svc1log.SafeParam("target", target))
	return &enumeratefern.EnumerateServiceDetails{EnumeratePop3Details: &detail}, errors
}
