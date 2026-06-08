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

	hostname, _, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target format: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumeratePop3Details: &detail}, errors
	}

	// Try plain TCP first.
	//
	// Important: a successful TCP dial does not mean the listener is speaking
	// plain POP3. Implicit-TLS POP3 servers (port 995 by convention, but any
	// port in practice) accept the TCP connection and then wait for the
	// client's TLS ClientHello — they never send a "+OK ..." greeting in the
	// clear. To distinguish, we peek for the greeting with a short deadline.
	// If nothing readable arrives, or the first byte is not the expected '+'
	// of a POP3 status line, we close and redial with implicit TLS.
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

		if peekErr == nil && len(peek) == 1 && peek[0] == '+' {
			// Clear POP3 greeting incoming — proceed plaintext.
			conn = plainConn
			reader = plainReader
			log.Debug("Plain POP3 greeting detected")
		} else if netErr, ok := peekErr.(net.Error); peekErr != nil && ok && netErr.Timeout() {
			// Peek deadline elapsed before the server sent anything.  The server
			// may simply be slow (e.g. a busy Dovecot instance on a loaded host).
			// A genuine implicit-TLS listener also stays silent while waiting for
			// the client's ClientHello, so we cannot distinguish the two cases on
			// timing alone.  Keeping the TCP connection avoids misrouting a slow
			// cleartext server to TLS; ReadGreeting will apply its own deadline and
			// fail gracefully if the listener is truly waiting for a TLS ClientHello.
			conn = plainConn
			reader = plainReader
			log.Debug("Peek timed out — keeping plain TCP connection; ReadGreeting will determine if POP3")
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
		tlsConn, tlsErr := dialTLS(target, hostname)
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
	preCaps, preMechs, impl, loginDelay, expireDays := runCapa(conn, reader)
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
			postCaps, postMechs, postImpl, _, _ := runCapa(conn, reader)
			if len(postCaps) > 0 {
				serverInfo.PostTlsCapabilities = postCaps
			}
			if postImpl != "" && impl == "" {
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

	quit(conn)
	_ = conn.Close()

	log.Info("POP3 enumeration complete", svc1log.SafeParam("target", target))
	return &enumeratefern.EnumerateServiceDetails{EnumeratePop3Details: &detail}, errors
}
