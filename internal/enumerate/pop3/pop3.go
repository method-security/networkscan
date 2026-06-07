// Package pop3 implements POP3 (RFC 1939) service enumeration.
package pop3

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	protocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	pop3fern "github.com/Method-Security/networkscan/generated/go/enumerate/pop3"
	pop3util "github.com/Method-Security/networkscan/internal/protocol/pop3"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumeratePOP3 implements NetworkApplicationLibrary for POP3 enumeration.
type LibraryEnumeratePOP3 struct{}

// EnumerateTarget connects to a POP3 server and collects banner, CAPA, and TLS information.
// Mode A (unauthenticated): probes the server without credentials.
// It tries plain TCP first; if that fails it tries implicit TLS (port 995 style).
// If plain TCP succeeds, it also attempts STLS upgrade.
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

	// Try plain TCP first
	var conn net.Conn
	var implicitTLS bool

	log.Debug("Attempting plain TCP to POP3 target", svc1log.SafeParam("target", target))
	conn, err = dialTCP(ctx, target)
	if err != nil {
		log.Debug("Plain TCP failed, trying implicit TLS", svc1log.SafeParam("error", err))
		conn, err = dialTLS(target, hostname)
		if err != nil {
			canConnect := false
			detail.CanConnect = &canConnect
			errors = append(errors, fmt.Sprintf("connection failed (TCP and TLS): %v", err))
			return &enumeratefern.EnumerateServiceDetails{EnumeratePop3Details: &detail}, errors
		}
		implicitTLS = true
		tlsSupported := true
		serverInfo.TlsSupported = &tlsSupported
		log.Debug("Implicit TLS connection succeeded")
	}

	canConnect := true
	detail.CanConnect = &canConnect
	detail.ImplicitTls = &implicitTLS

	// Read greeting
	greeting, err := pop3util.ReadGreeting(conn)
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
	preCaps, preMechs, impl, loginDelay, expireDays := runCapa(conn)
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
		tlsConn, err := upgradeToTLS(conn, hostname)
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

			// Run CAPA again post-STLS to get updated capabilities
			postCaps, postMechs, postImpl, _, _ := runCapa(conn)
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
