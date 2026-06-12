// Package rdp implements pre-auth RDP fingerprinting (enumerate stage, Mode A).
// It performs an X.224 Connection Request with rdpNegReq, parses the
// Connection Confirm / rdpNegRsp / rdpNegFailure, optionally upgrades to TLS,
// and captures the server certificate.
//
// No authentication or payload beyond the X.224 handshake is sent.
package rdp

import (
	// Standard
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	rdpfern "github.com/Method-Security/networkscan/generated/go/enumerate/rdp"

	// Internal
	rdpproto "github.com/Method-Security/networkscan/internal/protocol/rdp"
	"github.com/Method-Security/networkscan/utils"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const defaultRDPPort = 3389

// LibraryEnumerateRDP implements NetworkApplicationLibrary for RDP enumeration.
type LibraryEnumerateRDP struct{}

// EnumerateTarget implements NetworkApplicationLibrary and performs pre-auth RDP
// fingerprinting against a single target (host:port or bare host).
func (l *LibraryEnumerateRDP) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	detail := enumerateRDP(ctx, target)
	return &enumeratefern.EnumerateServiceDetails{EnumerateRdpDetails: detail}, nil
}

// enumerateRDP performs a pre-auth RDP fingerprint against the given target (host:port).
// It returns a populated EnumerateRdpDetails.
func enumerateRDP(ctx context.Context, target string) *rdpfern.EnumerateRdpDetails {
	log := svc1log.FromContext(ctx)
	log.Info("Starting RDP enumeration", svc1log.SafeParam("target", target))

	// Parse target via the shared helper so out-of-range / non-numeric ports
	// fall back to the default 3389 (matches enumerate/{ldap,mongodb,mysql,…}).
	host, port := utils.ParseHostPort(target, defaultRDPPort)

	// Use net.JoinHostPort to correctly handle IPv6 addresses
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	requestedFlags := int(rdpproto.RequestAllProtocols)
	result := &rdpfern.EnumerateRdpDetails{
		Target:                 addr,
		Success:                false,
		RequestedProtocolFlags: &requestedFlags,
	}

	// Connect TCP with timeout from context deadline (set by engine) or fallback.
	deadline := 30 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		deadline = time.Until(dl)
		if deadline <= 0 {
			deadline = 5 * time.Second
		}
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		errMsg := fmt.Sprintf("TCP connection failed: %v", err)
		result.ErrorMessage = &errMsg
		return result
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(deadline))

	// Send X.224 Connection Request with cookie "test" and all protocols.
	const cookie = "test"
	if err := rdpproto.WriteX224ConnectionRequest(conn, cookie, rdpproto.RequestAllProtocols); err != nil {
		errMsg := fmt.Sprintf("X.224 CR send failed: %v", err)
		result.ErrorMessage = &errMsg
		return result
	}

	// Read X.224 Connection Confirm.
	cc, err := rdpproto.ReadX224ConnectionConfirm(conn)
	if err != nil {
		errMsg := fmt.Sprintf("X.224 CC read failed: %v", err)
		result.ErrorMessage = &errMsg
		return result
	}

	// Mark as success — we got a well-formed response.
	result.Success = true

	// Parse negotiation response.
	if cc.NegResponseReceived {
		// mapProtocolToFlags returns nil for unrecognized flags; leave
		// result.SelectedProtocol unset in that case (the raw uint32 is still
		// preserved in selectedProtocolFlags below for forensics).
		result.SelectedProtocol = mapProtocolToFlags(cc.SelectedProtocol)
		selectedFlags := int(cc.SelectedProtocol)
		result.SelectedProtocolFlags = &selectedFlags
		// Infer supported protocols from what the server actually selected
		supported := inferSupportedProtocols(cc.SelectedProtocol, cc.FailureCode, false)
		if len(supported) > 0 {
			result.SupportedProtocols = supported
		}
		// HYBRID and HYBRID_EX use CredSSP/NLA; record that as nlaRequired so the
		// successful-HYBRID-handshake path agrees with the failure-side
		// HYBRID_REQUIRED_BY_SERVER branch below.
		if cc.SelectedProtocol == rdpproto.ProtocolHybrid || cc.SelectedProtocol == rdpproto.ProtocolHybridEx {
			nlaRequired := true
			result.NlaRequired = &nlaRequired
		}
	} else if cc.NegFailureReceived {
		// Failure code — infer supported protocols from failure and set nlaRequired flag.
		// mapFailureCode returns nil for unrecognized codes; leave
		// result.NegFailureCode unset in that case rather than guessing.
		result.NegFailureCode = mapFailureCode(cc.FailureCode)
		supported := inferSupportedProtocols(0, cc.FailureCode, true)
		if len(supported) > 0 {
			result.SupportedProtocols = supported
		}
		if cc.FailureCode == rdpproto.FailureHybridRequiredByServer {
			nlaRequired := true
			result.NlaRequired = &nlaRequired
		}
	}

	// Attempt TLS upgrade if selected protocol is not raw RDP.
	if cc.NegResponseReceived && cc.SelectedProtocol != rdpproto.ProtocolRDP {
		tlsCert, tlsErr := upgradeToTLS(conn, host)
		if tlsErr != nil {
			log.Debug("TLS upgrade failed", svc1log.SafeParam("error", tlsErr))
		} else {
			result.Certificate = tlsCert
		}
	}

	return result
}

// upgradeToTLS performs a TLS client handshake on an existing TCP connection
// and returns the server certificate information.
//
// InsecureSkipVerify is intentional: this is an enumeration probe against
// arbitrary RDP servers that routinely present self-signed, expired, or
// hostname-mismatched certificates. Verifying the chain would prevent us
// from collecting the very forensic evidence (cert subject/SAN/fingerprint)
// the probe exists to capture. Mirrors the rationale in
// internal/enumerate/pop3/helpers.go and internal/protocol/imap/protocol.go.
func upgradeToTLS(conn net.Conn, serverName string) (*rdpfern.RdpTlsCertificate, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // see function doc — pre-auth probe, untrusted certs expected
		ServerName:         serverName,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificate in TLS state")
	}

	cert := state.PeerCertificates[0]
	return buildTLSCertificate(cert), nil
}

// buildTLSCertificate converts an x509.Certificate to a Fern RdpTlsCertificate.
func buildTLSCertificate(cert *x509.Certificate) *rdpfern.RdpTlsCertificate {
	selfSigned := cert.Issuer.String() == cert.Subject.String()

	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, email)
	}

	return &rdpfern.RdpTlsCertificate{
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		NotBefore:  cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
		Sans:       sans,
		SelfSigned: selfSigned,
	}
}

// MapProtocolToFlags converts a raw protocol uint32 to the Fern RdpProtocolFlag enum,
// or nil if proto is not one of the values defined by [MS-RDPBCGR] §2.2.1.1.1.
// Exported so it can be used by the bluekeep pentest package.
func MapProtocolToFlags(proto uint32) *rdpfern.RdpProtocolFlag {
	return mapProtocolToFlags(proto)
}

// mapProtocolToFlags is the internal implementation. Returns nil for unrecognized
// values rather than guessing — keeps EnumerateRdpDetails.SelectedProtocol unset
// on future/unknown flags instead of mislabeling them as PROTOCOL_RDP (the raw
// 32-bit value is still preserved in SelectedProtocolFlags for forensics).
func mapProtocolToFlags(proto uint32) *rdpfern.RdpProtocolFlag {
	var v rdpfern.RdpProtocolFlag
	switch proto {
	case rdpproto.ProtocolRDP:
		v = rdpfern.RdpProtocolFlagProtocolRdp
	case rdpproto.ProtocolSSL:
		v = rdpfern.RdpProtocolFlagProtocolSsl
	case rdpproto.ProtocolHybrid:
		v = rdpfern.RdpProtocolFlagProtocolHybrid
	case rdpproto.ProtocolRDSTLS:
		v = rdpfern.RdpProtocolFlagProtocolRdstls
	case rdpproto.ProtocolHybridEx:
		v = rdpfern.RdpProtocolFlagProtocolHybridEx
	case rdpproto.ProtocolHybridRecLimit:
		v = rdpfern.RdpProtocolFlagProtocolHybridRecLimitReached
	default:
		return nil
	}
	return &v
}

// mapFailureCode converts a raw failure code uint32 to the Fern RdpNegFailureCode
// enum, or nil if the code is not one of the codes defined by [MS-RDPBCGR]
// §2.2.1.2.2. Returning nil (rather than guessing) lets the caller leave
// EnumerateRdpDetails.NegFailureCode unset for unrecognized codes, matching the
// ontology-definition convention against UNKNOWN/OTHER enum sentinels — the raw
// 32-bit code is still preserved in the signal payload for forensics.
func mapFailureCode(code uint32) *rdpfern.RdpNegFailureCode {
	var v rdpfern.RdpNegFailureCode
	switch code {
	case rdpproto.FailureSSLRequiredByServer:
		v = rdpfern.RdpNegFailureCodeSslRequiredByServer
	case rdpproto.FailureSSLNotAllowedByServer:
		v = rdpfern.RdpNegFailureCodeSslNotAllowedByServer
	case rdpproto.FailureSSLCertNotOnServer:
		v = rdpfern.RdpNegFailureCodeSslCertNotOnServer
	case rdpproto.FailureInconsistentFlags:
		v = rdpfern.RdpNegFailureCodeInconsistentFlags
	case rdpproto.FailureHybridRequiredByServer:
		v = rdpfern.RdpNegFailureCodeHybridRequiredByServer
	case rdpproto.FailureSSLWithUserAuthRequiredByServer:
		v = rdpfern.RdpNegFailureCodeSslWithUserAuthRequiredByServer
	default:
		return nil
	}
	return &v
}

// inferSupportedProtocols infers what protocols the server supports from the
// server's actual response rather than echoing the requested bitmap.
//
// Logic:
//   - If negFailure and HYBRID_REQUIRED_BY_SERVER → server only supports HYBRID (NLA).
//   - If negFailure and SSL_REQUIRED_BY_SERVER → server supports SSL family (SSL+HYBRID+HYBRID_EX).
//   - If negRsp with selectedProtocol=HYBRID → server supports at least HYBRID (probably HYBRID_EX too).
//   - If negRsp with selectedProtocol=SSL → server supports SSL.
//   - If negRsp with selectedProtocol=RDP → server supports RDP.
//   - Otherwise emit the selected protocol as a single member.
func inferSupportedProtocols(selectedProtocol uint32, failureCode uint32, isFailure bool) []rdpfern.RdpProtocolFlag {
	if isFailure {
		switch failureCode {
		case rdpproto.FailureHybridRequiredByServer:
			return []rdpfern.RdpProtocolFlag{rdpfern.RdpProtocolFlagProtocolHybrid}
		case rdpproto.FailureSSLRequiredByServer, rdpproto.FailureSSLWithUserAuthRequiredByServer:
			return []rdpfern.RdpProtocolFlag{
				rdpfern.RdpProtocolFlagProtocolSsl,
				rdpfern.RdpProtocolFlagProtocolHybrid,
				rdpfern.RdpProtocolFlagProtocolHybridEx,
			}
		default:
			return nil
		}
	}

	// Negotiation success — infer from selected protocol
	switch selectedProtocol {
	case rdpproto.ProtocolHybrid:
		return []rdpfern.RdpProtocolFlag{
			rdpfern.RdpProtocolFlagProtocolHybrid,
			rdpfern.RdpProtocolFlagProtocolHybridEx,
		}
	case rdpproto.ProtocolHybridEx:
		return []rdpfern.RdpProtocolFlag{
			rdpfern.RdpProtocolFlagProtocolHybrid,
			rdpfern.RdpProtocolFlagProtocolHybridEx,
		}
	case rdpproto.ProtocolSSL:
		return []rdpfern.RdpProtocolFlag{rdpfern.RdpProtocolFlagProtocolSsl}
	case rdpproto.ProtocolRDP:
		return []rdpfern.RdpProtocolFlag{rdpfern.RdpProtocolFlagProtocolRdp}
	default:
		if flag := mapProtocolToFlags(selectedProtocol); flag != nil {
			return []rdpfern.RdpProtocolFlag{*flag}
		}
		return nil
	}
}

// RunEnumerateRDP is a legacy entry point kept for direct callers. It returns
// an EnumerateRdpDetails for a single target.
func RunEnumerateRDP(ctx context.Context, target string, timeoutSec int) *rdpfern.EnumerateRdpDetails {
	// Create a timeout context from the timeout parameter.
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()
	return enumerateRDP(timeoutCtx, target)
}
