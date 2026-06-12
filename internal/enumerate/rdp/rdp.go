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
	"strings"
	"time"

	// Generated
	rdpfern "github.com/Method-Security/networkscan/generated/go/enumerate/rdp"
	// Internal
	rdpproto "github.com/Method-Security/networkscan/internal/protocol/rdp"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const defaultRDPPort = 3389

// EnumerateRDP performs a pre-auth RDP fingerprint against the given target (host:port).
// It returns a populated EnumerateRdpTargetResult.
func EnumerateRDP(ctx context.Context, target string, timeoutSec int) *rdpfern.EnumerateRdpTargetResult {
	log := svc1log.FromContext(ctx)
	log.Info("Starting RDP enumeration", svc1log.SafeParam("target", target))

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = strconv.Itoa(defaultRDPPort)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		errMsg := fmt.Sprintf("invalid port in target '%s': %v", target, err)
		success := false
		return &rdpfern.EnumerateRdpTargetResult{
			Target:       target,
			Port:         defaultRDPPort,
			Success:      success,
			ErrorMessage: &errMsg,
		}
	}

	result := &rdpfern.EnumerateRdpTargetResult{
		Target:                 fmt.Sprintf("%s:%d", host, port),
		Port:                   port,
		RequestedProtocolFlags: int(rdpproto.RequestAllProtocols),
	}

	// Connect TCP with timeout.
	deadline := time.Duration(timeoutSec) * time.Second
	dialer := &net.Dialer{}
	connCtx, connCancel := context.WithTimeout(ctx, deadline)
	defer connCancel()

	conn, err := dialer.DialContext(connCtx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		errMsg := fmt.Sprintf("TCP connection failed: %v", err)
		success := false
		result.Success = success
		result.ErrorMessage = &errMsg
		return result
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(deadline))

	// Send X.224 Connection Request with cookie "test" and all protocols.
	const cookie = "test"
	if err := rdpproto.WriteX224ConnectionRequest(conn, cookie, rdpproto.RequestAllProtocols); err != nil {
		errMsg := fmt.Sprintf("X.224 CR send failed: %v", err)
		success := false
		result.Success = success
		result.ErrorMessage = &errMsg
		return result
	}

	// Read X.224 Connection Confirm.
	cc, err := rdpproto.ReadX224ConnectionConfirm(conn)
	if err != nil {
		errMsg := fmt.Sprintf("X.224 CC read failed: %v", err)
		success := false
		result.Success = success
		result.ErrorMessage = &errMsg
		return result
	}

	// Mark as success — we got a well-formed response.
	success := true
	result.Success = success

	// Parse negotiation response.
	if cc.NegResponseReceived {
		selected := mapProtocolToFlags(cc.SelectedProtocol)
		result.SelectedProtocol = &selected
		result.SelectedProtocolFlags = int(cc.SelectedProtocol)
		result.SupportedProtocols = parseSupportedProtocols(rdpproto.RequestAllProtocols)
	} else if cc.NegFailureReceived {
		// Failure code — infer NLA required if HYBRID_REQUIRED_BY_SERVER.
		failCode := mapFailureCode(cc.FailureCode)
		result.NegFailureCode = &failCode
		if cc.FailureCode == rdpproto.FailureHybridRequiredByServer {
			result.NlaRequired = true
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

// RunEnumerateRDP performs RDP enumeration for multiple targets and returns a report.
func RunEnumerateRDP(ctx context.Context, targets []string, timeoutSec int) *rdpfern.EnumerateRdpServiceReport {
	log := svc1log.FromContext(ctx)

	timeout := timeoutSec
	if timeout == 0 {
		timeout = 30
	}

	config := &rdpfern.RdpEnumerateConfig{
		Timeout: &timeout,
	}

	var results []*rdpfern.EnumerateRdpTargetResult
	var errors []string

	for _, target := range targets {
		targetCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		r := EnumerateRDP(targetCtx, target, timeout)
		cancel()
		results = append(results, r)
		if r.ErrorMessage != nil {
			log.Debug("RDP enumeration error",
				svc1log.SafeParam("target", target),
				svc1log.SafeParam("error", *r.ErrorMessage))
		}
	}

	return &rdpfern.EnumerateRdpServiceReport{
		Config:  config,
		Results: results,
		Errors:  errors,
	}
}

// upgradeToTLS performs a TLS client handshake on an existing TCP connection
// and returns the server certificate information.
func upgradeToTLS(conn net.Conn, serverName string) (*rdpfern.TlsCertificate, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
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

// buildTLSCertificate converts an x509.Certificate to a Fern TlsCertificate.
func buildTLSCertificate(cert *x509.Certificate) *rdpfern.TlsCertificate {
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

	return &rdpfern.TlsCertificate{
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		NotBefore:  cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
		Sans:       sans,
		SelfSigned: selfSigned,
	}
}

// mapProtocolToFlags converts a raw protocol uint32 to the Fern RdpProtocolFlag enum.
func mapProtocolToFlags(proto uint32) rdpfern.RdpProtocolFlag {
	switch proto {
	case rdpproto.ProtocolRDP:
		return rdpfern.RdpProtocolFlagProtocolRdp
	case rdpproto.ProtocolSSL:
		return rdpfern.RdpProtocolFlagProtocolSsl
	case rdpproto.ProtocolHybrid:
		return rdpfern.RdpProtocolFlagProtocolHybrid
	case rdpproto.ProtocolRDSTLS:
		return rdpfern.RdpProtocolFlagProtocolRdstls
	case rdpproto.ProtocolHybridEx:
		return rdpfern.RdpProtocolFlagProtocolHybridEx
	case rdpproto.ProtocolHybridRecLimit:
		return rdpfern.RdpProtocolFlagProtocolHybridRecLimitReached
	default:
		return rdpfern.RdpProtocolFlagProtocolRdp
	}
}

// mapFailureCode converts a raw failure code uint32 to the Fern RdpNegFailureCode enum.
func mapFailureCode(code uint32) rdpfern.RdpNegFailureCode {
	switch code {
	case rdpproto.FailureSSLRequiredByServer:
		return rdpfern.RdpNegFailureCodeSslRequiredByServer
	case rdpproto.FailureSSLNotAllowedByServer:
		return rdpfern.RdpNegFailureCodeSslNotAllowedByServer
	case rdpproto.FailureSSLCertNotOnServer:
		return rdpfern.RdpNegFailureCodeSslCertNotOnServer
	case rdpproto.FailureInconsistentFlags:
		return rdpfern.RdpNegFailureCodeInconsistentFlags
	case rdpproto.FailureHybridRequiredByServer:
		return rdpfern.RdpNegFailureCodeHybridRequiredByServer
	case rdpproto.FailureSSLWithUserAuthRequiredByServer:
		return rdpfern.RdpNegFailureCodeSslWithUserAuthRequiredByServer
	default:
		return rdpfern.RdpNegFailureCodeSslRequiredByServer
	}
}

// parseSupportedProtocols returns the list of protocols from a bitmap of requested flags.
func parseSupportedProtocols(bitmap uint32) []rdpfern.RdpProtocolFlag {
	var flags []rdpfern.RdpProtocolFlag
	if bitmap&rdpproto.ProtocolSSL != 0 {
		flags = append(flags, rdpfern.RdpProtocolFlagProtocolSsl)
	}
	if bitmap&rdpproto.ProtocolHybrid != 0 {
		flags = append(flags, rdpfern.RdpProtocolFlagProtocolHybrid)
	}
	if bitmap&rdpproto.ProtocolRDSTLS != 0 {
		flags = append(flags, rdpfern.RdpProtocolFlagProtocolRdstls)
	}
	if bitmap&rdpproto.ProtocolHybridEx != 0 {
		flags = append(flags, rdpfern.RdpProtocolFlagProtocolHybridEx)
	}
	return flags
}

// splitHostNoPort extracts the host from a "host:port" or bare "host" string.
func splitHostNoPort(target string) string {
	if !strings.Contains(target, ":") {
		return target
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	return host
}
