// Package socks implements SOCKS4/4a/5 proxy enumeration.
package socks

import (
	// Standard
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	socksfern "github.com/Method-Security/networkscan/generated/go/enumerate/socks"

	// Internal
	socksproto "github.com/Method-Security/networkscan/internal/protocol/socks"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateSocks implements NetworkApplicationLibrary for SOCKS proxy enumeration.
type LibraryEnumerateSocks struct{}

// EnumerateTarget probes the SOCKS proxy at the given target (host:port).
// It tests SOCKS4, SOCKS4a, and SOCKS5 support and records details about
// auth methods, BIND, and UDP ASSOCIATE support.
func (s *LibraryEnumerateSocks) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting SOCKS enumeration", svc1log.SafeParam("target", target))

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		errMsg := fmt.Sprintf("invalid target format: %v", err)
		detail := &socksfern.EnumerateSocksDetails{
			Target: target,
			Port:   0,
			Error:  &errMsg,
		}
		return &enumeratefern.EnumerateServiceDetails{EnumerateSocksDetails: detail}, []string{errMsg}
	}

	port := 0
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		port = 1080
	}

	detail := &socksfern.EnumerateSocksDetails{
		Target: host,
		Port:   port,
	}
	errors := []string{}

	probeIP := net.ParseIP(DefaultProbeIP)
	if probeIP == nil {
		probeIP = net.IPv4(93, 184, 216, 34)
	}

	// ---- SOCKS4 probe ----
	log.Debug("Probing SOCKS4", svc1log.SafeParam("target", target))
	socks4Supported := probeSocks4(ctx, target, probeIP, DefaultProbePort, log)
	detail.Socks4Supported = &socks4Supported

	// ---- SOCKS4a probe ----
	log.Debug("Probing SOCKS4a", svc1log.SafeParam("target", target))
	socks4aSupported := probeSocks4a(ctx, target, DefaultProbeHost, DefaultProbePort, log)
	detail.Socks4ASupported = &socks4aSupported

	// ---- SOCKS5 handshake ----
	log.Debug("Probing SOCKS5", svc1log.SafeParam("target", target))
	socks5Result := probeSocks5(ctx, target, port, probeIP, log)

	detail.Socks5Supported = &socks5Result.supported
	if socks5Result.supported {
		detail.AuthMethodsOffered = socks5Result.authMethods
		detail.NoAuthAllowed = &socks5Result.noAuthAllowed
		detail.UserpassAuthAllowed = &socks5Result.userpassAllowed
		detail.GssapiAvailable = &socks5Result.gssapiAvailable
		detail.BindSupported = &socks5Result.bindSupported
		detail.UdpAssociateSupported = &socks5Result.udpAssociateSupported
		if socks5Result.bndAddr != "" {
			detail.BndAddr = &socks5Result.bndAddr
		}
		if socks5Result.bndPort != 0 {
			bndPort := int(socks5Result.bndPort)
			detail.BndPort = &bndPort
		}
		hint := detectImplementationHint(
			port,
			socks5Result.chosenMethod,
			socks5Result.connectRep,
			socks5Result.bindRepCode,
			socks5Result.responseTimeMs,
			socks4Supported,
			socks4aSupported,
			socks5Result.udpAssociateSupported,
		)
		detail.ImplementationHint = &hint
	}

	for _, e := range socks5Result.errors {
		errors = append(errors, e)
	}

	log.Info("SOCKS enumeration complete",
		svc1log.SafeParam("target", target),
		svc1log.SafeParam("socks4", socks4Supported),
		svc1log.SafeParam("socks4a", socks4aSupported),
		svc1log.SafeParam("socks5", socks5Result.supported))

	return &enumeratefern.EnumerateServiceDetails{EnumerateSocksDetails: detail}, errors
}

// probeSocks4 attempts a SOCKS4 CONNECT and returns true if the server replied
// with a valid SOCKS4 response (regardless of grant/reject code).
func probeSocks4(ctx context.Context, target string, probeIP net.IP, probePort uint16, log svc1log.Logger) bool {
	conn, err := dialWithTimeout(ctx, target, DefaultDialTimeoutSeconds)
	if err != nil {
		log.Debug("SOCKS4 dial failed", svc1log.SafeParam("error", err.Error()))
		return false
	}
	defer func() { _ = conn.Close() }()

	req := socksproto.BuildSOCKS4ConnectRequest(probeIP, probePort, "probe")
	setStepDeadline(ctx, conn)
	if _, err := conn.Write(req); err != nil {
		log.Debug("SOCKS4 write failed", svc1log.SafeParam("error", err.Error()))
		return false
	}

	setStepDeadline(ctx, conn)
	reader := bufio.NewReader(conn)
	code, _, _, err := socksproto.ParseSOCKS4Reply(reader)
	if err != nil {
		log.Debug("SOCKS4 reply parse failed", svc1log.SafeParam("error", err.Error()))
		return false
	}

	// All four reply codes (0x5A granted, 0x5B rejected, 0x5C identd unreachable,
	// 0x5D user-id mismatch) confirm the server speaks SOCKS4.
	return code == socksproto.SOCKS4RepGranted ||
		code == socksproto.SOCKS4RepRejected ||
		code == socksproto.SOCKS4RepIdentFail ||
		code == socksproto.SOCKS4RepIdentMismatch
}

// probeSocks4a attempts a SOCKS4a CONNECT using a domain name.
func probeSocks4a(ctx context.Context, target string, probeHost string, probePort uint16, log svc1log.Logger) bool {
	conn, err := dialWithTimeout(ctx, target, DefaultDialTimeoutSeconds)
	if err != nil {
		log.Debug("SOCKS4a dial failed", svc1log.SafeParam("error", err.Error()))
		return false
	}
	defer func() { _ = conn.Close() }()

	req := socksproto.BuildSOCKS4aConnectRequest(probeHost, probePort, "probe")
	setStepDeadline(ctx, conn)
	if _, err := conn.Write(req); err != nil {
		log.Debug("SOCKS4a write failed", svc1log.SafeParam("error", err.Error()))
		return false
	}

	setStepDeadline(ctx, conn)
	reader := bufio.NewReader(conn)
	code, _, _, err := socksproto.ParseSOCKS4Reply(reader)
	if err != nil {
		log.Debug("SOCKS4a reply parse failed", svc1log.SafeParam("error", err.Error()))
		return false
	}

	// Only a granted (0x5A) reply reliably demonstrates SOCKS4a — a SOCKS4-
	// only proxy receiving a 4a-style request (IP 0.0.0.1 + null + hostname)
	// routinely returns 0x5B as a generic rejection without ever parsing the
	// trailing hostname. The ident codes (0x5C / 0x5D) have the same problem.
	// A grant is the only signal we can attribute confidently to 4a-specific
	// behavior. We trade a false negative (a 4a server that legitimately
	// rejects our probe target) for the much more common false positive.
	return code == socksproto.SOCKS4RepGranted
}

// socks5ProbeResult holds the result of the full SOCKS5 probe sequence.
type socks5ProbeResult struct {
	supported             bool
	chosenMethod          byte
	authMethods           []socksfern.SocksAuthMethod
	noAuthAllowed         bool
	userpassAllowed       bool
	gssapiAvailable       bool
	bindSupported         bool
	udpAssociateSupported bool
	bndAddr               string
	bndPort               uint16
	connectRep            *byte // nil if CONNECT was never attempted
	bindRepCode           *byte
	responseTimeMs        int64
	errors                []string
}

// probeSocks5 performs the full SOCKS5 probe sequence:
// greeting → method selection → CONNECT → BIND → UDP ASSOCIATE.
func probeSocks5(
	ctx context.Context,
	target string,
	port int,
	probeIP net.IP,
	log svc1log.Logger,
) socks5ProbeResult {
	result := socks5ProbeResult{}

	// --- Step 1: Greeting / method negotiation ---
	conn, err := dialWithTimeout(ctx, target, DefaultDialTimeoutSeconds)
	if err != nil {
		log.Debug("SOCKS5 dial failed", svc1log.SafeParam("error", err.Error()))
		return result
	}

	// Offer NO_AUTH, GSSAPI, USERNAME_PASSWORD
	offeredMethods := []byte{socksproto.AuthNoAuth, socksproto.AuthGSSAPI, socksproto.AuthUsernamePassword}
	greeting := socksproto.BuildSOCKS5Greeting(offeredMethods)

	setStepDeadline(ctx, conn)
	start := time.Now()
	if _, err := conn.Write(greeting); err != nil {
		log.Debug("SOCKS5 greeting write failed", svc1log.SafeParam("error", err.Error()))
		_ = conn.Close()
		return result
	}

	setStepDeadline(ctx, conn)
	reader := bufio.NewReader(conn)
	chosenMethod, err := socksproto.ParseSOCKS5ServerChoice(reader)
	result.responseTimeMs = time.Since(start).Milliseconds()

	if err != nil {
		log.Debug("SOCKS5 method choice parse failed", svc1log.SafeParam("error", err.Error()))
		_ = conn.Close()
		return result
	}

	// Server responded with a valid SOCKS5 method selection — it is SOCKS5
	result.supported = true
	result.chosenMethod = chosenMethod

	// Record auth methods based on server's chosen method.
	// userpassAllowed means "server supports username/password as an auth method"
	// and is set at negotiation time, regardless of whether our probe credentials succeed.
	result.authMethods = parseAuthMethodsFromChoice(chosenMethod)
	result.noAuthAllowed = chosenMethod == socksproto.AuthNoAuth
	result.userpassAllowed = chosenMethod == socksproto.AuthUsernamePassword
	result.gssapiAvailable = chosenMethod == socksproto.AuthGSSAPI

	// If server chose no-auth (0xFF = no acceptable method is a non-auth response)
	if chosenMethod == socksproto.AuthNoAcceptable {
		// Server doesn't accept any of our methods but it's still SOCKS5
		_ = conn.Close()
		return result
	}

	// --- Step 2: Auth sub-negotiation if needed ---
	// Gate the CONNECT step on whether auth on THIS connection succeeded.
	// BIND and UDP probes (Steps 4 & 5) open INDEPENDENT connections and
	// run regardless of CONNECT outcome — a userpass auth failure here
	// should not silently hide BIND/UDP capability.
	proceedOnMain := chosenMethod == socksproto.AuthNoAuth
	if chosenMethod == socksproto.AuthUsernamePassword {
		// Probe with a default guest/guest credential. The intent of Mode A
		// (unauthenticated) enumeration is only to confirm the server speaks
		// the USERPASS sub-negotiation correctly — actual credential testing
		// is out of scope for this enumerator.
		setStepDeadline(ctx, conn)
		authReq := socksproto.BuildSOCKS5UsernamePasswordAuth("guest", "guest")
		if _, err := conn.Write(authReq); err != nil {
			result.errors = append(result.errors, fmt.Sprintf("SOCKS5 auth write failed: %v", err))
		} else {
			setStepDeadline(ctx, conn)
			authOK, err := socksproto.ParseSOCKS5AuthReply(reader)
			if err != nil {
				result.errors = append(result.errors, fmt.Sprintf("SOCKS5 auth reply failed: %v", err))
			} else if authOK {
				proceedOnMain = true
			}
		}
	}

	// --- Step 3: CONNECT probe ---
	if proceedOnMain {
		setStepDeadline(ctx, conn)
		connectReq := socksproto.BuildSOCKS5ConnectRequest(probeIP, DefaultProbePort)
		if _, err := conn.Write(connectReq); err != nil {
			result.errors = append(result.errors, fmt.Sprintf("SOCKS5 CONNECT write failed: %v", err))
		} else {
			setStepDeadline(ctx, conn)
			repCode, bndAddr, bndPort, err := socksproto.ParseSOCKS5Reply(reader)
			if err != nil {
				result.errors = append(result.errors, fmt.Sprintf("SOCKS5 CONNECT reply failed: %v", err))
			} else {
				result.connectRep = &repCode
				if repCode == socksproto.RepSuccess {
					result.bndAddr = bndAddr
					result.bndPort = bndPort
				}
			}
		}
	}

	_ = conn.Close()

	// --- Step 4: BIND probe (independent connection) ---
	if bindRep, ok := probeSocks5Command(ctx, target, socksproto.BuildSOCKS5BindRequest(net.IPv4(0, 0, 0, 0), 0), log); ok {
		result.bindRepCode = &bindRep
		result.bindSupported = bindRep == socksproto.RepSuccess
	}

	// --- Step 5: UDP ASSOCIATE probe (new connection) ---
	// Same auth-method mirroring as the BIND probe.
	if udpRep, ok := probeSocks5Command(ctx, target, socksproto.BuildSOCKS5UDPAssociateRequest(net.IPv4(0, 0, 0, 0), 0), log); ok {
		result.udpAssociateSupported = udpRep == socksproto.RepSuccess
	}

	// When the server selected GSSAPI on the main connection, probeSocks5Command
	// will also fail to complete auth on the BIND/UDP probe connections (GSSAPI
	// requires a full token exchange we do not implement). Record this explicitly
	// so callers know the nil bindRepCode and false udpAssociateSupported are a
	// limitation of the probe, not evidence that BIND/UDP are disabled.
	if result.gssapiAvailable {
		result.errors = append(result.errors, "GSSAPI-only proxy: BIND and UDP ASSOCIATE probes skipped (GSSAPI auth not implemented)")
	}

	return result
}

// probeSocks5Command opens a fresh SOCKS5 connection, completes greeting +
// optional auth (offering NO_AUTH, GSSAPI, and USERPASS so proxies that
// require auth on every connection still answer), then sends the supplied
// request and returns the reply code. The ok return is false when the probe
// could not reach the reply stage for any reason (dial failure, write
// failure, auth rejected, or GSSAPI-only auth which we cannot complete).
// Callers should treat ok=false as "no signal" rather than "command not
// supported".
func probeSocks5Command(ctx context.Context, target string, request []byte, log svc1log.Logger) (byte, bool) {
	conn, err := dialWithTimeout(ctx, target, DefaultDialTimeoutSeconds)
	if err != nil {
		log.Debug("SOCKS5 probe dial failed", svc1log.SafeParam("error", err.Error()))
		return 0, false
	}
	defer func() { _ = conn.Close() }()

	setStepDeadline(ctx, conn)
	// Mirror the main probe greeting (NO_AUTH + GSSAPI + USERPASS) so that
	// GSSAPI-only servers respond with 0x01 (GSSAPI) instead of 0xFF (no
	// acceptable method), giving consistent server feedback across probes.
	if _, err := conn.Write(socksproto.BuildSOCKS5Greeting([]byte{socksproto.AuthNoAuth, socksproto.AuthGSSAPI, socksproto.AuthUsernamePassword})); err != nil {
		return 0, false
	}
	setStepDeadline(ctx, conn)
	reader := bufio.NewReader(conn)
	chosen, err := socksproto.ParseSOCKS5ServerChoice(reader)
	if err != nil {
		return 0, false
	}

	// Auth sub-negotiation when the server selects USERPASS. Any write or
	// auth failure MUST abort — falling through would send the BIND/UDP
	// command on an unauthenticated session and break subsequent reads.
	switch chosen {
	case socksproto.AuthNoAuth:
		// OK
	case socksproto.AuthUsernamePassword:
		setStepDeadline(ctx, conn)
		if _, err := conn.Write(socksproto.BuildSOCKS5UsernamePasswordAuth("guest", "guest")); err != nil {
			return 0, false
		}
		setStepDeadline(ctx, conn)
		authOK, err := socksproto.ParseSOCKS5AuthReply(reader)
		if err != nil || !authOK {
			return 0, false
		}
	case socksproto.AuthGSSAPI:
		// GSSAPI (RFC 1961) requires a full Kerberos / GSS token exchange that
		// we do not implement. We cannot complete the handshake and therefore
		// cannot probe BIND or UDP ASSOCIATE on a GSSAPI-only proxy.
		return 0, false
	default:
		return 0, false
	}

	setStepDeadline(ctx, conn)
	if _, err := conn.Write(request); err != nil {
		return 0, false
	}
	setStepDeadline(ctx, conn)
	rep, _, _, err := socksproto.ParseSOCKS5Reply(reader)
	if err != nil {
		return 0, false
	}
	return rep, true
}
