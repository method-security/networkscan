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

	_ = conn.SetDeadline(time.Now().Add(DefaultProbeTimeoutSeconds * time.Second))

	req := socksproto.BuildSOCKS4ConnectRequest(probeIP, probePort, "probe")
	if _, err := conn.Write(req); err != nil {
		log.Debug("SOCKS4 write failed", svc1log.SafeParam("error", err.Error()))
		return false
	}

	reader := bufio.NewReader(conn)
	code, _, _, err := socksproto.ParseSOCKS4Reply(reader)
	if err != nil {
		log.Debug("SOCKS4 reply parse failed", svc1log.SafeParam("error", err.Error()))
		return false
	}

	// 0x5A = granted, 0x5B = rejected — both indicate a real SOCKS4 server
	return code == socksproto.SOCKS4RepGranted || code == socksproto.SOCKS4RepRejected
}

// probeSocks4a attempts a SOCKS4a CONNECT using a domain name.
func probeSocks4a(ctx context.Context, target string, probeHost string, probePort uint16, log svc1log.Logger) bool {
	conn, err := dialWithTimeout(ctx, target, DefaultDialTimeoutSeconds)
	if err != nil {
		log.Debug("SOCKS4a dial failed", svc1log.SafeParam("error", err.Error()))
		return false
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(DefaultProbeTimeoutSeconds * time.Second))

	req := socksproto.BuildSOCKS4aConnectRequest(probeHost, probePort, "probe")
	if _, err := conn.Write(req); err != nil {
		log.Debug("SOCKS4a write failed", svc1log.SafeParam("error", err.Error()))
		return false
	}

	reader := bufio.NewReader(conn)
	code, _, _, err := socksproto.ParseSOCKS4Reply(reader)
	if err != nil {
		log.Debug("SOCKS4a reply parse failed", svc1log.SafeParam("error", err.Error()))
		return false
	}

	return code == socksproto.SOCKS4RepGranted || code == socksproto.SOCKS4RepRejected
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
	connectRep            byte
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

	_ = conn.SetDeadline(time.Now().Add(DefaultProbeTimeoutSeconds * time.Second))

	// Offer NO_AUTH, GSSAPI, USERNAME_PASSWORD
	offeredMethods := []byte{socksproto.AuthNoAuth, socksproto.AuthGSSAPI, socksproto.AuthUsernamePassword}
	greeting := socksproto.BuildSOCKS5Greeting(offeredMethods)

	start := time.Now()
	if _, err := conn.Write(greeting); err != nil {
		log.Debug("SOCKS5 greeting write failed", svc1log.SafeParam("error", err.Error()))
		_ = conn.Close()
		return result
	}

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

	// Record auth methods
	result.authMethods = parseAuthMethodsFromChoice(offeredMethods, chosenMethod)
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
	if chosenMethod == socksproto.AuthUsernamePassword {
		// Probe with a default guest/guest credential. The intent of Mode A
		// (unauthenticated) enumeration is only to confirm the server speaks
		// the USERPASS sub-negotiation correctly — actual credential testing
		// is out of scope for this enumerator.
		authReq := socksproto.BuildSOCKS5UsernamePasswordAuth("guest", "guest")
		if _, err := conn.Write(authReq); err != nil {
			result.errors = append(result.errors, fmt.Sprintf("SOCKS5 auth write failed: %v", err))
			_ = conn.Close()
			return result
		}
		authOK, err := socksproto.ParseSOCKS5AuthReply(reader)
		if err != nil {
			result.errors = append(result.errors, fmt.Sprintf("SOCKS5 auth reply failed: %v", err))
			_ = conn.Close()
			return result
		}
		if !authOK {
			// Auth failed — can't proceed but SOCKS5 is confirmed
			_ = conn.Close()
			return result
		}
		result.userpassAllowed = true
	} else if chosenMethod != socksproto.AuthNoAuth {
		// Unsupported method — can't proceed
		_ = conn.Close()
		return result
	}

	// --- Step 3: CONNECT probe ---
	connectReq := socksproto.BuildSOCKS5ConnectRequest(probeIP, DefaultProbePort)
	if _, err := conn.Write(connectReq); err != nil {
		result.errors = append(result.errors, fmt.Sprintf("SOCKS5 CONNECT write failed: %v", err))
		_ = conn.Close()
		return result
	}

	repCode, bndAddr, bndPort, err := socksproto.ParseSOCKS5Reply(reader)
	if err != nil {
		result.errors = append(result.errors, fmt.Sprintf("SOCKS5 CONNECT reply failed: %v", err))
		_ = conn.Close()
		return result
	}
	result.connectRep = repCode
	if repCode == socksproto.RepSuccess {
		result.bndAddr = bndAddr
		result.bndPort = bndPort
	}

	_ = conn.Close()

	// --- Step 4: BIND probe (new connection) ---
	bindConn, err := dialWithTimeout(ctx, target, DefaultDialTimeoutSeconds)
	if err == nil {
		_ = bindConn.SetDeadline(time.Now().Add(DefaultProbeTimeoutSeconds * time.Second))

		// Fresh handshake
		bindGreeting := socksproto.BuildSOCKS5Greeting([]byte{socksproto.AuthNoAuth})
		if _, err := bindConn.Write(bindGreeting); err == nil {
			bindReader := bufio.NewReader(bindConn)
			bindMethod, err := socksproto.ParseSOCKS5ServerChoice(bindReader)
			if err == nil && bindMethod == socksproto.AuthNoAuth {
				bindReq := socksproto.BuildSOCKS5BindRequest(net.IPv4(0, 0, 0, 0), 0)
				if _, err := bindConn.Write(bindReq); err == nil {
					bindRep, _, _, err := socksproto.ParseSOCKS5Reply(bindReader)
					if err == nil {
						result.bindRepCode = &bindRep
						result.bindSupported = bindRep == socksproto.RepSuccess
					}
				}
			}
		}
		_ = bindConn.Close()
	}

	// --- Step 5: UDP ASSOCIATE probe (new connection) ---
	udpConn, err := dialWithTimeout(ctx, target, DefaultDialTimeoutSeconds)
	if err == nil {
		_ = udpConn.SetDeadline(time.Now().Add(DefaultProbeTimeoutSeconds * time.Second))

		udpGreeting := socksproto.BuildSOCKS5Greeting([]byte{socksproto.AuthNoAuth})
		if _, err := udpConn.Write(udpGreeting); err == nil {
			udpReader := bufio.NewReader(udpConn)
			udpMethod, err := socksproto.ParseSOCKS5ServerChoice(udpReader)
			if err == nil && udpMethod == socksproto.AuthNoAuth {
				udpReq := socksproto.BuildSOCKS5UDPAssociateRequest(net.IPv4(0, 0, 0, 0), 0)
				if _, err := udpConn.Write(udpReq); err == nil {
					udpRep, _, _, err := socksproto.ParseSOCKS5Reply(udpReader)
					if err == nil && udpRep == socksproto.RepSuccess {
						result.udpAssociateSupported = true
					}
				}
			}
		}
		_ = udpConn.Close()
	}

	return result
}
