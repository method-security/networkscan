// Package plugins provides IPMI (Intelligent Platform Management Interface) service fingerprinting.
//
// The IPMI fingerprinter runs the always-on Get-Channel-Auth-Capabilities
// banner against UDP/623 to identify the BMC and surface the parsed
// Auth-Type-Support-1/2/3 bitmaps (IPMI 2.0 spec §22.13). The fix the
// AITF-110 work calls out — surfacing the bitmap fully and detecting
// IPMI 2.0 from the right byte — lives here.
//
// Cipher Zero (CVE-2013-4031) and the RAKP HMAC-SHA1 disclosure
// existence oracle (CVE-2013-4786) are pre-auth but heavier: every host
// burns ~15 UDP exchanges (cipher zero + 5 RAKP rounds × 2 calls), and
// the RAKP path actively probes BMC username state. Per @apurvagoenka
// on PR #308, those deep probes belong on the on-demand enumerate path
// rather than running on every discovery sweep. Operators opt in via
// `Method enumerate ipmi <host:port>`; see internal/enumerate/ipmi for
// that flow.
package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	ipmiprotocol "github.com/Method-Security/networkscan/internal/protocol/ipmi"
)

// udpReadBufferSize bounds the maximum response payload we'll accept
// from a BMC in a single read. Get-Channel-Auth-Caps responses are well
// under 100 bytes; 1024 leaves plenty of headroom.
const udpReadBufferSize = 1024

// IPMIFingerprinter is the UDP/623 IPMI discovery plugin. Single
// Get-Channel-Auth-Capabilities probe — see package docs for why the
// deep validators (Cipher Zero, RAKP) live on the enumerate path
// instead.
type IPMIFingerprinter struct{}

// Name returns the fingerprinter identifier.
func (IPMIFingerprinter) Name() string { return "ipmi" }

// DefaultPorts returns the UDP ports the IPMI fingerprinter watches.
func (IPMIFingerprinter) DefaultPorts() []int { return []int{623} }

// Detect runs the Get-Channel-Auth-Capabilities probe against the host
// and returns a populated discoverfern.ServiceDetails. Returns an error
// when the probe fails — that means the host is not IPMI on this port.
func (IPMIFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// helpers.UDPExchange will respect ctx cancellation and translate
	// `timeout` into a per-call read deadline (treating timeout==0 as
	// "deadline=now" and timeout<0 as "no deadline").
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, ipmiprotocol.BuildGetChannelAuthCapabilitiesRequest(), udpReadBufferSize)
	if err != nil {
		return nil, err
	}
	caps, err := ipmiprotocol.ParseAuthCapabilities(resp)
	if err != nil {
		return nil, err
	}

	version := caps.Version()

	// Backward-compatible authType string: the old plugin stored the
	// first byte of the session header (always 0x00) and downstream
	// consumers may read it. We now store the *real* Auth-Type-Support-1
	// bitmap byte from offset 22, which conveys the channel auth-type
	// mask. Fall back to "0x00" when we somehow couldn't pull that byte
	// (truncated response).
	authTypeStr := "0x00"
	if rawByte, ok := ipmiprotocol.CopyAuthTypeSupport1(resp); ok {
		authTypeStr = fmt.Sprintf("0x%02x", rawByte)
	}

	metadata := &protocol.IpmiServerInfo{
		Version:          &version,
		AuthType:         &authTypeStr,
		AuthCapabilities: authCapsToFern(caps),
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeIpmi,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Ipmi: metadata},
	}, nil
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
