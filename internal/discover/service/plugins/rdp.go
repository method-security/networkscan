package plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Azure/go-ntlmssp"
	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	ntlmutil "github.com/Method-Security/networkscan/internal/common/ntlm"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	rdpwire "github.com/Method-Security/networkscan/internal/protocol/rdp"
	"github.com/rbetts/go-ntlm/ntlm/messages"
)

type RDPFingerprinter struct{}
type RDPTLSFingerprinter struct{}

func (RDPFingerprinter) Name() string           { return "rdp" }
func (RDPFingerprinter) DefaultPorts() []int    { return []int{3389} }
func (RDPTLSFingerprinter) Name() string        { return "rdp" }
func (RDPTLSFingerprinter) DefaultPorts() []int { return []int{3389} }
func (RDPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeRDP(ctx, ip, port, host, timeout, false)
}
func (RDPTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeRDP(ctx, ip, port, host, timeout, true)
}

func detectNativeRDP(ctx context.Context, ip net.IP, port int, host string, timeout int, secure bool) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	requested := rdpwire.ProtocolRDP
	if secure {
		requested = rdpwire.RequestAllProtocols
	}
	if err = rdpwire.WriteX224ConnectionRequest(conn, "", requested); err != nil {
		return nil, err
	}
	// The negotiation confirm fits in a single 19-byte TPKT. Validate the
	// RFC 1006 header before delegating parsing to our protocol package.
	var header [4]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 3 || header[1] != 0 || binary.BigEndian.Uint16(header[2:]) != 19 {
		return nil, fmt.Errorf("invalid RDP negotiation frame")
	}
	cc, err := rdpwire.ReadX224ConnectionConfirm(io.MultiReader(bytes.NewReader(header[:]), io.LimitReader(conn, 15)))
	if err != nil {
		return nil, err
	}
	pdu := cc.RawPDU
	if len(pdu) != 15 || pdu[0] != 14 || pdu[2] != 0 || pdu[3] != 0 || pdu[6] != 0 || binary.LittleEndian.Uint16(pdu[9:11]) != 8 {
		return nil, fmt.Errorf("invalid RDP connection confirm")
	}
	meta := map[string]string{}
	if cc.NegFailureReceived {
		if secure || cc.FailureCode < 1 || cc.FailureCode > 6 || pdu[8] != 0 {
			return nil, fmt.Errorf("RDP negotiation failed")
		}
		meta["negotiationFailure"] = strconv.FormatUint(uint64(cc.FailureCode), 10)
		secure = false
	} else {
		if !cc.NegResponseReceived {
			return nil, fmt.Errorf("missing RDP negotiation response")
		}
		selected := cc.SelectedProtocol
		if (!secure && selected != 0) || (secure && selected != 1 && selected != 2 && selected != 8) {
			return nil, fmt.Errorf("unoffered RDP security protocol")
		}
		meta["selectedProtocol"] = strconv.FormatUint(uint64(selected), 10)
		meta["negotiationFlags"] = strconv.Itoa(int(cc.NegFlags))
		if secure {
			upgraded, err := helpers.UpgradeTLS(ctx, conn, host)
			if err != nil {
				return nil, err
			}
			state := upgraded.(*tls.Conn).ConnectionState()
			meta["tlsVersion"] = tls.VersionName(state.Version)
			if len(state.PeerCertificates) > 0 {
				meta["certificateSubject"] = state.PeerCertificates[0].Subject.String()
			}
			if selected == rdpwire.ProtocolHybrid || selected == rdpwire.ProtocolHybridEx {
				// Enrichment is optional once RDP and TLS are confirmed. Send only
				// Type 1 and read Type 2; no credentials or Type 3 are ever sent.
				if info, err := readRDPCredSSPInfo(upgraded); err == nil {
					for key, value := range info {
						meta[key] = value
					}
				}
			}
		}
	}
	result := helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeRdp, "RDP", "", meta)
	result.Tls = &secure
	return result, nil
}

// TSRequest and NegoData are specified by MS-CSSP sections 2.2.1/2.2.1.1.
type rdpDiscoveryToken struct {
	Token []byte `asn1:"explicit,tag:0"`
}
type rdpDiscoveryRequest struct {
	Version    int                 `asn1:"explicit,tag:0"`
	Tokens     []rdpDiscoveryToken `asn1:"optional,explicit,tag:1"`
	AuthInfo   []byte              `asn1:"optional,explicit,tag:2"`
	PubKeyAuth []byte              `asn1:"optional,explicit,tag:3"`
	ErrorCode  int64               `asn1:"optional,explicit,tag:4"`
	Nonce      []byte              `asn1:"optional,explicit,tag:5"`
}

func readRDPCredSSPInfo(conn net.Conn) (map[string]string, error) {
	negotiate, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		return nil, err
	}
	request, err := asn1.Marshal(rdpDiscoveryRequest{Version: 6, Tokens: []rdpDiscoveryToken{{Token: negotiate}}})
	if err != nil {
		return nil, err
	}
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	response, err := readRDPDiscoveryDER(conn)
	if err != nil {
		return nil, err
	}
	var decoded rdpDiscoveryRequest
	rest, err := asn1.Unmarshal(response, &decoded)
	if err != nil || len(rest) != 0 || decoded.Version < 2 || decoded.ErrorCode != 0 || len(decoded.Tokens) != 1 {
		return nil, fmt.Errorf("invalid CredSSP challenge")
	}
	token := decoded.Tokens[0].Token
	if !bytes.HasPrefix(token, []byte("NTLMSSP\x00")) {
		// RFC 4178 NegTokenResp can wrap the NTLM response token.
		var wrapped struct {
			State     asn1.Enumerated       `asn1:"optional,explicit,tag:0"`
			Mechanism asn1.ObjectIdentifier `asn1:"optional,explicit,tag:1"`
			Response  []byte                `asn1:"optional,explicit,tag:2"`
			MIC       []byte                `asn1:"optional,explicit,tag:3"`
		}
		rest, err = asn1.UnmarshalWithParams(token, &wrapped, "explicit,tag:1")
		if err != nil || len(rest) != 0 {
			return nil, fmt.Errorf("invalid SPNEGO response")
		}
		token = wrapped.Response
	}
	return parseRDPDiscoveryChallenge(token)
}

func readRDPDiscoveryDER(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:2]); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, fmt.Errorf("expected CredSSP sequence")
	}
	headerLen, size := 2, int(header[1])
	if size >= 128 {
		n := size & 127
		if n < 1 || n > 2 {
			return nil, fmt.Errorf("CredSSP length exceeds limit")
		}
		if _, err := io.ReadFull(r, header[2:2+n]); err != nil {
			return nil, err
		}
		headerLen += n
		size = 0
		for _, b := range header[2:headerLen] {
			size = size*256 + int(b)
		}
	}
	if size > 16384 {
		return nil, fmt.Errorf("CredSSP message exceeds limit")
	}
	packet := make([]byte, headerLen+size)
	copy(packet, header[:headerLen])
	_, err := io.ReadFull(r, packet[headerLen:])
	return packet, err
}

func parseRDPDiscoveryChallenge(token []byte) (map[string]string, error) {
	// The established NTLM parser assumes valid security-buffer and AV-pair
	// bounds. Validate those before passing it any network-controlled bytes.
	if len(token) < 48 || !bytes.Equal(token[:8], []byte("NTLMSSP\x00")) || binary.LittleEndian.Uint32(token[8:12]) != 2 {
		return nil, fmt.Errorf("invalid NTLM challenge")
	}
	minimum := 48
	if binary.LittleEndian.Uint32(token[20:24])&0x02000000 != 0 {
		minimum = 56
	}
	if len(token) < minimum {
		return nil, fmt.Errorf("truncated NTLM version")
	}
	var targetInfo []byte
	for _, offset := range []int{12, 40} {
		length := uint64(binary.LittleEndian.Uint16(token[offset:]))
		start := uint64(binary.LittleEndian.Uint32(token[offset+4:]))
		if length == 0 {
			continue
		}
		if start < uint64(minimum) || start+length > uint64(len(token)) || (offset == 12 && length%2 != 0) {
			return nil, fmt.Errorf("invalid NTLM security buffer")
		}
		if offset == 40 {
			targetInfo = token[start : start+length]
		}
	}
	if len(targetInfo) > 0 {
		remaining := targetInfo
		terminated := false
		for len(remaining) >= 4 {
			id, size := binary.LittleEndian.Uint16(remaining), int(binary.LittleEndian.Uint16(remaining[2:]))
			remaining = remaining[4:]
			if size > len(remaining) || (id >= 1 && id <= 5 && size%2 != 0) {
				return nil, fmt.Errorf("invalid NTLM AV pair")
			}
			if id == 0 {
				if size != 0 || len(remaining) != 0 {
					return nil, fmt.Errorf("invalid NTLM AV terminator")
				}
				terminated = true
				break
			}
			remaining = remaining[size:]
		}
		if !terminated {
			return nil, fmt.Errorf("unterminated NTLM AV pairs")
		}
	}
	challenge, err := messages.ParseChallengeMessage(token)
	if err != nil {
		return nil, err
	}
	meta := map[string]string{}
	if challenge.TargetName != nil {
		if name := challenge.TargetName.String(); name != "" {
			meta["targetName"] = name
		}
	}
	for key, id := range map[string]messages.AvPairType{"netBIOSComputerName": messages.MsvAvNbComputerName, "netBIOSDomainName": messages.MsvAvNbDomainName, "dnsComputerName": messages.MsvAvDnsComputerName, "dnsDomainName": messages.MsvAvDnsDomainName, "forestName": messages.MsvAvDnsTreeName} {
		if challenge.TargetInfo != nil {
			if value := challenge.TargetInfo.StringValue(id); value != "" {
				meta[key] = value
			}
		}
	}
	if version := challenge.Version; version != nil {
		meta["osVersion"] = fmt.Sprintf("%d.%d.%d", version.ProductMajorVersion, version.ProductMinorVersion, version.ProductBuild)
		if mapped, ok := ntlmutil.WindowsBuildMapping[strconv.Itoa(int(version.ProductBuild))]; ok {
			meta["mappedOsVersion"] = mapped
			meta["fingerprint"] = mapped
		}
	}
	return meta, nil
}
