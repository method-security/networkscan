package ike

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	ikefern "github.com/Method-Security/networkscan/generated/go/enumerate/ike"
	ikeprotocol "github.com/Method-Security/networkscan/internal/protocol/ike"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateIKE implements NetworkApplicationLibrary for IKE enumeration.
type LibraryEnumerateIKE struct{}

// EnumerateTarget Overview:
// 1. Parse target host:port
// 2. Probe with IKEv2 SA_INIT → detect IKEv2 support, extract SA proposals and vendor IDs
// 3. Probe with IKEv1 Aggressive Mode → detect IKEv1 and Aggressive Mode support
// 4. If target port is not 4500, probe UDP 4500 → detect NAT-T capability
// 5. Analyze vendor IDs for DPD support and vendor identification
// 6. Scan SA proposals for weak algorithms
func (l *LibraryEnumerateIKE) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	var serverInfo commonprotocolfern.IkeServerInfo
	var details ikefern.EnumerateIkeDetails
	errors := []string{}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target %q: %v", target, err))
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateIkeDetails(&details), errors
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid port in target %q: %v", target, err))
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateIkeDetails(&details), errors
	}
	details.Target = host
	details.Port = port
	// IKEv2 probe
	ikev2Response, err := probeUDP(ctx, target, ikeprotocol.BuildIKEv2SAInitRequest())
	if err != nil {
		errors = append(errors, fmt.Sprintf("IKEv2 probe failed on %s: %v", target, err))
		log.Warn("IKEv2 probe failed", svc1log.SafeParam("target", target), svc1log.SafeParam("error", err))
	} else if len(ikev2Response) >= 28 {
		ikev2 := true
		serverInfo.Ikev2Supported = &ikev2
		log.Info("IKEv2 response received", svc1log.SafeParam("target", target))
		if header, parseErr := ikeprotocol.ParseIKEHeader(ikev2Response); parseErr == nil {
			version := fmt.Sprintf("IKEv%d", header.MajorVersion)
			initiatorSPI := hex.EncodeToString(header.InitiatorSPI[:])
			responderSPI := hex.EncodeToString(header.ResponderSPI[:])
			exchangeType := ikeprotocol.GetExchangeTypeName(header.ExchangeType)
			flags := fmt.Sprintf("0x%02x", header.Flags)
			messageID := fmt.Sprintf("%d", header.MessageID)
			serverInfo.Version = &version
			serverInfo.InitiatorSpi = &initiatorSPI
			serverInfo.ResponderSpi = &responderSPI
			serverInfo.ExchangeType = &exchangeType
			serverInfo.Flags = &flags
			serverInfo.MessageId = &messageID
			vendorIDs, proposals := ikeprotocol.ParseIKEPayloads(ikev2Response[28:], header.NextPayload)
			serverInfo.VendorIds = vendorIDs
			serverInfo.EncryptionAlgorithms = proposals.EncryptionAlgs
			serverInfo.HashAlgorithms = proposals.HashAlgs
			serverInfo.AuthenticationMethods = proposals.AuthMethods
			serverInfo.DhGroups = proposals.DHGroups
		}
	}
	// IKEv1 Aggressive Mode probe
	amResponse, err := probeUDP(ctx, target, buildIKEv1AggressiveModeProbe())
	if err != nil {
		errors = append(errors, fmt.Sprintf("IKEv1 AM probe failed on %s: %v", target, err))
		log.Warn("IKEv1 AM probe failed", svc1log.SafeParam("target", target), svc1log.SafeParam("error", err))
	} else if len(amResponse) >= 28 {
		aggressiveMode, ikev1 := isIKEv1AggressiveResponse(amResponse)
		serverInfo.AggressiveModeEnabled = &aggressiveMode
		serverInfo.Ikev1Supported = &ikev1
		log.Info("IKEv1 AM probe response",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("aggressiveMode", aggressiveMode),
			svc1log.SafeParam("ikev1", ikev1))
	}
	// NAT-T probe on UDP 4500 (only if not already probing 4500)
	if portStr != "4500" {
		natTarget := net.JoinHostPort(host, "4500")
		_, natErr := probeUDP(ctx, natTarget, ikeprotocol.BuildIKEv2SAInitRequest())
		if natErr == nil {
			natT := true
			serverInfo.NatTraversalSupported = &natT
			log.Info("NAT-T port 4500 responded", svc1log.SafeParam("host", host))
		}
	}
	// Vendor ID analysis
	if len(serverInfo.VendorIds) > 0 {
		dpd := checkDPDSupport(serverInfo.VendorIds)
		serverInfo.DeadPeerDetectionSupported = &dpd
		serverInfo.VendorIdentification = extractVendorIdentification(serverInfo.VendorIds)
	}
	// Weak algorithm detection
	serverInfo.WeakAlgorithmsDetected = detectWeakAlgorithms(
		serverInfo.EncryptionAlgorithms,
		serverInfo.HashAlgorithms,
		serverInfo.DhGroups,
	)
	details.ServerInfo = &serverInfo
	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateIkeDetails(&details), errors
}
