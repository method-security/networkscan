// Package plugins provides IKE (Internet Key Exchange) service fingerprinting
package plugins

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	ikeprotocol "github.com/Method-Security/networkscan/internal/protocol/ike"
)

type IKEFingerprinter struct{}

func (IKEFingerprinter) Name() string { return "ike" }

func (IKEFingerprinter) DefaultPorts() []int { return []int{500, 4500} }

func (IKEFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	conn, err := dialService(ctx, "udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if err := setServiceReadDeadline(conn, timeout); err != nil {
		return nil, err
	}

	if _, err := conn.Write(ikeprotocol.BuildIKEv2SAInitRequest()); err != nil {
		return nil, err
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	if n < 28 {
		return nil, fmt.Errorf("invalid IKE response size: %d", n)
	}

	response := buffer[:n]
	ikeHeader, err := ikeprotocol.ParseIKEHeader(response)
	if err != nil {
		return nil, err
	}

	if ikeHeader.NextPayload == 0 && ikeHeader.MajorVersion == 0 {
		return nil, fmt.Errorf("invalid IKE header")
	}

	vendorIDs, proposals := ikeprotocol.ParseIKEPayloads(response[28:n], ikeHeader.NextPayload)

	version := fmt.Sprintf("IKEv%d", ikeHeader.MajorVersion)
	initiatorSPI := hex.EncodeToString(ikeHeader.InitiatorSPI[:])
	responderSPI := hex.EncodeToString(ikeHeader.ResponderSPI[:])
	exchangeType := ikeprotocol.GetExchangeTypeName(ikeHeader.ExchangeType)
	flags := fmt.Sprintf("0x%02x", ikeHeader.Flags)
	messageID := fmt.Sprintf("%d", ikeHeader.MessageID)

	metadata := &protocol.IkeServerInfo{
		Version:      &version,
		InitiatorSpi: &initiatorSPI,
		ResponderSpi: &responderSPI,
		ExchangeType: &exchangeType,
		Flags:        &flags,
		MessageId:    &messageID,
	}

	if len(vendorIDs) > 0 {
		metadata.VendorIds = vendorIDs
	}
	if len(proposals.EncryptionAlgs) > 0 {
		metadata.EncryptionAlgorithms = ikeprotocol.MergeFernEncryptionAlgorithms(metadata.EncryptionAlgorithms, proposals.EncryptionAlgs)
	}
	if len(proposals.HashAlgs) > 0 {
		metadata.HashAlgorithms = ikeprotocol.MergeFernHashAlgorithms(metadata.HashAlgorithms, proposals.HashAlgs)
	}
	if len(proposals.AuthMethods) > 0 {
		metadata.AuthenticationMethods = ikeprotocol.MergeFernAuthenticationMethods(metadata.AuthenticationMethods, proposals.AuthMethods)
	}
	if len(proposals.DHGroups) > 0 {
		metadata.DhGroups = ikeprotocol.MergeFernDHGroups(metadata.DhGroups, proposals.DHGroups)
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeIke,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Ike: metadata},
	}

	return result, nil
}
