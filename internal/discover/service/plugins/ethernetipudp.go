package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type EthernetIPUDPFingerprinter struct{}

func (EthernetIPUDPFingerprinter) Name() string { return "ethernetip-udp" }

func (EthernetIPUDPFingerprinter) DefaultPorts() []int { return []int{44818} }

func (EthernetIPUDPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, ethernetIPListIdentityRequest(), 1024)
	if err != nil {
		return nil, err
	}
	info, ok := parseEthernetIPIdentity(resp)
	if !ok {
		return nil, fmt.Errorf("not EtherNet/IP")
	}

	// Gate: if this is a Unitronics device, let the UniStream-specific fingerprinter own it.
	// (UniStream runs first in plugin order; we'd be re-processing if we didn't gate here.)
	vendorIDIsUnitronics := info.VendorId != nil && *info.VendorId == 318
	productNameIsUnitronics := false
	if info.ProductName != nil {
		lower := strings.ToLower(*info.ProductName)
		productNameIsUnitronics = strings.Contains(lower, "unitronics") || strings.Contains(lower, "unistream")
	}
	if vendorIDIsUnitronics || productNameIsUnitronics {
		return nil, fmt.Errorf("unitronics-specific EtherNet/IP")
	}

	// Determine version string
	version := new(string)
	if info.ProductName != nil && *info.ProductName != "" {
		*version = *info.ProductName
	} else {
		*version = "EtherNet/IP"
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeEthernetip,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Ethernetip: info},
	}, nil
}
