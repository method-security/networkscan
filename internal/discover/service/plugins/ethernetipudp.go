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
	product, ok := parseEthernetIPIdentity(resp)
	if !ok {
		return nil, fmt.Errorf("not EtherNet/IP")
	}
	lower := strings.ToLower(product)
	if strings.Contains(lower, "unitronics") || strings.Contains(lower, "unistream") {
		return nil, fmt.Errorf("unitronics-specific EtherNet/IP")
	}
	meta := map[string]string{"command": "list-identity"}
	if product != "" {
		meta["identity"] = product
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeUdp, "EtherNet/IP", "CIP", meta), nil
}
