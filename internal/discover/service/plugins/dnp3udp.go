package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type DNP3UDPFingerprinter struct{}

func (DNP3UDPFingerprinter) Name() string { return "dnp3-udp" }

func (DNP3UDPFingerprinter) DefaultPorts() []int { return []int{20000} }

func (DNP3UDPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, buildDNP3LinkStatusRequest(), 292)
	if err != nil {
		return nil, err
	}
	if !validDNP3Frame(resp) {
		return nil, fmt.Errorf("not DNP3")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeUdp, common.ProtocolTypeDnp3, "DNP3", "DNP3", map[string]string{"response": "link-layer"}), nil
}
