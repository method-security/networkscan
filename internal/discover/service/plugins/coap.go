package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type CoAPFingerprinter struct{}

func (CoAPFingerprinter) Name() string { return "coap" }

func (CoAPFingerprinter) DefaultPorts() []int { return []int{5683} }

func (CoAPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, []byte{0x40, 0x01, 0x12, 0x34, 0xbb, '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n', 0x04, 'c', 'o', 'r', 'e'}, 1500)
	if err != nil {
		return nil, err
	}
	if len(resp) < 4 || resp[0]>>6 != 1 || resp[2] != 0x12 || resp[3] != 0x34 || resp[1] == 0x00 {
		return nil, fmt.Errorf("not CoAP")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeUdp, "CoAP", fmt.Sprintf("code-%d.%02d", resp[1]>>5, resp[1]&0x1f), map[string]string{"message_id": "0x1234"}), nil
}
