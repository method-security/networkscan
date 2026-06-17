package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type RTMPFingerprinter struct{}

func (RTMPFingerprinter) Name() string { return "rtmp" }

func (RTMPFingerprinter) DefaultPorts() []int { return []int{1935} }

func (RTMPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probe := make([]byte, 1537)
	probe[0] = 0x03
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, probe, 3073)
	if err != nil {
		return nil, err
	}
	if len(resp) < 1537 || resp[0] != 0x03 {
		return nil, fmt.Errorf("not RTMP")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeRtmp, "RTMP", "RTMP", map[string]string{"handshake": "s0s1"}), nil
}
