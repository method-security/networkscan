package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type TriStationFingerprinter struct{}

func (TriStationFingerprinter) Name() string { return "tristation" }

func (TriStationFingerprinter) DefaultPorts() []int { return []int{1502} }

func (TriStationFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, []byte{0x01, 0x00, 0x00, 0x00}, 512)
	if err != nil {
		return nil, err
	}
	if !looksLikeTriStation(resp) {
		return nil, fmt.Errorf("not TriStation")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeUdp, "TriStation", "TriStation", map[string]string{"response": "udp-1502"}), nil
}

func looksLikeTriStation(resp []byte) bool {
	if len(resp) < 4 || len(resp) > 512 {
		return false
	}
	if resp[0] > 0x40 {
		return false
	}
	zeroes := 0
	for _, b := range resp {
		if b == 0x00 {
			zeroes++
		}
	}
	return zeroes < len(resp)
}
