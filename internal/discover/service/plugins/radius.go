package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type RADIUSFingerprinter struct{}

func (RADIUSFingerprinter) Name() string { return "radius" }

func (RADIUSFingerprinter) DefaultPorts() []int { return []int{1812} }

func (RADIUSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probe := make([]byte, 20)
	probe[0] = 1
	probe[1] = 0x42
	binary.BigEndian.PutUint16(probe[2:4], uint16(len(probe)))
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, probe, 4096)
	if err != nil {
		return nil, err
	}
	if len(resp) < 20 || resp[1] != 0x42 || (resp[0] != 2 && resp[0] != 3 && resp[0] != 11) || int(binary.BigEndian.Uint16(resp[2:4])) > len(resp) {
		return nil, fmt.Errorf("not RADIUS")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeUdp, "RADIUS", fmt.Sprintf("code-%d", resp[0]), map[string]string{"identifier": "0x42"}), nil
}
