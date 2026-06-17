package plugins

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type BACnetFingerprinter struct{}

func (BACnetFingerprinter) Name() string { return "bacnet" }

func (BACnetFingerprinter) DefaultPorts() []int { return []int{47808} }

func (BACnetFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, []byte{0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08}, 1476)
	if err != nil {
		return nil, err
	}
	if len(resp) < 8 || resp[0] != 0x81 || (resp[1] != 0x0a && resp[1] != 0x0b) || !bytes.Contains(resp[4:], []byte{0x10, 0x00}) {
		return nil, fmt.Errorf("not BACnet/IP")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeUdp, common.ProtocolTypeBacnet, "BACnet/IP", "BACnet/IP", map[string]string{"response": "i-am"}), nil
}
