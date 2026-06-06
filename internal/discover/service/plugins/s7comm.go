package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type S7CommFingerprinter struct{}

func (S7CommFingerprinter) Name() string { return "s7comm" }

func (S7CommFingerprinter) DefaultPorts() []int { return []int{102} }

func (S7CommFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probe := []byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02, 0xc0, 0x01, 0x0a}
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, probe, 256)
	if err != nil {
		return nil, err
	}
	if len(resp) < 7 || resp[0] != 0x03 || resp[1] != 0x00 || resp[5] != 0xd0 {
		return nil, fmt.Errorf("not S7comm")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "Siemens S7comm", "COTP/S7", map[string]string{"cotp": "connection-confirm"}), nil
}
