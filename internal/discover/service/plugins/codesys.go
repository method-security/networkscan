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

type CodesysFingerprinter struct{}

func (CodesysFingerprinter) Name() string { return "codesys" }

func (CodesysFingerprinter) DefaultPorts() []int {
	return []int{1200, 1210, 1211, 1217, 1740, 1741, 1742, 1743, 11740}
}

func (CodesysFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte{0xbb, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x01}, 512)
	if err != nil {
		resp, err = helpers.TCPExchange(ctx, ip, port, timeout, []byte{0xbb, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x01}, 512)
		if err != nil {
			return nil, err
		}
	}
	if len(resp) < 2 || resp[0] != 0xbb {
		return nil, fmt.Errorf("not CODESYS")
	}
	meta := map[string]string{"response": "v2-identification"}
	if len(resp) > 129 {
		osEnd := 96
		if len(resp) < osEnd {
			osEnd = len(resp)
		}
		productEnd := 160
		if len(resp) < productEnd {
			productEnd = len(resp)
		}
		osName := strings.TrimRight(string(resp[64:osEnd]), "\x00")
		product := strings.TrimRight(string(resp[128:productEnd]), "\x00")
		if osName != "" {
			meta["os"] = strings.TrimSpace(osName)
		}
		if product != "" {
			meta["product"] = strings.TrimSpace(product)
		}
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "CODESYS", "CODESYS V2", meta), nil
}
