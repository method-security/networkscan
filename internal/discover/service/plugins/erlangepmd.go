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

type ErlangEPMDFingerprinter struct{}

func (ErlangEPMDFingerprinter) Name() string { return "erlang-epmd" }

func (ErlangEPMDFingerprinter) DefaultPorts() []int { return []int{4369} }

func (ErlangEPMDFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte{0x00, 0x01, 'n'}, 4096)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if len(resp) < 4 || !strings.Contains(text, "name ") {
		return nil, fmt.Errorf("not Erlang EPMD")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "Erlang EPMD", "EPMD", map[string]string{"names": strings.TrimSpace(text[4:])}), nil
}
