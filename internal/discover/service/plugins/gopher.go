package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type GopherFingerprinter struct{}

func (GopherFingerprinter) Name() string { return "gopher" }

func (GopherFingerprinter) DefaultPorts() []int { return []int{70} }

func (GopherFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte("\r\n"), 4096)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !helpers.ValidGopherItem(text) {
		return nil, fmt.Errorf("not Gopher")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "Gopher", "Gopher", map[string]string{"first_item": helpers.FirstLine(text)}), nil
}
