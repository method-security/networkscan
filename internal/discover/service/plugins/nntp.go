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

type NNTPFingerprinter struct{}

func (NNTPFingerprinter) Name() string { return "nntp" }

func (NNTPFingerprinter) DefaultPorts() []int { return []int{119, 563} }

func (NNTPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPReadBanner(ctx, ip, port, timeout, 512)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !(strings.HasPrefix(text, "200 ") || strings.HasPrefix(text, "201 ")) || !strings.Contains(strings.ToUpper(text), "NNTP") {
		return nil, fmt.Errorf("not NNTP")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeNntp, "NNTP", "NNTP", map[string]string{"banner": strings.TrimSpace(text)}), nil
}
