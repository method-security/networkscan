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

type TarantoolFingerprinter struct{}

func (TarantoolFingerprinter) Name() string { return "tarantool" }

func (TarantoolFingerprinter) DefaultPorts() []int { return []int{3301} }

func (TarantoolFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPReadBanner(ctx, ip, port, timeout, 256)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !strings.HasPrefix(text, "Tarantool ") || !strings.Contains(text, "(Binary)") {
		return nil, fmt.Errorf("not Tarantool")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "Tarantool", helpers.FirstLine(text), map[string]string{"banner": helpers.FirstLine(text)}), nil
}
