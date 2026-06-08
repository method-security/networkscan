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

type NATSFingerprinter struct{}

func (NATSFingerprinter) Name() string { return "nats" }

func (NATSFingerprinter) DefaultPorts() []int { return []int{4222} }

func (NATSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPReadBanner(ctx, ip, port, timeout, 4096)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !strings.HasPrefix(text, "INFO ") || !strings.Contains(text, "server_id") {
		return nil, fmt.Errorf("not NATS")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "NATS", "NATS", map[string]string{"banner": strings.TrimSpace(text)}), nil
}
