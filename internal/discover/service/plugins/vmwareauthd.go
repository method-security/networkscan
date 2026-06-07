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

type VMwareAuthdFingerprinter struct{}

func (VMwareAuthdFingerprinter) Name() string { return "vmware-authd" }

func (VMwareAuthdFingerprinter) DefaultPorts() []int { return []int{902} }

func (VMwareAuthdFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPReadBanner(ctx, ip, port, timeout, 1024)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !strings.HasPrefix(text, "220 VMware Authentication Daemon") {
		return nil, fmt.Errorf("not VMware authd")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "VMware Authentication Daemon", "VMware authd", map[string]string{"banner": strings.TrimSpace(text)}), nil
}
