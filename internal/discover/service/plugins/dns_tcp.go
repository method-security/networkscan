package plugins

import (
	"context"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"github.com/miekg/dns"
)

type DNSTCPFingerprinter struct{}

func (DNSTCPFingerprinter) Name() string        { return "dns-tcp" }
func (DNSTCPFingerprinter) DefaultPorts() []int { return []int{53} }
func (DNSTCPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	return detectDNS(ctx, &dns.Client{Net: "tcp", Timeout: helpers.Timeout(timeout)}, ip, port, host, common.TransportTypeTcp, nil)
}
