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

type XMPPFingerprinter struct{}

func (XMPPFingerprinter) Name() string { return "xmpp" }

func (XMPPFingerprinter) DefaultPorts() []int { return []int{5222, 5269} }

func (XMPPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probe := []byte("<?xml version='1.0'?><stream:stream to='" + host + "' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, probe, 4096)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !strings.Contains(text, "<stream:stream") || !strings.Contains(text, "jabber:") {
		return nil, fmt.Errorf("not XMPP")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "XMPP", "XMPP", map[string]string{"response": helpers.FirstLine(text)}), nil
}
