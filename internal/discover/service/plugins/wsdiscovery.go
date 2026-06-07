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

type WSDiscoveryFingerprinter struct{}

func (WSDiscoveryFingerprinter) Name() string { return "ws-discovery" }

func (WSDiscoveryFingerprinter) DefaultPorts() []int { return []int{3702} }

func (WSDiscoveryFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probe := []byte(`<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><e:Header><w:MessageID>uuid:00000000-0000-0000-0000-000000000001</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe/></e:Body></e:Envelope>`)
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, probe, 8192)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !strings.Contains(text, "ProbeMatches") && !strings.Contains(text, "schemas.xmlsoap.org/ws/2005/04/discovery") {
		return nil, fmt.Errorf("not WS-Discovery")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeUdp, "WS-Discovery", "WS-Discovery", map[string]string{"response": helpers.FirstLine(text)}), nil
}
