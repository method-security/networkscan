package plugins

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

var (
	ajpCping = []byte{0x12, 0x34, 0x00, 0x01, 0x0a}
	ajpCpong = []byte{0x41, 0x42, 0x00, 0x01, 0x09}
)

type AJP13Fingerprinter struct{}

func (AJP13Fingerprinter) Name() string { return "ajp13" }

func (AJP13Fingerprinter) DefaultPorts() []int { return []int{8009} }

func (AJP13Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, ajpCping, len(ajpCpong))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(resp, ajpCpong) {
		return nil, fmt.Errorf("not AJP13")
	}

	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeAjp13, "AJP13", "Apache Jserv Protocol v1.3", map[string]string{
		"probe": "cping",
		"state": "cpong",
	}), nil
}
