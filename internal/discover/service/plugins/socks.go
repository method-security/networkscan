package plugins

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"github.com/Method-Security/networkscan/internal/protocol/socks"
)

type SOCKSFingerprinter struct{}

func (SOCKSFingerprinter) Name() string { return "socks" }

// 9050/9150 are Tor's SOCKS ports; 1080/1081 are the conventional proxy ports.
func (SOCKSFingerprinter) DefaultPorts() []int { return []int{1080, 1081, 9050, 9150} }

var socksAuthMethodNames = map[byte]string{
	socks.AuthNoAuth:           "NO_AUTH",
	socks.AuthGSSAPI:           "GSSAPI",
	socks.AuthUsernamePassword: "USERNAME_PASSWORD",
	socks.AuthNoAcceptable:     "NO_ACCEPTABLE_METHODS",
}

// Detect greets as SOCKS5 and validates the method-selection reply. Only the greeting is sent: a
// SOCKS4 probe would have to issue a real CONNECT, making the proxy dial out during discovery.
func (SOCKSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probe := socks.BuildSOCKS5Greeting([]byte{socks.AuthNoAuth})
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, probe, 2)
	if err != nil {
		return nil, err
	}
	if len(resp) < 2 || resp[0] != socks.Version5 {
		return nil, fmt.Errorf("not SOCKS")
	}

	method, err := socks.ParseSOCKS5ServerChoice(bytes.NewReader(resp))
	if err != nil {
		return nil, err
	}
	name, ok := socksAuthMethodNames[method]
	if !ok {
		return nil, fmt.Errorf("not SOCKS")
	}

	metadata := map[string]string{"auth_method": name}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeSocks, "SOCKS", "5", metadata), nil
}
