package helpers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"

	"github.com/Method-Security/networkscan/generated/go/common"
)

type Endpoint struct {
	Address netip.AddrPort
	Host    string
	Context context.Context
}

func Ports(matches func(uint16) bool) []int {
	var ports []int
	for port := 1; port <= 65535; port++ {
		if matches(uint16(port)) {
			ports = append(ports, port)
		}
	}
	return ports
}

func ConnectService(ctx context.Context, ip net.IP, port int, host string, timeout int, transport common.TransportType) (net.Conn, Endpoint, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || port < 1 || port > 65535 {
		return nil, Endpoint{}, fmt.Errorf("invalid service endpoint")
	}
	endpoint := Endpoint{Address: netip.AddrPortFrom(addr.Unmap(), uint16(port)), Host: host, Context: ctx}
	network := "tcp"
	if transport == common.TransportTypeUdp {
		network = "udp"
	}
	conn, err := Dial(ctx, network, endpoint.Address.String(), timeout)
	if err != nil {
		return nil, endpoint, err
	}
	if transport == common.TransportTypeTcptls {
		secure, err := UpgradeTLS(ctx, conn, host)
		if err != nil {
			_ = conn.Close()
			return nil, endpoint, err
		}
		conn = secure
	}
	return conn, endpoint, nil
}

func UpgradeTLS(ctx context.Context, conn net.Conn, host string) (net.Conn, error) {
	secure := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return secure, nil
}
