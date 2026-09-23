package plugins

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type VNCFingerprinter struct{}

func (VNCFingerprinter) Name() string        { return "VNC" }
func (VNCFingerprinter) DefaultPorts() []int { return []int{5900} }

// RFC 6143 section 7.1.1 identifies RFB before security negotiation.
func (VNCFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	var banner [12]byte
	if _, err = io.ReadFull(conn, banner[:]); err != nil {
		return nil, err
	}
	if string(banner[:4]) != "RFB " || banner[7] != '.' || banner[11] != '\n' {
		return nil, fmt.Errorf("not RFB")
	}
	for _, i := range []int{4, 5, 6, 8, 9, 10} {
		if banner[i] < '0' || banner[i] > '9' {
			return nil, fmt.Errorf("invalid RFB version")
		}
	}
	major, _ := strconv.Atoi(string(banner[4:7]))
	minor, _ := strconv.Atoi(string(banner[8:11]))
	if major != 3 || minor < 3 {
		return nil, fmt.Errorf("unsupported RFB version")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeVnc, "VNC", string(banner[4:11]), map[string]string{"banner": string(banner[:11])}), nil
}
