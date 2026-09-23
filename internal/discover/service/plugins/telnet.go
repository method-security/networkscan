package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type TelnetFingerprinter struct{}

func (TelnetFingerprinter) Name() string        { return "telnet" }
func (TelnetFingerprinter) DefaultPorts() []int { return []int{23} }

// RFC 854: request suppress-go-ahead and require a complete option negotiation.
func (TelnetFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if _, err = conn.Write([]byte{255, 253, 3}); err != nil {
		return nil, err
	}
	r := bufio.NewReader(io.LimitReader(conn, 8192))
	var banner strings.Builder
	for i := 0; i < 4096; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b != 255 {
			if b >= 32 || b == '\r' || b == '\n' {
				banner.WriteByte(b)
			}
			continue
		}
		command, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if command == 255 {
			continue
		}
		if command >= 251 && command <= 254 {
			option, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeTelnet, "TELNET", "", map[string]string{"serverData": strings.TrimSpace(banner.String()), "command": strconv.Itoa(int(command)), "option": strconv.Itoa(int(option))}), nil
		}
		if command == 250 {
			// Subnegotiations are bounded by the same total reader budget.
			for {
				b, err = r.ReadByte()
				if err != nil {
					return nil, err
				}
				if b == 255 {
					b, err = r.ReadByte()
					if err != nil {
						return nil, err
					}
					if b == 240 {
						break
					}
					if b != 255 {
						return nil, fmt.Errorf("invalid Telnet subnegotiation")
					}
				}
			}
		} else if command < 241 || command > 249 {
			return nil, fmt.Errorf("invalid Telnet command")
		}
	}
	return nil, fmt.Errorf("no Telnet negotiation")
}
