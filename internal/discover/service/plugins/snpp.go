package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type SNPPFingerprinter struct{}

func (SNPPFingerprinter) Name() string        { return "snpp" }
func (SNPPFingerprinter) DefaultPorts() []int { return []int{444} }

// RFC 1861 HELP is available before any pager or message transaction.
func (SNPPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	r := bufio.NewReaderSize(io.LimitReader(conn, 32768), 4096)
	code, banner, err := readFTPReply(r)
	if err != nil {
		return nil, err
	}
	if code != 220 {
		return nil, fmt.Errorf("not SNPP: greeting %d", code)
	}
	if _, err = io.WriteString(conn, "HELP\r\n"); err != nil {
		return nil, err
	}
	// SNPP uses 214 lines followed by 250, unlike FTP multiline replies.
	var lines []string
	complete := false
	for i := 0; i < 64; i++ {
		line, err := readTCPDiscoveryLine(r)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(line, "250 ") {
			complete = true
			break
		}
		if !strings.HasPrefix(line, "214 ") {
			return nil, fmt.Errorf("invalid SNPP HELP reply")
		}
		lines = append(lines, line)
	}
	text := strings.Join(lines, "\n")
	upper := strings.ToUpper(banner + "\n" + text)
	if !complete || !(strings.Contains(upper, "SNPP") || (strings.Contains(upper, "PAGE") && strings.Contains(upper, "MESS") && strings.Contains(upper, "SEND"))) {
		return nil, fmt.Errorf("not SNPP")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeSnpp, "SNPP", banner, map[string]string{"banner": banner, "help": text}), nil
}
