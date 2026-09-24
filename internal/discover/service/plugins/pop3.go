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
	popwire "github.com/Method-Security/networkscan/internal/protocol/pop3"
)

type POP3Fingerprinter struct{}
type POP3TLSFingerprinter struct{}

func (POP3Fingerprinter) Name() string           { return "pop3" }
func (POP3Fingerprinter) DefaultPorts() []int    { return []int{110} }
func (POP3TLSFingerprinter) Name() string        { return "pop3s" }
func (POP3TLSFingerprinter) DefaultPorts() []int { return []int{995} }
func (POP3Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativePOP3(ctx, ip, port, host, timeout, false)
}
func (POP3TLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativePOP3(ctx, ip, port, host, timeout, true)
}

// RFC 1939 and RFC 2449: discover extensions without entering authentication.
func detectNativePOP3(ctx context.Context, ip net.IP, port int, host string, timeout int, secure bool) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if secure {
		tlsConn, err := helpers.UpgradeTLS(ctx, conn, host)
		if err != nil {
			return nil, err
		}
		conn = tlsConn
	}
	r := bufio.NewReaderSize(io.LimitReader(conn, 65536), 4096)
	banner, err := readTCPDiscoveryLine(r)
	if err != nil {
		return nil, err
	}
	if banner != "+OK" && !strings.HasPrefix(banner, "+OK ") {
		return nil, fmt.Errorf("not POP3")
	}
	if _, err = io.WriteString(conn, "CAPA\r\n"); err != nil {
		return nil, err
	}
	status, err := readTCPDiscoveryLine(r)
	if err != nil {
		return nil, err
	}
	var lines []string
	if status == "+OK" || strings.HasPrefix(status, "+OK ") {
		complete := false
		for i := 0; i < 128; i++ {
			line, err := readTCPDiscoveryLine(r)
			if err != nil {
				return nil, err
			}
			if line == "." {
				complete = true
				break
			}
			if strings.HasPrefix(line, "..") {
				line = line[1:]
			}
			if line == "" {
				return nil, fmt.Errorf("empty POP3 capability")
			}
			lines = append(lines, line)
		}
		if !complete {
			return nil, fmt.Errorf("POP3 capabilities exceed limit")
		}
	} else if status != "-ERR" && !strings.HasPrefix(status, "-ERR ") {
		return nil, fmt.Errorf("invalid POP3 CAPA response")
	}
	caps, auth, implementation, _, _ := popwire.ParseCapabilities(lines)
	meta := map[string]string{"banner": banner, "capabilities": strings.Join(caps, "\n"), "authMethods": strings.Join(auth, " ")}
	if timestamp, ok := popwire.ExtractApopTimestamp(banner); ok {
		meta["apopTimestamp"] = timestamp
	}
	if implementation != "" {
		meta["implementation"] = implementation
	}
	protocol, app := common.ProtocolTypePop3, "POP3"
	if secure {
		protocol, app = common.ProtocolTypePop3S, "POP3S"
	}
	result := helpers.GenericResult(host, ip, port, common.TransportTypeTcp, protocol, app, implementation, meta)
	result.Tls = &secure
	return result, nil
}
