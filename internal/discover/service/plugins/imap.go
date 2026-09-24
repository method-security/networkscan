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
	imapwire "github.com/Method-Security/networkscan/internal/protocol/imap"
)

type IMAPFingerprinter struct{}
type IMAPTLSFingerprinter struct{}

func (IMAPFingerprinter) Name() string           { return "imap" }
func (IMAPFingerprinter) DefaultPorts() []int    { return []int{143} }
func (IMAPTLSFingerprinter) Name() string        { return "imaps" }
func (IMAPTLSFingerprinter) DefaultPorts() []int { return []int{993} }
func (IMAPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeIMAP(ctx, ip, port, host, timeout, false)
}
func (IMAPTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeIMAP(ctx, ip, port, host, timeout, true)
}

// CAPABILITY is valid in both unauthenticated and PREAUTH states (RFC 9051).
func detectNativeIMAP(ctx context.Context, ip net.IP, port int, host string, timeout int, secure bool) (*discover.ServiceDetails, error) {
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
	upper := strings.ToUpper(banner)
	if !strings.HasPrefix(upper, "* OK ") && !strings.HasPrefix(upper, "* PREAUTH ") {
		return nil, fmt.Errorf("not IMAP")
	}
	if _, err = io.WriteString(conn, "NS01 CAPABILITY\r\n"); err != nil {
		return nil, err
	}
	var capabilities []string
	for i := 0; i < 128; i++ {
		line, err := readTCPDiscoveryLine(r)
		if err != nil {
			return nil, err
		}
		upper = strings.ToUpper(line)
		if strings.HasPrefix(upper, "* CAPABILITY ") {
			capabilities = imapwire.ParseCapabilities(line)
		}
		if strings.HasPrefix(upper, "NS01 ") {
			if !strings.HasPrefix(upper, "NS01 OK ") {
				return nil, fmt.Errorf("IMAP CAPABILITY rejected")
			}
			valid := false
			var auth []string
			for _, cap := range capabilities {
				if strings.EqualFold(cap, "IMAP4REV1") || strings.EqualFold(cap, "IMAP4REV2") || strings.EqualFold(cap, "IMAP4") {
					valid = true
				}
				if strings.HasPrefix(strings.ToUpper(cap), "AUTH=") {
					auth = append(auth, cap[5:])
				}
			}
			if !valid {
				return nil, fmt.Errorf("missing IMAP capability")
			}
			protocol, app := common.ProtocolTypeImap, "IMAP"
			if secure {
				protocol, app = common.ProtocolTypeImaps, "IMAPS"
			}
			result := helpers.GenericResult(host, ip, port, common.TransportTypeTcp, protocol, app, "", map[string]string{"banner": banner, "capabilities": strings.Join(capabilities, " "), "authMethods": strings.Join(auth, " ")})
			result.Tls = &secure
			return result, nil
		}
		if !strings.HasPrefix(line, "* ") || strings.HasPrefix(upper, "* BYE ") {
			return nil, fmt.Errorf("invalid IMAP response")
		}
	}
	return nil, fmt.Errorf("IMAP response exceeds limit")
}
