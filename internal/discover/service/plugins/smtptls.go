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
	smtpwire "github.com/Method-Security/networkscan/internal/protocol/smtp"
)

type SMTPTLSFingerprinter struct{}

func (SMTPTLSFingerprinter) Name() string        { return "smtps" }
func (SMTPTLSFingerprinter) DefaultPorts() []int { return []int{465} }

// Implicit TLS submission (RFC 8314), with RFC 5321 EHLO capability discovery.
func (SMTPTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	tlsConn, err := helpers.UpgradeTLS(ctx, conn, host)
	if err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(io.LimitReader(tlsConn, 65536), 4096)
	code, banner, err := readSMTPReply(r)
	if err != nil {
		return nil, err
	}
	if code != 220 {
		return nil, fmt.Errorf("not SMTPS")
	}
	if _, err = io.WriteString(tlsConn, "EHLO scanner.local\r\n"); err != nil {
		return nil, err
	}
	code, response, err := readSMTPReply(r)
	if err != nil {
		return nil, err
	}
	if code != 250 {
		if code != 500 && code != 502 && code != 504 {
			return nil, fmt.Errorf("SMTP EHLO rejected")
		}
		if _, err = io.WriteString(tlsConn, "HELO scanner.local\r\n"); err != nil {
			return nil, err
		}
		code, response, err = readSMTPReply(r)
		if err != nil || code != 250 {
			return nil, fmt.Errorf("SMTP HELO failed: %v", err)
		}
	}
	var auth, extensions []string
	for i, line := range strings.Split(response, "\n") {
		if i == 0 || len(line) < 4 {
			continue
		}
		ext := line[4:]
		extensions = append(extensions, ext)
		if strings.HasPrefix(strings.ToUpper(ext), "AUTH ") || strings.HasPrefix(strings.ToUpper(ext), "AUTH=") {
			auth = append(auth, strings.Fields(ext[5:])...)
		}
	}
	server, software, version := smtpwire.ParseBanner(helpers.FirstLine(banner))
	meta := map[string]string{"banner": banner, "authMethods": fmt.Sprint(auth), "extensions": strings.Join(extensions, "\n"), "serverName": server, "softwareName": software}
	result := helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeSmtps, "SMTPS", strings.TrimSpace(software+" "+version), meta)
	secure := true
	result.Tls = &secure
	return result, nil
}
