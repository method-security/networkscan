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

type FTPFingerprinter struct{}

func (FTPFingerprinter) Name() string        { return "ftp" }
func (FTPFingerprinter) DefaultPorts() []int { return []int{21} }

// RFC 959 section 4.2 permits arbitrary intermediate lines in multiline replies.
// The reader has a fixed line bound; callers also limit the entire exchange.
func readFTPReply(r *bufio.Reader) (int, string, error) {
	line, err := readTCPDiscoveryLine(r)
	if err != nil {
		return 0, "", err
	}
	if len(line) < 4 || line[0] < '1' || line[0] > '5' || line[1] < '0' || line[1] > '9' || line[2] < '0' || line[2] > '9' || (line[3] != ' ' && line[3] != '-') {
		return 0, "", fmt.Errorf("invalid numeric reply")
	}
	code, _ := strconv.Atoi(line[:3])
	lines := []string{line}
	if line[3] == '-' {
		end := line[:3] + " "
		for i := 0; i < 128; i++ {
			line, err = readTCPDiscoveryLine(r)
			if err != nil {
				return 0, "", err
			}
			lines = append(lines, line)
			if strings.HasPrefix(line, end) {
				return code, strings.Join(lines, "\n"), nil
			}
		}
		return 0, "", fmt.Errorf("numeric reply exceeds line limit")
	}
	return code, line, nil
}

func readTCPDiscoveryLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", fmt.Errorf("missing CRLF")
	}
	return string(line[:len(line)-2]), nil
}

func (FTPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	r := bufio.NewReaderSize(io.LimitReader(conn, 65536), 4096)
	code, banner, err := readFTPReply(r)
	if err != nil {
		return nil, err
	}
	if code == 120 {
		code, banner, err = readFTPReply(r)
	}
	if err != nil || code != 220 {
		return nil, fmt.Errorf("not FTP: greeting code %d: %v", code, err)
	}
	if _, err = io.WriteString(conn, "SYST\r\n"); err != nil {
		return nil, err
	}
	code, system, err := readFTPReply(r)
	if err != nil {
		return nil, err
	}
	meta := map[string]string{"banner": banner}
	confirmed := code == 215
	if confirmed {
		meta["system"] = strings.TrimPrefix(system, "215 ")
	}
	if _, err = io.WriteString(conn, "FEAT\r\n"); err != nil {
		return nil, err
	}
	code, features, err := readFTPReply(r)
	if err != nil {
		return nil, err
	}
	if code == 211 {
		meta["features"] = features
		confirmed = true
	}
	if !confirmed && !strings.Contains(strings.ToUpper(banner), "FTP") {
		return nil, fmt.Errorf("greeting lacks FTP evidence")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeFtp, "FTP", banner, meta), nil
}
