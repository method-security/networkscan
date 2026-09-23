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

type RTSPFingerprinter struct{}

func (RTSPFingerprinter) Name() string        { return "rtsp" }
func (RTSPFingerprinter) DefaultPorts() []int { return []int{554} }

// RFC 2326 / RFC 7826: OPTIONS * does not create a media session.
func (RTSPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if _, err = io.WriteString(conn, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: networkscan\r\n\r\n"); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(io.LimitReader(conn, 32768), 4096)
	status, err := readTCPDiscoveryLine(r)
	if err != nil {
		return nil, err
	}
	fields := strings.SplitN(status, " ", 3)
	if len(fields) != 3 || (fields[0] != "RTSP/1.0" && fields[0] != "RTSP/2.0") || len(fields[1]) != 3 {
		return nil, fmt.Errorf("not RTSP")
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil || code < 100 || code > 599 {
		return nil, fmt.Errorf("invalid RTSP status")
	}
	meta := map[string]string{"status": status, "serverInfo": ""}
	cseq := false
	for i := 0; i < 128; i++ {
		line, err := readTCPDiscoveryLine(r)
		if err != nil {
			return nil, err
		}
		if line == "" {
			if !cseq {
				return nil, fmt.Errorf("missing RTSP CSeq")
			}
			return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeRtsp, "RTSP", strings.TrimPrefix(fields[0], "RTSP/"), meta), nil
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid RTSP header")
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "cseq":
			if cseq || value != "1" {
				return nil, fmt.Errorf("unexpected RTSP CSeq")
			}
			cseq = true
		case "server":
			meta["serverInfo"] = value
		case "public":
			meta["public"] = value
		case "www-authenticate":
			meta["www_authenticate"] = value
		}
	}
	return nil, fmt.Errorf("RTSP headers exceed limit")
}
