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

type RsyncFingerprinter struct{}

func (RsyncFingerprinter) Name() string        { return "rsync" }
func (RsyncFingerprinter) DefaultPorts() []int { return []int{873} }

// The rsync project's csprotocol.txt defines this daemon greeting exchange.
func (RsyncFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	r := bufio.NewReaderSize(io.LimitReader(conn, 65536), 4096)
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	banner := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	fields := strings.Fields(banner)
	if len(fields) < 2 || fields[0] != "@RSYNCD:" {
		return nil, fmt.Errorf("not rsync")
	}
	parts := strings.Split(fields[1], ".")
	if len(parts) > 2 {
		return nil, fmt.Errorf("invalid rsync version")
	}
	for _, part := range parts {
		if part == "" || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return nil, fmt.Errorf("invalid rsync version")
		}
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 20 || major > 99 || (major >= 30 && len(parts) != 2) || (major >= 32 && len(fields) < 3) {
		return nil, fmt.Errorf("invalid rsync protocol version")
	}
	// Negotiate protocol 31 and request only the public module listing.
	if _, err = io.WriteString(conn, "@RSYNCD: 31.0\n#list\n"); err != nil {
		return nil, err
	}
	var listing []string
	for i := 0; i < 256; i++ {
		line, err = r.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		text := strings.TrimRight(string(line), "\r\n")
		if text == "@RSYNCD: EXIT" {
			return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeRsync, "RSYNC", fields[1], map[string]string{"banner": banner, "modules": strings.Join(listing, "\n"), "digest_algorithms": strings.Join(fields[2:], " ")}), nil
		}
		if strings.HasPrefix(text, "@ERROR") {
			return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeRsync, "RSYNC", fields[1], map[string]string{"banner": banner, "error": text}), nil
		}
		listing = append(listing, text)
	}
	return nil, fmt.Errorf("rsync listing exceeds limit")
}
