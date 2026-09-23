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

type RedisTLSFingerprinter struct{}

func (RedisTLSFingerprinter) Name() string        { return "redis" }
func (RedisTLSFingerprinter) DefaultPorts() []int { return []int{6380} }

// INFO is read-only and discloses a version when allowed before authentication.
// https://redis.io/docs/latest/develop/reference/protocol-spec/
func (RedisTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	raw, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = raw.Close() }()
	conn, err := helpers.UpgradeTLS(ctx, raw, host)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(conn, 4096)
	for _, command := range []string{"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n", "*1\r\n$4\r\nPING\r\n"} {
		if _, err = io.WriteString(conn, command); err != nil {
			return nil, err
		}
		kind, value, err := redisTLSReply(reader)
		if err != nil {
			return nil, err
		}
		meta := map[string]string{"cpes": "[cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*]"}
		version := ""
		switch {
		case kind == '$':
			for _, line := range strings.Split(value, "\r\n") {
				key, val, ok := strings.Cut(line, ":")
				if ok && (key == "redis_version" || key == "redis_mode" || key == "os") {
					meta[key] = val
				}
			}
			version = meta["redis_version"]
			if version == "" {
				return nil, fmt.Errorf("Redis INFO has no version")
			}
			meta["authRequired"] = "false"
			meta["state"] = "info"
		case kind == '+' && value == "PONG":
			meta["authRequired"] = "false"
			meta["state"] = "pong"
		case kind == '-' && (value == "NOAUTH" || strings.HasPrefix(value, "NOAUTH ")):
			meta["authRequired"] = "true"
			meta["state"] = "auth_required"
		case kind == '-' && strings.HasPrefix(value, "DENIED ") && strings.Contains(strings.ToLower(value), "redis is running in protected mode"):
			meta["state"] = "protected_mode"
		case kind == '-' && (strings.HasPrefix(value, "NOPERM ") || strings.HasPrefix(value, "ERR unknown command")):
			continue
		default:
			return nil, fmt.Errorf("not Redis over TLS")
		}
		result := helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeRedis, "redis", version, meta)
		enabled := true
		result.Tls = &enabled
		return result, nil
	}
	return nil, fmt.Errorf("Redis commands unavailable")
}

func redisTLSReply(r *bufio.Reader) (byte, string, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return 0, "", err
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return 0, "", fmt.Errorf("invalid RESP line")
	}
	kind := line[0]
	text := string(line[1 : len(line)-2])
	if kind == '+' || kind == '-' {
		return kind, text, nil
	}
	if kind != '$' {
		return 0, "", fmt.Errorf("unexpected RESP type")
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 0 || n > 65536 {
		return 0, "", fmt.Errorf("invalid RESP bulk length")
	}
	body := make([]byte, n+2)
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, "", err
	}
	if body[n] != '\r' || body[n+1] != '\n' {
		return 0, "", fmt.Errorf("invalid RESP bulk terminator")
	}
	return kind, string(body[:n]), nil
}
