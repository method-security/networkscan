package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type MySQLFingerprinter struct{}

func (MySQLFingerprinter) Name() string        { return "MySQL" }
func (MySQLFingerprinter) DefaultPorts() []int { return []int{3306} }

// Detect reads only the server greeting; no handshake response or credentials are sent.
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
func (MySQLFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	var header [4]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if header[3] != 0 || n < 3 || n > 65536 {
		return nil, fmt.Errorf("invalid MySQL greeting frame")
	}
	body := make([]byte, n)
	if _, err = io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	version, meta, err := mysqlGreeting(body)
	if err != nil {
		return nil, err
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeMysql, "mysql", version, meta), nil
}

func mysqlGreeting(b []byte) (string, map[string]string, error) {
	bad := fmt.Errorf("invalid MySQL greeting")
	m := map[string]string{"errorMsg": "", "errorCode": "0"}
	if len(b) < 3 {
		return "", nil, bad
	}
	if b[0] == 0xff {
		code := binary.LittleEndian.Uint16(b[1:3])
		msg := b[3:]
		if len(msg) > 0 && msg[0] == '#' {
			if len(msg) < 6 {
				return "", nil, bad
			}
			m["sqlState"] = string(msg[1:6])
			msg = msg[6:]
		}
		// Initial errors have no capability negotiation, so SQLSTATE is optional.
		if code < 1000 || code > 4999 || len(msg) == 0 || bytes.IndexByte(msg, 0) >= 0 {
			return "", nil, bad
		}
		m["packetType"] = "error"
		m["errorCode"] = strconv.Itoa(int(code))
		m["errorMsg"] = string(msg)
		if code == 1045 || code == 1698 {
			m["authRequired"] = "true"
		}
		return "", m, nil
	}
	if b[0] != 10 && b[0] != 9 {
		return "", nil, bad
	}
	end := bytes.IndexByte(b[1:], 0)
	if end < 1 || end > 255 {
		return "", nil, bad
	}
	end++
	for _, c := range b[1:end] {
		if c < 32 || c > 126 {
			return "", nil, bad
		}
	}
	version := string(b[1:end])
	p := end + 1
	if b[0] == 9 {
		if len(b) < p+6 || b[len(b)-1] != 0 {
			return "", nil, bad
		}
	} else {
		if len(b) < p+15 || b[p+12] != 0 {
			return "", nil, bad
		}
		caps := uint32(binary.LittleEndian.Uint16(b[p+13 : p+15]))
		if len(b) > p+15 {
			if len(b) < p+31 {
				return "", nil, bad
			}
			caps |= uint32(binary.LittleEndian.Uint16(b[p+18:p+20])) << 16
			m["characterSet"] = strconv.Itoa(int(b[p+15]))
			tail := b[p+31:]
			if caps&0x8000 != 0 {
				saltSize := 13
				if caps&0x80000 != 0 && int(b[p+20])-8 > saltSize {
					saltSize = int(b[p+20]) - 8
				}
				if len(tail) < saltSize {
					return "", nil, bad
				}
				tail = tail[saltSize:]
			}
			if caps&0x80000 != 0 {
				plugin := bytes.TrimSuffix(tail, []byte{0})
				if len(plugin) == 0 || len(plugin) > 255 {
					return "", nil, bad
				}
				for _, c := range plugin {
					if c < 33 || c > 126 {
						return "", nil, bad
					}
				}
				m["authPlugin"] = string(plugin)
			}
		}
		m["capabilities"] = strconv.FormatUint(uint64(caps), 10)
		m["tlsSupported"] = strconv.FormatBool(caps&0x800 != 0)
	}
	m["packetType"] = "handshake"
	m["protocolVersion"] = strconv.Itoa(int(b[0]))
	m["serverVersion"] = version
	m["product"] = "mysql"
	m["cpes"] = "[cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*]"
	if strings.Contains(strings.ToLower(version), "mariadb") {
		m["product"] = "mariadb"
		m["cpes"] = "[cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*]"
	}
	return version, m, nil
}
