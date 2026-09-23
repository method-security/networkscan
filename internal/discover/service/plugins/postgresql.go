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

type PostgresFingerprinter struct{}

func (PostgresFingerprinter) Name() string        { return "postgres" }
func (PostgresFingerprinter) DefaultPorts() []int { return []int{5432} }

// PostgreSQL protocol 3 startup identifies a user but never supplies a password.
// https://www.postgresql.org/docs/current/protocol-message-formats.html
func (PostgresFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	startup := append([]byte{0, 0, 0, 0, 0, 3, 0, 0}, []byte("user\x00networkscan\x00database\x00postgres\x00application_name\x00networkscan\x00\x00")...)
	binary.BigEndian.PutUint32(startup, uint32(len(startup)))
	if _, err = conn.Write(startup); err != nil {
		return nil, err
	}
	version, meta, err := postgresStartupReply(conn)
	if err != nil {
		return nil, err
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypePostgresql, "postgres", version, meta), nil
}

func postgresStartupReply(r io.Reader) (string, map[string]string, error) {
	bad := fmt.Errorf("invalid PostgreSQL startup response")
	meta := map[string]string{"cpes": "[cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*]"}
	version := ""
	accepted := false
	total := 0
	for messages := 0; messages < 128; messages++ {
		var h [5]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return "", nil, err
		}
		n := int(binary.BigEndian.Uint32(h[1:]))
		if n < 4 || n > 65536 || total+n > 262144 {
			return "", nil, bad
		}
		total += n
		b := make([]byte, n-4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", nil, err
		}
		switch h[0] {
		case 'R':
			if accepted || len(b) < 4 {
				return "", nil, bad
			}
			method := binary.BigEndian.Uint32(b)
			valid := false
			switch method {
			case 0, 2, 3, 6, 7, 9:
				valid = len(b) == 4
			case 5:
				valid = len(b) == 8
			case 10:
				valid = len(b) > 5 && b[len(b)-1] == 0 && b[len(b)-2] == 0 && bytes.Contains(b[4:], []byte("SCRAM-SHA-256\x00"))
			}
			if !valid {
				return "", nil, bad
			}
			meta["authRequired"] = strconv.FormatBool(method != 0)
			meta["authenticationMethod"] = strconv.FormatUint(uint64(method), 10)
			if method != 0 {
				return "", meta, nil
			}
			accepted = true
		case 'S':
			fields := bytes.Split(b, []byte{0})
			if !accepted || len(fields) != 3 || len(fields[0]) == 0 || len(fields[2]) != 0 {
				return "", nil, bad
			}
			if string(fields[0]) == "server_version" {
				version = string(fields[1])
				meta["serverVersion"] = version
			}
		case 'K':
			if !accepted || len(b) != 8 {
				return "", nil, bad
			}
		case 'Z':
			if !accepted || len(b) != 1 || b[0] != 'I' {
				return "", nil, bad
			}
			return version, meta, nil
		case 'E':
			fields := map[byte]string{}
			if len(b) < 2 || b[len(b)-1] != 0 {
				return "", nil, bad
			}
			for p := 0; p < len(b)-1; {
				tag := b[p]
				end := bytes.IndexByte(b[p+1:], 0)
				if tag == 0 || end < 0 {
					return "", nil, bad
				}
				fields[tag] = string(b[p+1 : p+1+end])
				p += end + 2
			}
			code := fields['C']
			if len(code) != 5 || fields['M'] == "" || (fields['S'] == "" && fields['V'] == "") {
				return "", nil, bad
			}
			for _, c := range code {
				if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z') {
					return "", nil, bad
				}
			}
			meta["sqlState"] = code
			meta["errorMsg"] = fields['M']
			if strings.HasPrefix(code, "28") {
				meta["authRequired"] = "true"
			}
			return version, meta, nil
		default:
			return "", nil, bad
		}
	}
	return "", nil, bad
}
