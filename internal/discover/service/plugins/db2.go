package plugins

import (
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
	"golang.org/x/text/encoding/charmap"
)

type DB2Fingerprinter struct{}

func (DB2Fingerprinter) Name() string        { return "db2" }
func (DB2Fingerprinter) DefaultPorts() []int { return []int{446, 50000} }

// EXCSAT exchanges DRDA server attributes without ACCSEC or SECCHK.
// https://www.ibm.com/docs/en/ims/15.5.0?topic=objects-excsat-command-x1041
func (DB2Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	var attributes []byte
	for _, field := range []struct {
		code uint16
		text string
	}{{0x115e, "networkscan"}, {0x1147, "networkscan"}, {0x116d, "networkscan"}, {0x115a, "1.0"}} {
		value, err := charmap.CodePage037.NewEncoder().Bytes([]byte(field.text))
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, db2Parameter(field.code, value)...)
	}
	// AGENT, SQLAM, RDB, and SECMGR manager levels (no security negotiation).
	attributes = append(attributes, db2Parameter(0x1404, []byte{0x14, 0x03, 0, 7, 0x24, 0x07, 0, 7, 0x24, 0x0f, 0, 7, 0x14, 0x40, 0, 7})...)
	command := db2Parameter(0x1041, attributes)
	request := append([]byte{0, 0, 0xd0, 1, 0, 1}, command...)
	binary.BigEndian.PutUint16(request, uint16(len(request)))
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	var h [6]byte
	if _, err = io.ReadFull(conn, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:2]))
	if n < 10 || n > 32767 || h[2] != 0xd0 || (h[3]&15 != 2 && h[3]&15 != 3) || binary.BigEndian.Uint16(h[4:]) != 1 {
		return nil, fmt.Errorf("invalid DRDA reply header")
	}
	b := make([]byte, n-6)
	if _, err = io.ReadFull(conn, b); err != nil {
		return nil, err
	}
	version, meta, err := db2Attributes(b)
	if err != nil {
		return nil, err
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeDb2, "db2", version, meta), nil
}

func db2Parameter(code uint16, value []byte) []byte {
	b := make([]byte, 4, len(value)+4)
	binary.BigEndian.PutUint16(b, uint16(len(value)+4))
	binary.BigEndian.PutUint16(b[2:], code)
	return append(b, value...)
}

func db2Attributes(b []byte) (string, map[string]string, error) {
	bad := fmt.Errorf("invalid DRDA EXCSATRD")
	if len(b) < 4 || int(binary.BigEndian.Uint16(b)) != len(b) || binary.BigEndian.Uint16(b[2:]) != 0x1443 {
		return "", nil, bad
	}
	meta := map[string]string{}
	for p := 4; p < len(b); {
		if len(b)-p < 4 {
			return "", nil, bad
		}
		n := int(binary.BigEndian.Uint16(b[p:]))
		if n < 4 || n > len(b)-p {
			return "", nil, bad
		}
		code := binary.BigEndian.Uint16(b[p+2:])
		value := b[p+4 : p+n]
		p += n
		key := ""
		switch code {
		case 0x115e:
			key = "externalName"
		case 0x116d:
			key = "serverName"
		case 0x115a:
			key = "serverRelease"
		case 0x1147:
			key = "serverClass"
		}
		if key == "" {
			continue
		}
		if len(value) == 0 || len(value) > 255 {
			return "", nil, bad
		}
		// DRDA starts in CCSID 37. Some ASCII DRDA implementations send plain attributes.
		ascii := true
		for _, c := range value {
			if c < 32 || c > 126 {
				ascii = false
				break
			}
		}
		text := string(value)
		if !ascii {
			decoded, err := charmap.CodePage037.NewDecoder().Bytes(value)
			if err != nil {
				return "", nil, err
			}
			text = string(decoded)
		}
		meta[key] = strings.TrimSpace(text)
	}
	if meta["serverClass"] == "" || meta["serverRelease"] == "" {
		return "", nil, bad
	}
	version := meta["serverRelease"]
	class := strings.ToUpper(meta["serverClass"])
	switch {
	case strings.Contains(class, "DB2"):
		meta["cpes"] = "[cpe:2.3:a:ibm:db2:*:*:*:*:*:*:*:*]"
	case strings.Contains(class, "DERBY"):
		meta["cpes"] = "[cpe:2.3:a:apache:derby:*:*:*:*:*:*:*:*]"
	case strings.Contains(class, "INFORMIX"):
		meta["cpes"] = "[cpe:2.3:a:ibm:informix:*:*:*:*:*:*:*:*]"
	}
	if strings.HasPrefix(version, "SQL") && len(version) == 8 {
		major, e1 := strconv.Atoi(version[3:5])
		minor, e2 := strconv.Atoi(version[5:7])
		fix, e3 := strconv.Atoi(version[7:])
		if e1 == nil && e2 == nil && e3 == nil {
			version = fmt.Sprintf("%d.%d.%d", major, minor, fix)
		}
	}
	return version, meta, nil
}
