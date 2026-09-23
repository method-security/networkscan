package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type MSSQLFingerprinter struct{}

func (MSSQLFingerprinter) Name() string        { return "mssql" }
func (MSSQLFingerprinter) DefaultPorts() []int { return []int{1433} }

// MS-TDS 2.2.6.5: VERSION followed by ENCRYPTION, with offsets relative to the payload.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868
func mssqlPrelogin() []byte {
	body := []byte{0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 255, 15, 0, 0, 0, 0, 0, 0}
	return append([]byte{0x12, 1, 0, 26, 0, 0, 1, 0}, body...)
}

func (MSSQLFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if _, err = conn.Write(mssqlPrelogin()); err != nil {
		return nil, err
	}
	b, err := databaseTDSReply(conn)
	if err != nil {
		return nil, err
	}
	version, encryption, err := mssqlOptions(b)
	if err != nil {
		return nil, err
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeMssql, "mssql", version,
		map[string]string{"encryption": strconv.Itoa(int(encryption)), "encryptionRequired": strconv.FormatBool(encryption&0x7f == 3),
			"cpes": "[cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*]"}), nil
}

// Both SQL Server and ASE use bounded, potentially fragmented TDS response frames.
func databaseTDSReply(r io.Reader) ([]byte, error) {
	var result []byte
	for packets := 0; packets < 128; packets++ {
		var h [8]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint16(h[2:4]))
		if h[0] != 4 || h[1] & ^byte(1) != 0 || size < 8 || size > 32768 || len(result)+size-8 > 65536 {
			return nil, fmt.Errorf("invalid TDS response frame")
		}
		b := make([]byte, size-8)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		result = append(result, b...)
		if h[1]&1 != 0 {
			return result, nil
		}
	}
	return nil, fmt.Errorf("too many TDS fragments")
}

func mssqlOptions(b []byte) (string, byte, error) {
	bad := fmt.Errorf("invalid TDS PRELOGIN options")
	type span struct {
		token      byte
		start, end int
	}
	var entries []span
	tableEnd := 0
	seen := map[byte]bool{}
	for p := 0; p < len(b); {
		if b[p] == 255 {
			tableEnd = p + 1
			break
		}
		if len(b)-p < 5 || seen[b[p]] {
			return "", 0, bad
		}
		seen[b[p]] = true
		start := int(binary.BigEndian.Uint16(b[p+1 : p+3]))
		size := int(binary.BigEndian.Uint16(b[p+3 : p+5]))
		if start+size > len(b) {
			return "", 0, bad
		}
		entries = append(entries, span{b[p], start, start + size})
		p += 5
	}
	if tableEnd == 0 || len(entries) == 0 || entries[0].token != 0 {
		return "", 0, bad
	}
	version := ""
	encryption := byte(255)
	for i, e := range entries {
		if e.start < tableEnd {
			return "", 0, bad
		}
		for _, prev := range entries[:i] {
			if e.start < prev.end && prev.start < e.end {
				return "", 0, bad
			}
		}
		v := b[e.start:e.end]
		switch e.token {
		case 0:
			if len(v) != 6 {
				return "", 0, bad
			}
			version = fmt.Sprintf("%d.%d.%d", v[0], v[1], binary.BigEndian.Uint16(v[2:4]))
		case 1:
			if len(v) != 1 || (v[0]&0x7f) > 3 {
				return "", 0, bad
			}
			encryption = v[0]
		}
	}
	if version == "" || encryption == 255 {
		return "", 0, bad
	}
	return version, encryption, nil
}
