package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type SybaseFingerprinter struct{}

func (SybaseFingerprinter) Name() string        { return "sybase" }
func (SybaseFingerprinter) DefaultPorts() []int { return []int{5000} }

// ASE rejects non-login TDS packets before authentication with error 1621.
// https://infocenter.sybase.com/help/topic/com.sybase.infocenter.dc00729.1500/html/errMessageAdvRes/BABGHBAF.htm
// Token layouts: https://www.freetds.org/tds.html (FreeTDS protocol documentation).
func (SybaseFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	// A SQL Server PRELOGIN contains no login record, username, or password.
	if _, err = conn.Write(mssqlPrelogin()); err != nil {
		return nil, err
	}
	b, err := databaseTDSReply(conn)
	if err != nil {
		return nil, err
	}
	meta, err := sybasePreauthError(b)
	if err != nil {
		return nil, err
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeSybase, "sybase", "", meta), nil
}

func sybasePreauthError(b []byte) (map[string]string, error) {
	bad := fmt.Errorf("not an ASE preauthentication rejection")
	// ERROR and EED are length-prefixed in TDS 5.0; SQL Server PRELOGIN is not.
	if len(b) < 3 || (b[0] != 0xaa && b[0] != 0xe5) {
		return nil, bad
	}
	n := int(binary.LittleEndian.Uint16(b[1:3]))
	if n < 10 || n > len(b)-3 {
		return nil, bad
	}
	payload := b[3 : 3+n]
	code := binary.LittleEndian.Uint32(payload)
	if code != 1621 {
		return nil, bad
	}
	p := 6
	if b[0] == 0xe5 {
		if p >= len(payload) {
			return nil, bad
		}
		p += 1 + int(payload[p]) + 3
	}
	if p+2 > len(payload) {
		return nil, bad
	}
	size := int(binary.LittleEndian.Uint16(payload[p:]))
	p += 2
	if size == 0 || size > len(payload)-p {
		return nil, bad
	}
	message := string(payload[p : p+size])
	p += size
	// The documented error number is locale independent; the message is evidence,
	// not a signature. No login attempt is needed to elicit this error.
	meta := map[string]string{"authRequired": "true", "errorCode": strconv.FormatUint(uint64(code), 10), "errorMsg": message,
		"cpes": "[cpe:2.3:a:sybase:adaptive_server_enterprise:*:*:*:*:*:*:*:*]"}
	for _, key := range []string{"serverName", "procedure"} {
		if p >= len(payload) {
			return nil, bad
		}
		size = int(payload[p])
		p++
		if size > len(payload)-p {
			return nil, bad
		}
		if size > 0 {
			meta[key] = string(payload[p : p+size])
		}
		p += size
	}
	if len(payload)-p != 2 {
		return nil, bad
	}
	return meta, nil
}
