// Package plugins provides Oracle TNS service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

// OracleFingerprinter detects Oracle TNS listeners via raw TCP probe.
type OracleFingerprinter struct{}

func (OracleFingerprinter) Name() string { return "oracle" }

func (OracleFingerprinter) DefaultPorts() []int { return []int{1521, 1522, 1525} }

func (OracleFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	timeoutDur := time.Duration(timeout) * time.Second
	if timeout <= 0 {
		timeoutDur = 5 * time.Second
	}

	conn, err := net.DialTimeout("tcp", addr, timeoutDur)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeoutDur))
	_ = ctx

	// Build TNS CONNECT packet with bogus service name
	pkt := buildOracleTNSConnect(ip.String(), port)
	if _, err := conn.Write(pkt); err != nil {
		return nil, nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return nil, nil
	}
	response := buf[:n]

	// Check packet type (4=REFUSE, 2=ACCEPT, 11=RESEND)
	pktType := response[4]
	if pktType != 4 && pktType != 2 && pktType != 11 {
		return nil, nil
	}

	body := string(response[12:])
	// Must contain VSNNUM to be a real Oracle response
	if !strings.Contains(body, "VSNNUM") {
		return nil, nil
	}

	return buildOracleResult(host, ip, port, body), nil
}

func buildOracleTNSConnect(ipStr string, port int) []byte {
	connectData := []byte(fmt.Sprintf(
		"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=non-abc-existent-service-xyz-probe)(CID=(PROGRAM=networkscan)(HOST=localhost)(USER=)))(ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=%d)))",
		ipStr, port,
	))
	pktLen := uint16(len(connectData) + 58)
	hdr := make([]byte, 58)
	binary.BigEndian.PutUint16(hdr[0:], pktLen)
	hdr[4] = 0x01 // CONNECT
	binary.BigEndian.PutUint16(hdr[8:], 0x013c)
	binary.BigEndian.PutUint16(hdr[10:], 0x012c)
	binary.BigEndian.PutUint16(hdr[14:], 0x8000)
	binary.BigEndian.PutUint16(hdr[16:], 0x7fff)
	binary.BigEndian.PutUint16(hdr[18:], 0x7f08)
	binary.BigEndian.PutUint16(hdr[22:], 0x0001)
	binary.BigEndian.PutUint16(hdr[24:], uint16(len(connectData)))
	binary.BigEndian.PutUint16(hdr[26:], 0x003a)
	return append(hdr, connectData...)
}

func buildOracleResult(host string, ip net.IP, port int, body string) *discoverfern.ServiceDetails {
	info := &protocol.OracleServerInfo{}
	version := ""

	// Extract VSNNUM and decode to version string
	vsnRe := regexp.MustCompile(`VSNNUM=(\d+)`)
	if m := vsnRe.FindStringSubmatch(body); len(m) > 1 {
		vsn := m[1]
		info.Vsnnum = &vsn
		if vsnNum, err := strconv.Atoi(m[1]); err == nil {
			if vsnNum > 0 {
				version = decodeOracleVSNNUM(vsnNum)
				info.Version = &version
			}
		}
		protoVer := "TNS"
		info.ProtocolVersion = &protoVer
	}

	// Extract error code
	errRe := regexp.MustCompile(`ERR=(\d+)`)
	if m := errRe.FindStringSubmatch(body); len(m) > 1 {
		info.ErrorCode = &m[1]
	}

	if version == "" {
		version = "Oracle (version unknown)"
		info.Version = &version
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Version:   &version,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeOracle,
		Metadata:  &discoverfern.ServiceMetadata{Oracle: info},
	}
}

func decodeOracleVSNNUM(vsnNum int) string {
	return fmt.Sprintf("%d.%d.%d.%d.%d",
		(vsnNum>>24)&0xff,
		(vsnNum>>20)&0x0f,
		(vsnNum>>12)&0xff,
		(vsnNum>>8)&0x0f,
		vsnNum&0xff,
	)
}
