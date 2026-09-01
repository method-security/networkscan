// Package plugins provides Oracle TNS service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/netdial"
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

	conn, err := netdial.DialContext(ctx, "tcp", addr, netdial.WithTimeout(timeoutDur))
	if err != nil {
		return nil, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeoutDur))

	// Build TNS CONNECT packet with bogus service name
	pkt := buildOracleTNSConnect(ip.String(), port)
	if _, err := conn.Write(pkt); err != nil {
		return nil, nil
	}

	response, err := readOracleTNSPacket(conn)
	if err != nil || len(response) < 12 {
		return nil, nil
	}

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
		"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=NONEXISTENT_SVC_PROBE_XYZ)(CID=(PROGRAM=networkscan)(HOST=localhost)(USER=)))(ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=%d)))",
		ipStr, port,
	))
	pktLen := uint16(len(connectData) + 58)
	hdr := make([]byte, 58)
	binary.BigEndian.PutUint16(hdr[0:], pktLen)
	binary.BigEndian.PutUint16(hdr[2:], 0)
	hdr[4] = 0x01 // CONNECT
	hdr[5] = 0x00
	binary.BigEndian.PutUint16(hdr[6:], 0)
	binary.BigEndian.PutUint16(hdr[8:], 0x013c)
	binary.BigEndian.PutUint16(hdr[10:], 0x012c)
	binary.BigEndian.PutUint16(hdr[12:], 0x0000)
	binary.BigEndian.PutUint16(hdr[14:], 0x8000)
	binary.BigEndian.PutUint16(hdr[16:], 0x7fff)
	binary.BigEndian.PutUint16(hdr[18:], 0x7f08)
	binary.BigEndian.PutUint16(hdr[20:], 0x0000)
	binary.BigEndian.PutUint16(hdr[22:], 0x0001)
	binary.BigEndian.PutUint16(hdr[24:], uint16(len(connectData)))
	binary.BigEndian.PutUint16(hdr[26:], 0x003a)
	return append(hdr, connectData...)
}

func readOracleTNSPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	packetLen := int(binary.BigEndian.Uint16(header[0:2]))
	if packetLen < len(header) {
		return nil, fmt.Errorf("invalid TNS packet length %d", packetLen)
	}
	body := make([]byte, packetLen-len(header))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
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
		Version:   &version,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeOracledb,
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
