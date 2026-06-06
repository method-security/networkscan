package helpers

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

func TCPConn(ctx context.Context, ip net.IP, port int, timeout int) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 5
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	dialer := net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func TCPExchange(ctx context.Context, ip net.IP, port int, timeout int, probe []byte, maxRead int) ([]byte, error) {
	conn, err := TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(probe); err != nil {
		return nil, err
	}
	buf := make([]byte, maxRead)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func TCPReadBanner(ctx context.Context, ip net.IP, port int, timeout int, maxRead int) ([]byte, error) {
	conn, err := TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	buf := make([]byte, maxRead)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func UDPExchange(ctx context.Context, ip net.IP, port int, timeout int, probe []byte, maxRead int) ([]byte, error) {
	if timeout <= 0 {
		timeout = 5
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	dialer := net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)
	if _, err := conn.Write(probe); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	buf := make([]byte, maxRead)
	n, err := conn.Read(buf)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return buf[:n], nil
}

func GenericResult(host string, ip net.IP, port int, transport common.TransportType, appProtocol string, version string, metadata map[string]string) *discoverfern.ServiceDetails {
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["application_protocol"] = appProtocol
	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: transport,
		Protocol:  common.ProtocolTypeUnknown,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Generic: &discoverfern.GenericServiceMetadata{Metadata: metadata}},
	}
}

func FirstLine(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.IndexAny(s, "\r\n"); idx >= 0 {
		return s[:idx]
	}
	return s
}

func LooksLikeIRC(s string) bool {
	upper := strings.ToUpper(s)
	if strings.Contains(upper, "NOTICE AUTH") || strings.Contains(upper, "NOTICE *") {
		return true
	}
	for _, code := range []string{" 001 ", " 002 ", " 003 ", " 004 ", " 005 "} {
		if strings.Contains(s, code) && strings.HasPrefix(s, ":") {
			return true
		}
	}
	return strings.Contains(upper, "ERROR :CLOSING LINK") && strings.Contains(upper, "IRC")
}

func ValidGopherItem(s string) bool {
	line := FirstLine(s)
	if line == "" {
		return false
	}
	valid := "0123456789+gIhTis"
	if !strings.ContainsRune(valid, rune(line[0])) {
		return false
	}
	return len(strings.Split(line, "\t")) >= 4
}

func isHexASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	_, err := strconv.ParseUint(string(b), 16, 32)
	return err == nil
}

func IsRMIEndpointHost(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == ':' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func ADBCNXNPacket() []byte {
	payload := []byte("host::\x00")
	packet := make([]byte, 24+len(payload))
	copy(packet[0:4], []byte("CNXN"))
	binary.LittleEndian.PutUint32(packet[4:8], 0x01000000)
	binary.LittleEndian.PutUint32(packet[8:12], 4096)
	binary.LittleEndian.PutUint32(packet[12:16], uint32(len(payload)))
	var checksum uint32
	for _, b := range payload {
		checksum += uint32(b)
	}
	binary.LittleEndian.PutUint32(packet[16:20], checksum)
	binary.LittleEndian.PutUint32(packet[20:24], binary.LittleEndian.Uint32(packet[0:4])^0xffffffff)
	copy(packet[24:], payload)
	return packet
}

func ValidADBPacket(packet []byte) bool {
	if len(packet) < 24 {
		return false
	}
	cmd := binary.LittleEndian.Uint32(packet[0:4])
	length := binary.LittleEndian.Uint32(packet[12:16])
	checksum := binary.LittleEndian.Uint32(packet[16:20])
	magic := binary.LittleEndian.Uint32(packet[20:24])
	if magic != cmd^0xffffffff || length > 1024*1024 || int(24+length) > len(packet) {
		return false
	}
	var actual uint32
	for _, b := range packet[24 : 24+length] {
		actual += uint32(b)
	}
	return actual == checksum
}

func LooksLikeGitDaemon(resp []byte) bool {
	for len(resp) >= 4 {
		if !isHexASCII(resp[:4]) {
			return false
		}
		n, err := strconv.ParseInt(string(resp[:4]), 16, 32)
		if err != nil || n < 0 || n > 65520 {
			return false
		}
		if n == 0 {
			resp = resp[4:]
			continue
		}
		if n < 4 || int(n) > len(resp) {
			return false
		}
		payload := resp[4:n]
		if bytes.HasPrefix(payload, []byte("ERR ")) ||
			bytes.Contains(payload, []byte("\x00multi_ack")) ||
			bytes.Contains(payload, []byte(" refs/heads/")) ||
			bytes.Contains(payload, []byte(" refs/tags/")) ||
			bytes.Contains(payload, []byte(" HEAD\x00")) {
			return true
		}
		resp = resp[n:]
	}
	return false
}
