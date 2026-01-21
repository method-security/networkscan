// Package plugins provides SSH service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type SSHFingerprinter struct{}

func (SSHFingerprinter) Name() string { return "ssh" }

func (SSHFingerprinter) DefaultPorts() []int { return []int{22, 2222} }

func (SSHFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// Use raw TCP connection to read SSH banner - the gold standard approach
	dialer := net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set write deadline before sending client version
	err = conn.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err != nil {
		return nil, err
	}

	// Send client version first - some SSH servers wait for client greeting before sending banner
	clientVersion := "SSH-2.0-GoSSHScanner\r\n"
	_, err = conn.Write([]byte(clientVersion))
	if err != nil {
		return nil, fmt.Errorf("failed to send SSH version string: %w", err)
	}

	// Set read deadline for banner response
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err != nil {
		return nil, err
	}

	// Read banner
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	banner := strings.TrimSpace(string(buf[:n]))

	// SSH always begins with "SSH-" banner
	if !strings.HasPrefix(banner, "SSH") {
		return nil, fmt.Errorf("not an SSH service")
	}

	// Extract version from banner (e.g., "SSH-2.0-OpenSSH_8.9" -> "SSH-2.0-OpenSSH_8.9")
	target := fmt.Sprintf("%s:%d", host, port)
	metadata := &protocol.SshServerInfo{
		ServerVersion: &banner,
		Target:        &target,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeSsh,
		Version:   &banner,
		Metadata:  discoverfern.NewServiceMetadataFromSsh(metadata),
	}

	return result, nil
}
