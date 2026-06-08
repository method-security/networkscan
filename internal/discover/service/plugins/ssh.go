// Package plugins provides SSH service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"github.com/Method-Security/networkscan/utils"
)

type SSHFingerprinter struct{}

func (SSHFingerprinter) Name() string { return "ssh" }

func (SSHFingerprinter) DefaultPorts() []int { return []int{22, 2222} }

func (SSHFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := helpers.Dial(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set write deadline before sending client version
	err = helpers.SetWriteDeadline(conn, timeout)
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
	err = helpers.SetReadDeadline(conn, timeout)
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
	target := utils.FormatHostPort(host, port)
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
		Metadata:  &discoverfern.ServiceMetadata{Ssh: metadata},
	}

	return result, nil
}
