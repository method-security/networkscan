// Package plugins provides SSH service fingerprinting
package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
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

	banner, err := readSSHIdentification(conn)
	if err != nil {
		return nil, err
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
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeSsh,
		Version:   &banner,
		Metadata:  &discoverfern.ServiceMetadata{Ssh: metadata},
	}

	return result, nil
}

func readSSHIdentification(r io.Reader) (string, error) {
	// Bound both pre-identification text and individual lines while allowing fragmentation.
	reader := bufio.NewReaderSize(io.LimitReader(r, 8192), 256)
	for lines := 0; lines < 64; lines++ {
		raw, err := reader.ReadSlice('\n')
		if err != nil {
			return "", err
		}
		line := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
		if !strings.HasPrefix(line, "SSH-") {
			continue
		}
		version, software, ok := strings.Cut(line[4:], "-")
		if !ok || (version != "2.0" && version != "1.99" && version != "1.5") || len(raw) > 255 {
			return "", fmt.Errorf("invalid SSH identification")
		}
		name, _, _ := strings.Cut(software, " ")
		if name == "" {
			return "", fmt.Errorf("missing SSH software version")
		}
		for _, c := range name {
			if c < 33 || c > 126 {
				return "", fmt.Errorf("invalid SSH software version")
			}
		}
		for _, c := range software {
			if c < 32 || c == 127 {
				return "", fmt.Errorf("invalid SSH identification text")
			}
		}
		return line, nil
	}
	return "", fmt.Errorf("SSH preamble exceeds limit")
}
