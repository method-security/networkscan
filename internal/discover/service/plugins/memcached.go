// Package plugins provides MEMCACHED service fingerprinting
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

type MemcachedFingerprinter struct{}

func (MemcachedFingerprinter) Name() string { return "memcached" }

func (MemcachedFingerprinter) DefaultPorts() []int { return []int{11211} }

func (MemcachedFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// Create connection with timeout
	dialer := net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	// Send memcached "stats" command to get server info
	statsCmd := []byte("stats\r\n")

	if _, err := conn.Write(statsCmd); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 8192)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Memcached stats response should start with "STAT" and end with "END"
	responseStr := string(response[:n])
	if !strings.HasPrefix(responseStr, "STAT ") {
		return nil, fmt.Errorf("invalid memcached response")
	}

	if !strings.Contains(responseStr, "END\r\n") {
		// Try to read more data to get the complete response
		additionalData := make([]byte, 8192)
		if n2, err := conn.Read(additionalData); err == nil {
			responseStr += string(additionalData[:n2])
		}
	}

	// Parse stats response
	stats := parseMemcachedStats(responseStr)

	// Extract key information
	var version, pid, uptime, pointerSize *string

	if v, ok := stats["version"]; ok {
		version = &v
	}
	if p, ok := stats["pid"]; ok {
		pid = &p
	}
	if u, ok := stats["uptime"]; ok {
		uptime = &u
	}
	if ps, ok := stats["pointer_size"]; ok {
		pointerSize = &ps
	}

	// Default version if not found
	if version == nil {
		versionStr := "memcached"
		version = &versionStr
	}

	metadata := &protocol.MemcachedServerInfo{
		Version:     version,
		Pid:         pid,
		Uptime:      uptime,
		PointerSize: pointerSize,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeMemcached,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Memcached: metadata},
	}

	return result, nil
}

// parseMemcachedStats parses the stats command output
func parseMemcachedStats(response string) map[string]string {
	stats := make(map[string]string)

	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "STAT ") {
			continue
		}

		// Remove "STAT " prefix
		line = strings.TrimPrefix(line, "STAT ")

		// Split into key and value
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			stats[parts[0]] = parts[1]
		}
	}

	return stats
}
