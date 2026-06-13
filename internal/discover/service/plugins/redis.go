// Package plugins provides Redis service fingerprinting.
package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

const redisProbeTimeout = 2

type RedisFingerprinter struct{}

func (RedisFingerprinter) Name() string { return "redis" }

func (RedisFingerprinter) DefaultPorts() []int { return nil }

func (RedisFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probes := [][]byte{
		[]byte("*1\r\n$4\r\nPING\r\n"),
		[]byte("*1\r\n$4\r\nINFO\r\n"),
		[]byte("PING\r\n"),
	}

	var lastErr error
	probeTimeout := capRedisProbeTimeout(timeout)
	for _, probe := range probes {
		resp, err := helpers.TCPExchange(ctx, ip, port, probeTimeout, probe, 4096)
		if err != nil {
			lastErr = err
			continue
		}
		if details := redisDetailsFromResponse(host, ip, port, resp); details != nil {
			return details, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("not Redis")
}

func capRedisProbeTimeout(timeout int) int {
	if timeout < 0 || timeout > redisProbeTimeout {
		return redisProbeTimeout
	}
	return timeout
}

func redisDetailsFromResponse(host string, ip net.IP, port int, resp []byte) *discoverfern.ServiceDetails {
	if len(resp) == 0 {
		return nil
	}
	text := string(resp)
	lower := strings.ToLower(text)

	metadata := map[string]string{
		"banner": strings.TrimSpace(truncateString(text, 1024)),
	}
	version := "Redis"

	switch {
	case strings.HasPrefix(text, "+PONG"):
		metadata["state"] = "pong"
	case strings.Contains(lower, "redis_version:"):
		metadata["state"] = "info"
		if parsed := parseRedisInfoValue(text, "redis_version"); parsed != "" {
			version = parsed
			metadata["redis_version"] = parsed
		}
		if mode := parseRedisInfoValue(text, "redis_mode"); mode != "" {
			metadata["redis_mode"] = mode
		}
	case strings.HasPrefix(text, "-NOAUTH") || strings.Contains(lower, "authentication required"):
		metadata["state"] = "auth_required"
	case strings.HasPrefix(text, "-DENIED") && strings.Contains(lower, "redis is running in protected mode"):
		metadata["state"] = "protected_mode"
	case strings.HasPrefix(text, "-ERR") && strings.Contains(lower, "redis"):
		metadata["state"] = "redis_error"
	default:
		return nil
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Version:   &version,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeRedis,
		Metadata:  &discoverfern.ServiceMetadata{Generic: &discoverfern.GenericServiceMetadata{Metadata: metadata}},
	}
}

func parseRedisInfoValue(info string, key string) string {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, key+":"); ok {
			return value
		}
	}
	return ""
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
