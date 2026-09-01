// Package plugins provides Redis service fingerprinting.
package plugins

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type RedisFingerprinter struct{}

func (RedisFingerprinter) Name() string { return "redis" }

func (RedisFingerprinter) DefaultPorts() []int { return []int{6379, 6380, 26379} }

func (RedisFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probes := [][]byte{
		[]byte("*1\r\n$4\r\nPING\r\n"),
		[]byte("*1\r\n$4\r\nINFO\r\n"),
		[]byte("PING\r\n"),
	}

	var lastErr error
	for _, probe := range probes {
		resp, err := helpers.TCPExchange(ctx, ip, port, timeout, probe, 4096)
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
	line, hasRESPLine := firstRESPLine(text)

	switch {
	case hasRESPLine && line == "+PONG":
		metadata["state"] = "pong"
	case isRedisInfoResponse(text, lower):
		metadata["state"] = "info"
		if parsed := parseRedisInfoValue(text, "redis_version"); parsed != "" {
			version = parsed
			metadata["redis_version"] = parsed
		}
		if mode := parseRedisInfoValue(text, "redis_mode"); mode != "" {
			metadata["redis_mode"] = mode
		}
	case hasRESPLine && strings.HasPrefix(line, "-NOAUTH"):
		metadata["state"] = "auth_required"
	case hasRESPLine && strings.HasPrefix(line, "-DENIED") && strings.Contains(strings.ToLower(line), "redis is running in protected mode"):
		metadata["state"] = "protected_mode"
	case hasRESPLine && strings.HasPrefix(line, "-ERR") && strings.Contains(strings.ToLower(line), "redis"):
		metadata["state"] = "redis_error"
	default:
		return nil
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Version:   &version,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeRedis,
		Metadata:  &discoverfern.ServiceMetadata{Generic: &discoverfern.GenericServiceMetadata{Metadata: metadata}},
	}
}

func firstRESPLine(text string) (string, bool) {
	idx := strings.Index(text, "\r\n")
	if idx < 0 {
		return "", false
	}
	return text[:idx], true
}

func isRedisInfoResponse(text string, lower string) bool {
	line, ok := firstRESPLine(text)
	if !ok || !strings.HasPrefix(line, "$") || !strings.Contains(lower, "\r\nredis_version:") {
		return false
	}
	_, err := strconv.Atoi(strings.TrimPrefix(line, "$"))
	return err == nil
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
