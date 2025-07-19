package smb

import (
	"fmt"
	"net"
	"strings"
)

// extractHostPort parses target string to extract host and port
func extractHostPort(target string) (string, int) {
	if strings.Contains(target, ":") {
		host, portStr, err := net.SplitHostPort(target)
		if err == nil {
			if port := parsePort(portStr); port > 0 {
				return host, port
			}
		}
	}
	return target, 0
}

// parsePort converts port string to int
func parsePort(portStr string) int {
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return port
}
