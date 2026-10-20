package service

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func normalizeHostname(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil {
		return "", fmt.Errorf("hostname must be a DNS name, without a scheme or port: %q", host)
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid hostname: %q", host)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid hostname: %q", host)
			}
		}
	}
	return host, nil
}

func parseTCPHostnameTarget(target string) (serviceTarget, error) {
	address, hostname, ok := strings.Cut(target, "|")
	if !ok || address == "" || hostname == "" || strings.Contains(hostname, "|") {
		return serviceTarget{}, fmt.Errorf("invalid target %q: expected IP:port|hostname", target)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return serviceTarget{}, fmt.Errorf("hostname targets require an explicit IP:port: %q", target)
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if ip == nil || err != nil || port < 1 || port > 65535 {
		return serviceTarget{}, fmt.Errorf("invalid IP:port in hostname target: %q", target)
	}
	logicalHost, err := normalizeHostname(hostname)
	if err != nil {
		return serviceTarget{}, err
	}
	return serviceTarget{ip: ip, port: port, host: logicalHost}, nil
}
