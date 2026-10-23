package service

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

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
	return serviceTarget{ip: ip, port: port, host: hostname}, nil
}
