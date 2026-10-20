package service

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	discover "github.com/Method-Security/networkscan/generated/go/discover"
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

func explicitIPSocket(target string) (string, net.IP, int, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return "", nil, 0, fmt.Errorf("hostname overrides require an explicit IP:port target: %q", target)
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if ip == nil || err != nil || port < 1 || port > 65535 {
		return "", nil, 0, fmt.Errorf("invalid IP:port target for hostname override: %q", target)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), ip, port, nil
}

func parseTCPServiceConfigTargets(config discover.DiscoverServiceConfig) ([]serviceTarget, error) {
	if config.Hostname == nil && len(config.TargetHostnames) == 0 {
		return parseTCPServiceTargets(config.Targets)
	}
	if config.Hostname != nil && len(config.TargetHostnames) > 0 {
		return nil, fmt.Errorf("hostname and targetHostnames are mutually exclusive")
	}
	bindings := make(map[string][]string)
	if config.Hostname != nil {
		host, err := normalizeHostname(*config.Hostname)
		if err != nil {
			return nil, err
		}
		for _, target := range config.Targets {
			key, _, _, err := explicitIPSocket(target)
			if err != nil {
				return nil, err
			}
			bindings[key] = []string{host}
		}
	} else {
		sockets := make(map[string]bool)
		for _, target := range config.Targets {
			if key, _, _, err := explicitIPSocket(target); err == nil {
				sockets[key] = true
			}
		}
		for _, binding := range config.TargetHostnames {
			if binding == nil {
				return nil, fmt.Errorf("targetHostnames cannot contain null bindings")
			}
			key, _, _, err := explicitIPSocket(binding.Target)
			if err != nil {
				return nil, err
			}
			if !sockets[key] {
				return nil, fmt.Errorf("hostname binding target %q is not in targets", binding.Target)
			}
			host, err := normalizeHostname(binding.Hostname)
			if err != nil {
				return nil, err
			}
			duplicate := false
			for _, existing := range bindings[key] {
				duplicate = duplicate || existing == host
			}
			if !duplicate {
				bindings[key] = append(bindings[key], host)
			}
		}
	}
	var targets []serviceTarget
	for _, target := range config.Targets {
		key, ip, port, _ := explicitIPSocket(target)
		if hosts := bindings[key]; len(hosts) > 0 {
			for _, host := range hosts {
				targets = append(targets, serviceTarget{ip: ip, port: port, host: host})
			}
			continue
		}
		original, err := parseTCPServiceTargets([]string{target})
		if err != nil {
			return nil, err
		}
		targets = append(targets, original...)
	}
	return targets, nil
}
