// Package utils provides utility functions used across the networkscan application.
package utils

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	pentestfern "github.com/Method-Security/networkscan/generated/go/pentest"
)

// GetEntriesFromTXTFiles reads and combines entries from multiple text files.
// It takes a list of file paths, reads each file line by line, and returns a combined
// list of all entries. Each line in the input files becomes a separate entry.
// Returns an error if any file cannot be opened or read.
func GetEntriesFromTXTFiles(paths []string) ([]string, error) {
	entries := []string{}
	for _, path := range paths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		file, err := os.Open(absPath)
		if err != nil {
			return nil, err
		}
		var lines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		err = file.Close()
		if err != nil {
			return nil, err
		}
		entries = append(entries, lines...)
	}
	return entries, nil
}

// ParsePort converts a port string to an integer.
// Returns 0 if the port string is invalid or out of range (1-65535).
func ParsePort(portStr string) int {
	if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
		return port
	}
	return 0
}

// ParseHostPort parses a target string into host and port components.
// If no port is provided, uses the specified default port.
// Returns the host and port as separate values.
func ParseHostPort(target string, defaultPort int) (string, int) {
	host, portStr, err := net.SplitHostPort(target)
	port := defaultPort
	if err == nil {
		// Port was provided, try to parse it
		if p := ParsePort(portStr); p > 0 {
			port = p
		}
	} else {
		// No port provided, use target as host
		host = target
	}
	return host, port
}

// GetDefaultPortForService returns the default port for a given service type
func GetDefaultPortForService(service pentestfern.SprayTargetService) int {
	switch service {
	case pentestfern.SprayTargetServiceSsh:
		return 22
	case pentestfern.SprayTargetServiceSmb:
		return 445
	case pentestfern.SprayTargetServiceTelnet:
		return 23
	case pentestfern.SprayTargetServiceFtp:
		return 21
	case pentestfern.SprayTargetServiceLdap:
		return 389
	case pentestfern.SprayTargetServiceKerberos:
		return 88
	default:
		return 80
	}
}

// GenerateRandomString generates a random string of specified length using alphanumeric characters.
// This is useful for creating temporary file/directory names for testing purposes.
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// ParseTargetHosts expands CIDR ranges and hostnames into individual IP addresses
func ParseTargetHosts(target string) ([]string, error) {
	var hosts []string

	if strings.Contains(target, "/") {
		// Must be a valid CIDR - no smart parsing
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %s", target)
		}

		// Verify the IP is actually the network address
		if !ip.Equal(ipnet.IP) {
			return nil, fmt.Errorf("invalid CIDR: %s is not a network address", target)
		}

		// Generate all IPs in the CIDR range
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); IncIP(ip) {
			hosts = append(hosts, ip.String())
		}

		// Remove network and broadcast addresses for /24 and smaller
		ones, _ := ipnet.Mask.Size()
		if ones >= 24 && len(hosts) > 2 {
			hosts = hosts[1 : len(hosts)-1]
		}
	} else if strings.Contains(target, "-") {
		// IP range like 192.168.1.1-192.168.1.10
		parts := strings.Split(target, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid IP range: %s", target)
		}

		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		endIP := net.ParseIP(strings.TrimSpace(parts[1]))
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IP range: %s", target)
		}

		// Generate IPs in range
		for ip := make(net.IP, len(startIP)); copy(ip, startIP) > 0; IncIP(ip) {
			hosts = append(hosts, ip.String())
			if ip.Equal(endIP) {
				break
			}
		}
	} else {
		// Single host or hostname
		hosts = append(hosts, target)
	}

	return hosts, nil
}

// IncIP increments an IP address
func IncIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetIPs resolves a hostname to IP addresses
func GetIPs(host string) ([]net.IP, error) {
	// Try to parse as IP first
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	// Resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host %s: %v", host, err)
	}

	return ips, nil
}
