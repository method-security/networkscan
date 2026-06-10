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
	case pentestfern.SprayTargetServiceMssql:
		return 1433
	case pentestfern.SprayTargetServiceMysql:
		return 3306
	case pentestfern.SprayTargetServicePostgres:
		return 5432
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

// parseTargetInternal is the core logic for parsing different target formats
func parseTargetInternal(target string, trackMapping bool) ([]string, map[string]string, error) {
	var ipToHostname map[string]string
	if trackMapping {
		ipToHostname = make(map[string]string)
	}

	if strings.Contains(target, "/") {
		// CIDR range (e.g., 192.168.1.0/24)
		return expandCIDR(target)
	} else if isIPRange(target) {
		// IP range (e.g., 192.168.1.1-192.168.1.10)
		return expandIPRange(target)
	} else {
		// Single IP or hostname
		return parseSingleTarget(target, trackMapping, ipToHostname)
	}
}

// expandCIDR handles CIDR notation like 192.168.1.0/24
func expandCIDR(target string) ([]string, map[string]string, error) {
	ip, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid CIDR: %s", target)
	}

	// Verify the IP is actually the network address
	if !ip.Equal(ipnet.IP) {
		return nil, nil, fmt.Errorf("invalid CIDR: %s is not a network address", target)
	}

	var hosts []string
	// Generate all IPs in the CIDR range
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); IncIP(ip) {
		hosts = append(hosts, ip.String())
	}

	// Remove network and broadcast addresses for IPv4 networks /24 and smaller
	// IPv6 doesn't have broadcast addresses, so skip this logic for IPv6
	ones, bits := ipnet.Mask.Size()
	if bits == 32 && ones >= 24 && len(hosts) > 2 { // Only for IPv4 (/32 bits total)
		hosts = hosts[1 : len(hosts)-1]
	}

	return hosts, nil, nil
}

// isIPRange checks if target is an IP range like 192.168.1.1-192.168.1.10
func isIPRange(target string) bool {
	if !strings.Contains(target, "-") {
		return false
	}
	parts := strings.Split(target, "-")
	if len(parts) != 2 {
		return false
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))
	return startIP != nil && endIP != nil
}

// expandIPRange handles IP ranges like 192.168.1.1-192.168.1.10
func expandIPRange(target string) ([]string, map[string]string, error) {
	parts := strings.Split(target, "-")
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	var hosts []string
	for ip := make(net.IP, len(startIP)); copy(ip, startIP) > 0; IncIP(ip) {
		hosts = append(hosts, ip.String())
		if ip.Equal(endIP) {
			break
		}
	}
	return hosts, nil, nil
}

// parseSingleTarget handles single IPs or hostnames
func parseSingleTarget(target string, trackMapping bool, ipToHostname map[string]string) ([]string, map[string]string, error) {
	if ip := net.ParseIP(target); ip != nil {
		// Already an IP address
		return []string{target}, ipToHostname, nil
	}

	// It's a hostname/FQDN, resolve to IP addresses
	ips, err := GetIPs(target)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve hostname %s: %v", target, err)
	}

	var hosts []string
	for _, ip := range ips {
		ipStr := ip.String()
		hosts = append(hosts, ipStr)
		if trackMapping {
			ipToHostname[ipStr] = target
		}
	}

	return hosts, ipToHostname, nil
}

// ParseTargetHosts expands CIDR ranges and hostnames into individual IP addresses
func ParseTargetHosts(target string) ([]string, error) {
	hosts, _, err := parseTargetInternal(target, false)
	return hosts, err
}

// ParseTargetHostsWithMapping expands CIDR ranges and hostnames into individual IP addresses
// and returns a mapping from IP addresses back to their original hostnames (if resolved from FQDNs)
func ParseTargetHostsWithMapping(target string) ([]string, map[string]string, error) {
	return parseTargetInternal(target, true)
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

// FormatHostPort formats a host (IP address or hostname) and port into a valid address string.
// For IPv6 addresses, it wraps them in square brackets. For IPv4 and hostnames, it uses simple colon notation.
// This ensures compatibility with services expecting properly formatted network addresses.
func FormatHostPort(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

// IsIPv6 returns true if the host string is an IPv6 address.
func IsIPv6(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// FormatLDAPURL constructs a properly formatted LDAP URL that handles IPv6 addresses.
func FormatLDAPURL(host string, port int, useTLS bool) string {
	scheme := "ldap"
	if useTLS {
		scheme = "ldaps"
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}

// FormatRPCBinding constructs an ncacn_ip_tcp binding string.
// The string binding format uses '[' as the endpoint delimiter, so IPv6 colons
// in the network address are unambiguous: ncacn_ip_tcp:2001:db8::1[135]
func FormatRPCBinding(host string, endpoint string) string {
	return fmt.Sprintf("ncacn_ip_tcp:%s[%s]", host, endpoint)
}

// DetectIPVersions analyzes a list of IP addresses and returns which IP versions are present.
// Returns a slice containing "4" for IPv4 and/or "6" for IPv6.
// This is used to configure scanners to support the appropriate IP versions.
func DetectIPVersions(hosts []string) []string {
	hasIPv4 := false
	hasIPv6 := false

	for _, host := range hosts {
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}

		if ip.To4() != nil {
			hasIPv4 = true
		} else {
			hasIPv6 = true
		}

		// Short circuit if we've found both
		if hasIPv4 && hasIPv6 {
			break
		}
	}

	var versions []string
	if hasIPv4 {
		versions = append(versions, "4")
	}
	if hasIPv6 {
		versions = append(versions, "6")
	}

	// Default to IPv4 if no valid IPs found
	if len(versions) == 0 {
		versions = []string{"4"}
	}

	return versions
}
