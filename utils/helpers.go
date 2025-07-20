// Package utils provides utility functions used across the networkscan application.
package utils

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// ExtractHostPort parses a target string to extract host and port.
// It supports both "host:port" and "host" formats.
// If no port is specified, returns the host and port 0.
func ExtractHostPort(target string) (string, int) {
	if strings.Contains(target, ":") {
		host, portStr, err := net.SplitHostPort(target)
		if err == nil {
			if port := ParsePort(portStr); port > 0 {
				return host, port
			}
		}
	}
	return target, 0
}

// ParsePort converts a port string to an integer.
// Returns 0 if the port string is invalid or out of range.
func ParsePort(portStr string) int {
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	if port < 1 || port > 65535 {
		return 0
	}
	return port
}
