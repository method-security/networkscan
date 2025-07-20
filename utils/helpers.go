// Package utils provides utility functions used across the networkscan application.
package utils

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
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
