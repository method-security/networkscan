package configs

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed pentest discover enumerate
var configFS embed.FS

// ReadFile reads a file from the embedded config filesystem.
// The path should be relative to the configs/ directory (e.g., "pentest/spray/system_passwords.txt").
func ReadFile(path string) ([]byte, error) {
	return configFS.ReadFile(path)
}

// ReadLines reads a text file from the embedded config filesystem and returns its lines.
func ReadLines(path string) ([]string, error) {
	data, err := configFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded config %s: %w", path, err)
	}
	content := strings.TrimRight(string(data), "\r\n")
	if content == "" {
		return []string{}, nil
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, "\r")
	}
	return lines, nil
}

// ReadMultipleLineFiles reads multiple text files and combines their lines.
func ReadMultipleLineFiles(paths []string) ([]string, error) {
	var entries []string
	for _, path := range paths {
		lines, err := ReadLines(path)
		if err != nil {
			return nil, err
		}
		entries = append(entries, lines...)
	}
	return entries, nil
}
