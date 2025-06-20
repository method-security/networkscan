// Package utils provides utility functions used across the networkscan application.
package utils

import (
	"bufio"
	"errors"
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

// WordlistFiles maps service types and sizes to their corresponding username and password file paths
type WordlistFiles struct {
	UsernameFile string
	PasswordFile string
}

// builtInWordlistMap maps service types and wordlist sizes to their corresponding files
var builtInWordlistMap = map[string]map[string]WordlistFiles{
	"SSH": {
		"TINY": {
			UsernameFile: "configs/pentest/bruteforce/ssh/username_tiny.txt",
			PasswordFile: "configs/pentest/bruteforce/ssh/password_tiny.txt",
		},
	},
	"TELNET": {
		"TINY": {
			UsernameFile: "configs/pentest/bruteforce/telnet/username_tiny.txt",
			PasswordFile: "configs/pentest/bruteforce/telnet/password_tiny.txt",
		},
	},
}

// GetBuiltInWordlists loads built-in username and password wordlists based on service type and size.
// It returns slices of usernames and passwords from the appropriate wordlist files.
func GetBuiltInWordlists(service, size string) ([]string, []string, error) {
	// Convert service to uppercase for map lookup
	serviceStr := strings.ToUpper(service)
	sizeStr := strings.ToUpper(size)

	// Check if service exists in the map
	serviceMap, exists := builtInWordlistMap[serviceStr]
	if !exists {
		return nil, nil, errors.New("unsupported service type: " + service)
	}

	// Check if size exists for the service
	wordlistFiles, exists := serviceMap[sizeStr]
	if !exists {
		return nil, nil, errors.New("unsupported wordlist size '" + size + "' for service '" + service + "'")
	}

	// Load usernames from built-in wordlist
	usernames, err := GetEntriesFromTXTFiles([]string{wordlistFiles.UsernameFile})
	if err != nil {
		return nil, nil, errors.New("failed to load built-in username wordlist: " + err.Error())
	}

	// Load passwords from built-in wordlist
	passwords, err := GetEntriesFromTXTFiles([]string{wordlistFiles.PasswordFile})
	if err != nil {
		return nil, nil, errors.New("failed to load built-in password wordlist: " + err.Error())
	}

	return usernames, passwords, nil
}
