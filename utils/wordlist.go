// Package utils provides wordlist resolution utilities for the networkscan application.
package utils

import (
	"fmt"
	"path/filepath"

	pentestfern "github.com/Method-Security/networkscan/generated/go/pentest"
)

// WordlistResolver provides functionality to resolve wordlist enums to file paths
type WordlistResolver struct {
	baseConfigDir string
}

// NewWordlistResolver creates a new WordlistResolver with the specified base config directory
func NewWordlistResolver(baseConfigDir string) *WordlistResolver {
	return &WordlistResolver{
		baseConfigDir: baseConfigDir,
	}
}

// GetDefaultWordlistResolver returns a WordlistResolver configured for the container environment
func GetDefaultWordlistResolver() *WordlistResolver {
	// In container, configs are mounted at /opt/method/networkscan/var/conf/
	return NewWordlistResolver("/opt/method/networkscan/var/conf")
}

// GetConfigFilePath returns the full path for a file within the config directory
func (wr *WordlistResolver) GetConfigFilePath(relativePath string) string {
	return filepath.Join(wr.baseConfigDir, relativePath)
}

// ResolveWordlistPaths takes wordlist types and resolves them to actual file paths
func (wr *WordlistResolver) ResolveWordlistPaths(wordlistTypes []pentestfern.WordlistType) ([]string, error) {
	if len(wordlistTypes) == 0 {
		return []string{}, nil
	}

	var paths []string
	for _, wordlistType := range wordlistTypes {
		path, err := wr.getWordlistPath(wordlistType)
		if err != nil {
			return nil, err
		}
		if path != "" {
			paths = append(paths, path)
		}
	}

	return paths, nil
}

// getWordlistPath returns the file path for a specific wordlist type
func (wr *WordlistResolver) getWordlistPath(wordlistType pentestfern.WordlistType) (string, error) {
	switch wordlistType {
	case pentestfern.WordlistTypeSystemPasswords:
		return filepath.Join(wr.baseConfigDir, "pentest", "spray", "system_passwords.txt"), nil
	case pentestfern.WordlistTypeSystemUsernames:
		return filepath.Join(wr.baseConfigDir, "pentest", "spray", "system_usernames.txt"), nil
	case pentestfern.WordlistTypeDomainPasswords:
		return filepath.Join(wr.baseConfigDir, "pentest", "spray", "domain_passwords.txt"), nil
	case pentestfern.WordlistTypeDomainUsernames:
		return filepath.Join(wr.baseConfigDir, "pentest", "spray", "domain_usernames.txt"), nil
	case pentestfern.WordlistTypeServicePasswords:
		return filepath.Join(wr.baseConfigDir, "pentest", "spray", "service_passwords.txt"), nil
	case pentestfern.WordlistTypeServiceUsernames:
		return filepath.Join(wr.baseConfigDir, "pentest", "spray", "service_usernames.txt"), nil
	case pentestfern.WordlistTypeCustom:
		// Custom wordlists should be handled elsewhere - return empty path
		return "", nil
	default:
		return "", fmt.Errorf("unsupported wordlist type: %s", wordlistType)
	}
}

// LoadWordlistEntries loads entries from resolved wordlist paths
func (wr *WordlistResolver) LoadWordlistEntries(wordlistTypes []pentestfern.WordlistType) ([]string, error) {
	paths, err := wr.ResolveWordlistPaths(wordlistTypes)
	if err != nil {
		return nil, err
	}

	if len(paths) == 0 {
		return []string{}, nil
	}

	return GetEntriesFromTXTFiles(paths)
}

// GetPasswordWordlists loads password wordlists based on the config
func (wr *WordlistResolver) GetPasswordWordlists(passwordLists []pentestfern.WordlistType) ([]string, error) {
	return wr.LoadWordlistEntries(passwordLists)
}

// GetUsernameWordlists loads username wordlists based on the config
func (wr *WordlistResolver) GetUsernameWordlists(usernameLists []pentestfern.WordlistType) ([]string, error) {
	return wr.LoadWordlistEntries(usernameLists)
}

// ParseWordlistTypes converts string slice to WordlistType enums
func ParseWordlistTypes(wordlistStrings []string) ([]pentestfern.WordlistType, error) {
	if len(wordlistStrings) == 0 {
		return []pentestfern.WordlistType{}, nil
	}

	var wordlistTypes []pentestfern.WordlistType
	for _, list := range wordlistStrings {
		wordlistType, err := pentestfern.NewWordlistTypeFromString(list)
		if err != nil {
			return nil, fmt.Errorf("invalid wordlist type '%s': %v", list, err)
		}
		wordlistTypes = append(wordlistTypes, wordlistType)
	}

	return wordlistTypes, nil
}
