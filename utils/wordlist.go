// Package utils provides wordlist resolution utilities for the networkscan application.
package utils

import (
	"fmt"

	"github.com/Method-Security/networkscan/configs"
	pentestfern "github.com/Method-Security/networkscan/generated/go/pentest"
)

// resolveWordlistPaths returns the embedded config paths for the given wordlist types.
func resolveWordlistPaths(wordlistTypes []pentestfern.WordlistType) ([]string, error) {
	if len(wordlistTypes) == 0 {
		return []string{}, nil
	}

	var paths []string
	for _, wordlistType := range wordlistTypes {
		p, err := getWordlistConfigPath(wordlistType)
		if err != nil {
			return nil, err
		}
		if p != "" {
			paths = append(paths, p)
		}
	}

	return paths, nil
}

// getWordlistConfigPath returns the embedded config path for a specific wordlist type.
func getWordlistConfigPath(wordlistType pentestfern.WordlistType) (string, error) {
	switch wordlistType {
	case pentestfern.WordlistTypeSystemPasswords:
		return "pentest/spray/system_passwords.txt", nil
	case pentestfern.WordlistTypeSystemUsernames:
		return "pentest/spray/system_usernames.txt", nil
	case pentestfern.WordlistTypeDomainPasswords:
		return "pentest/spray/domain_passwords.txt", nil
	case pentestfern.WordlistTypeDomainUsernames:
		return "pentest/spray/domain_usernames.txt", nil
	case pentestfern.WordlistTypeServicePasswords:
		return "pentest/spray/service_passwords.txt", nil
	case pentestfern.WordlistTypeServiceUsernames:
		return "pentest/spray/service_usernames.txt", nil
	case pentestfern.WordlistTypeCustom:
		return "", nil
	default:
		return "", fmt.Errorf("unsupported wordlist type: %s", wordlistType)
	}
}

// loadWordlistEntries loads entries from embedded wordlists for the given types.
func loadWordlistEntries(wordlistTypes []pentestfern.WordlistType) ([]string, error) {
	paths, err := resolveWordlistPaths(wordlistTypes)
	if err != nil {
		return nil, err
	}

	if len(paths) == 0 {
		return []string{}, nil
	}

	return configs.ReadMultipleLineFiles(paths)
}

// GetPasswordWordlists loads password wordlists based on the config.
func GetPasswordWordlists(passwordLists []pentestfern.WordlistType) ([]string, error) {
	return loadWordlistEntries(passwordLists)
}

// GetUsernameWordlists loads username wordlists based on the config.
func GetUsernameWordlists(usernameLists []pentestfern.WordlistType) ([]string, error) {
	return loadWordlistEntries(usernameLists)
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
