package utils

import (
	"strings"

	"github.com/Method-Security/networkscan/generated/go/pentest"
)

// loadNamesFromFile loads names from config files
func loadNamesFromFile(filename string) ([]string, error) {
	entries, err := GetEntriesFromTXTFiles([]string{"configs/pentest/spray/" + filename})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// getFirstNames loads first names from file
func getFirstNames() ([]string, error) {
	return loadNamesFromFile("first_names.txt")
}

// getLastNames loads last names from file
func getLastNames() ([]string, error) {
	return loadNamesFromFile("last_names.txt")
}

// GenerateUsernamesByScheme generates usernames based on the specified scheme
func GenerateUsernamesByScheme(scheme pentest.UsernameScheme) ([]string, error) {
	firstNames, err := getFirstNames()
	if err != nil {
		return nil, err
	}

	lastNames, err := getLastNames()
	if err != nil {
		return nil, err
	}

	return generateUsernamesOptimized(firstNames, lastNames, scheme, 0), nil
}

// GenerateUsernamesWithLimit generates a limited number of usernames based on the scheme
func GenerateUsernamesWithLimit(scheme pentest.UsernameScheme, limit int) ([]string, error) {
	firstNames, err := getFirstNames()
	if err != nil {
		return nil, err
	}

	lastNames, err := getLastNames()
	if err != nil {
		return nil, err
	}

	return generateUsernamesOptimized(firstNames, lastNames, scheme, limit), nil
}

// generateUsernamesOptimized generates usernames with scheme-specific optimizations
func generateUsernamesOptimized(firstNames, lastNames []string, scheme pentest.UsernameScheme, limit int) []string {
	usernameSet := make(map[string]struct{})

	switch scheme {
	case pentest.UsernameSchemeFlast, pentest.UsernameSchemeFLast:
		// For schemes that only use first letter, generate a-z + last names
		for letter := 'a'; letter <= 'z'; letter++ {
			for _, lastName := range lastNames {
				var username string
				if scheme == pentest.UsernameSchemeFLast {
					username = string(letter) + "_" + strings.ToLower(lastName)
				} else {
					username = string(letter) + strings.ToLower(lastName)
				}
				usernameSet[username] = struct{}{}

				if limit > 0 && len(usernameSet) >= limit {
					break
				}
			}
			if limit > 0 && len(usernameSet) >= limit {
				break
			}
		}
	case pentest.UsernameSchemeLast:
		// For last name only, just use last names
		for _, lastName := range lastNames {
			username := strings.ToLower(lastName)
			usernameSet[username] = struct{}{}

			if limit > 0 && len(usernameSet) >= limit {
				break
			}
		}
	case pentest.UsernameSchemeFirst:
		// For first name only, just use first names
		for _, firstName := range firstNames {
			username := strings.ToLower(firstName)
			usernameSet[username] = struct{}{}

			if limit > 0 && len(usernameSet) >= limit {
				break
			}
		}
	default:
		// For other schemes, use the full Cartesian product
		for _, firstName := range firstNames {
			for _, lastName := range lastNames {
				username := generateUsername(firstName, lastName, scheme)
				usernameSet[username] = struct{}{}

				if limit > 0 && len(usernameSet) >= limit {
					break
				}
			}
			if limit > 0 && len(usernameSet) >= limit {
				break
			}
		}
	}

	// Convert set to slice
	var usernames []string
	for username := range usernameSet {
		usernames = append(usernames, username)
	}

	return usernames
}

// generateUsername creates a username based on the naming scheme
func generateUsername(firstName, lastName string, scheme pentest.UsernameScheme) string {
	// Ensure names are lowercase for consistency
	first := strings.ToLower(firstName)
	last := strings.ToLower(lastName)

	switch scheme {
	case pentest.UsernameSchemeFlast:
		// first letter + last name (jsmith)
		if len(first) > 0 {
			return string(first[0]) + last
		}
		return last
	case pentest.UsernameSchemeFirstDotLast:
		// first name + dot + last name (john.smith)
		return first + "." + last
	case pentest.UsernameSchemeFirstlast:
		// first name + last name (johnsmith)
		return first + last
	case pentest.UsernameSchemeLastfirst:
		// last name + first name (smithjohn)
		return last + first
	case pentest.UsernameSchemeFirst:
		// first name only (john)
		return first
	case pentest.UsernameSchemeLast:
		// last name only (smith)
		return last
	case pentest.UsernameSchemeFLast:
		// first letter + underscore + last name (j_smith) - This is F_LAST
		if len(first) > 0 {
			return string(first[0]) + "_" + last
		}
		return last
	case pentest.UsernameSchemeFirstLast:
		// first name + underscore + last name (john_smith) - This is FIRST_LAST
		return first + "_" + last
	default:
		// Default to flast if unknown scheme
		if len(first) > 0 {
			return string(first[0]) + last
		}
		return last
	}
}

// GetUsernameSchemeDescription returns a human-readable description of the scheme
func GetUsernameSchemeDescription(scheme pentest.UsernameScheme) string {
	switch scheme {
	case pentest.UsernameSchemeFlast:
		return "First letter + last name (jsmith)"
	case pentest.UsernameSchemeFirstDotLast:
		return "First name + dot + last name (john.smith)"
	case pentest.UsernameSchemeFirstlast:
		return "First name + last name (johnsmith)"
	case pentest.UsernameSchemeLastfirst:
		return "Last name + first name (smithjohn)"
	case pentest.UsernameSchemeFirst:
		return "First name only (john)"
	case pentest.UsernameSchemeLast:
		return "Last name only (smith)"
	case pentest.UsernameSchemeFLast:
		return "First letter + underscore + last name (j_smith)"
	case pentest.UsernameSchemeFirstLast:
		return "First name + underscore + last name (john_smith)"
	default:
		return "Unknown scheme"
	}
}
