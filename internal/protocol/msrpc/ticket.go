package msrpc

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/RedTeamPentesting/adauth"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
)

// SetupKerberosTicketWithHostname creates ccache file, extracts hostname, and sets KRB5CCNAME
// Returns: extractedHostname, cleanup function, error
func SetupKerberosTicketWithHostname(ticketBase64 string) (string, func(), error) {
	// Decode base64 ccache
	cacheBytes, err := base64.StdEncoding.DecodeString(ticketBase64)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode Kerberos ticket: %w", err)
	}

	// Parse ccache to extract hostname from SPN
	var ccache credentials.CCache
	err = ccache.Unmarshal(cacheBytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse ccache: %w", err)
	}

	var extractedHostname string
	if len(ccache.Credentials) > 0 {
		// Extract hostname from the first service ticket SPN
		for _, cred := range ccache.Credentials {
			spn := cred.Server.PrincipalName.PrincipalNameString()

			// Extract hostname from SPN (e.g., "cifs/NYC-DC01.corp.auric-dynamics.com" -> "NYC-DC01.corp.auric-dynamics.com")
			if strings.Contains(spn, "/") {
				parts := strings.SplitN(spn, "/", 2)
				if len(parts) == 2 {
					extractedHostname = parts[1]
					break
				}
			}
		}
	}

	// Create temporary ccache file
	tempDir := os.TempDir()
	ccacheFile := filepath.Join(tempDir, fmt.Sprintf("krb5cc_networkscan_%d", os.Getpid()))

	// Write ccache bytes to temporary file (unmodified)
	err = os.WriteFile(ccacheFile, cacheBytes, 0600)
	if err != nil {
		return "", nil, fmt.Errorf("failed to write ccache file: %w", err)
	}

	// Verify file was created
	if _, err := os.Stat(ccacheFile); err != nil {
		_ = os.Remove(ccacheFile) // Best effort cleanup
		return "", nil, fmt.Errorf("ccache file not created: %w", err)
	}

	// Set environment variable so adauth can find it automatically
	originalKRB5CCNAME := os.Getenv("KRB5CCNAME")
	_ = os.Setenv("KRB5CCNAME", ccacheFile) // Environment setting errors are rare

	// Return cleanup function that restores environment and removes file
	cleanup := func() {
		if originalKRB5CCNAME != "" {
			_ = os.Setenv("KRB5CCNAME", originalKRB5CCNAME) // Best effort restore
		} else {
			_ = os.Unsetenv("KRB5CCNAME") // Best effort restore
		}
		_ = os.Remove(ccacheFile) // Best effort cleanup
	}

	return extractedHostname, cleanup, nil
}

// SetupAdauthOptions configures adauth options for authentication
func SetupAdauthOptions(username, domain, extractedHostname, fallbackTarget string, kerberosTicket *string, password string, ntlmHash *string) (*adauth.Options, error) {
	if username == "" {
		return nil, fmt.Errorf("no username provided for authentication")
	}

	// Create basic adauth options
	opts := &adauth.Options{
		User: fmt.Sprintf("%s\\%s", domain, username),
	}

	// Set DomainController - prefer extracted hostname from ticket, otherwise use target
	if extractedHostname != "" {
		opts.DomainController = extractedHostname
	} else {
		// Use the target host as the domain controller to avoid DNS lookups
		opts.DomainController = fallbackTarget
	}

	// For Kerberos tickets, set CCache from KRB5CCNAME environment variable
	if kerberosTicket != nil && *kerberosTicket != "" {
		// adauth will auto-detect KRB5CCNAME from environment
		if ccachePath := os.Getenv("KRB5CCNAME"); ccachePath != "" {
			opts.CCache = ccachePath
		}
		return opts, nil
	}

	// For non-Kerberos auth, set the credentials explicitly
	hasPassword := password != ""
	hasNtlmHash := ntlmHash != nil && *ntlmHash != ""

	if !hasPassword && !hasNtlmHash {
		return nil, fmt.Errorf("authentication requires either password, NTLM hash, or Kerberos ticket credentials")
	}

	// Check for NTLM hash authentication first
	if hasNtlmHash {
		opts.NTHash = *ntlmHash
	} else if hasPassword {
		opts.Password = password
	}

	return opts, nil
}
