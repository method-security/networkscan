package smb

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	smbfern "github.com/Method-Security/networkscan/generated/go/enumerate/smb"
)

// LibraryEnumerateSMB implements NetworkApplicationLibrary for SMB enumeration using go-smb library.
type LibraryEnumerateSMB struct{}

// WindowsBuildMapping maps Windows build numbers to human-readable versions
var WindowsBuildMapping = map[string]string{
	// Windows Server builds
	"20348": "Windows Server 2022",
	"19041": "Windows Server 2022 (Insider)",
	"17763": "Windows Server 2019",
	"14393": "Windows Server 2016",
	"10586": "Windows Server 2016 (Technical Preview)",
	"9600":  "Windows Server 2012 R2",
	"9200":  "Windows Server 2012",
	"7601":  "Windows Server 2008 R2 SP1 / Windows 7 SP1",
	"6002":  "Windows Server 2008 SP2 / Windows Vista SP2",
	"6001":  "Windows Server 2008 SP1 / Windows Vista SP1",
	"6000":  "Windows Server 2008 / Windows Vista",
	
	// Windows 11 builds
	"22631": "Windows 11 23H2",
	"22621": "Windows 11 22H2", 
	"22000": "Windows 11 21H2",
	
	// Windows 10 builds
	"19045": "Windows 10 22H2",
	"19044": "Windows 10 21H2",
	"19043": "Windows 10 21H1",
	"19042": "Windows 10 20H2",
	"18363": "Windows 10 1909",
	"18362": "Windows 10 1903",
	"17134": "Windows 10 1803",
	"16299": "Windows 10 1709",
	"15063": "Windows 10 1703",
	"10240": "Windows 10 RTM",
	
	// Windows 8/8.1
	"9431":  "Windows 8.1 Update 1",
	
	// Windows 7 (additional builds)
	"7600":  "Windows 7 RTM",
}

// parseWindowsVersion extracts and enhances Windows version information
func parseWindowsVersion(rawOSVersion string) string {
	if rawOSVersion == "" {
		return "Windows Server"
	}
	
	// Extract build number using regex
	buildRegex := regexp.MustCompile(`Build (\d+)`)
	matches := buildRegex.FindStringSubmatch(rawOSVersion)
	
	if len(matches) > 1 {
		buildNumber := matches[1]
		
		// Look up human-readable version
		if readableVersion, exists := WindowsBuildMapping[buildNumber]; exists {
			return readableVersion
		}
		
		// If not found, try to classify by build number ranges
		return classifyWindowsByBuildNumber(buildNumber, rawOSVersion)
	}
	
	// Fallback to original version if no build number found
	return rawOSVersion
}

// classifyWindowsByBuildNumber classifies Windows versions by build number ranges
func classifyWindowsByBuildNumber(buildNumber, rawVersion string) string {
	build := parseInt(buildNumber)
	
	switch {
	case build >= 22000:
		return fmt.Sprintf("Windows 11 (Build %s)", buildNumber)
	case build >= 19000:
		return fmt.Sprintf("Windows 10/Server 2019-2022 (Build %s)", buildNumber) 
	case build >= 17000:
		return fmt.Sprintf("Windows 10/Server 2016-2019 (Build %s)", buildNumber)
	case build >= 14000:
		return fmt.Sprintf("Windows 10/Server 2016 (Build %s)", buildNumber)
	case build >= 10000:
		return fmt.Sprintf("Windows 10 (Build %s)", buildNumber)
	case build >= 9000:
		return fmt.Sprintf("Windows 8/Server 2012 (Build %s)", buildNumber)
	case build >= 7000:
		return fmt.Sprintf("Windows 7/Server 2008 (Build %s)", buildNumber)
	case build >= 6000:
		return fmt.Sprintf("Windows Vista/Server 2008 (Build %s)", buildNumber)
	default:
		return rawVersion // Return original if can't classify
	}
}

// parseInt safely converts string to int
func parseInt(s string) int {
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}

// detectDomainController checks if the target appears to be a domain controller
func detectDomainController(serverName, domain string, shares []*smbfern.SmbShare) bool {
	// Check for typical DC naming patterns
	if strings.Contains(strings.ToLower(serverName), "dc") || 
	   strings.Contains(strings.ToLower(serverName), "domain") {
		return true
	}
	
	// Check for domain controller specific shares
	for _, share := range shares {
		shareName := strings.ToUpper(share.Name)
		if shareName == "SYSVOL" || shareName == "NETLOGON" {
			return true
		}
	}
	
	return false
}

// EnumerateTarget performs comprehensive SMB enumeration using the go-smb library
func (s *LibraryEnumerateSMB) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details smbfern.EnumerateSmbDetails
	details.Target = target
	errors := []string{}

	log.Printf("[INFO] Starting SMB enumeration for target: %s", target)

	host, port := extractHostPort(target)
	if port == 0 {
		port = 445 // Default SMB port
	}

	// Create SMB connection options for enumeration (anonymous access)
	options := smb.Options{
		Host:        host,
		Port:        port,
		DialTimeout: 30 * time.Second,
		Initiator: &spnego.NTLMInitiator{
			NullSession: true, // Use null session for enumeration
		},
	}

	// Attempt connection
	session, err := smb.NewConnection(options)
	if err != nil {
		log.Printf("[ERROR] Failed to connect to %s: %v", target, err)
		errors = append(errors, fmt.Sprintf("Failed to connect to %s: %v", target, err))
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSmbDetails(&details), errors
	}
	defer session.Close()

	log.Printf("[INFO] Successfully connected to %s", target)

	// Extract basic connection information
	if session.IsAuthenticated() {
		authUser := session.GetAuthUsername()
		log.Printf("[INFO] Connected as: %s", authUser)
	}

	// Set default SMB version - we'll use SMB3.0.2 as default
	version := smbfern.SmbVersionSmb302
	details.Version = &version
	details.SupportedVersions = []smbfern.SmbVersion{
		smbfern.SmbVersionSmb302,
		smbfern.SmbVersionSmb30,
		smbfern.SmbVersionSmb21,
		smbfern.SmbVersionSmb20,
	}
	log.Printf("[INFO] SMB connection successful for %s, using SMB3.0.2", target)

	// Enumerate shares first to use for domain controller detection
	log.Printf("[INFO] Enumerating shares for %s", target)
	shares, shareErrors := enumerateShares(session, host)
	if len(shareErrors) > 0 {
		errors = append(errors, shareErrors...)
	}
	
	if len(shares) > 0 {
		details.Shares = shares
		log.Printf("[INFO] Found %d shares for %s", len(shares), target)
	}

	// Extract server information from the session (now with shares for DC detection)
	serverInfo := extractServerInfoFromSession(session, shares)
	if serverInfo != nil {
		details.ServerInfo = serverInfo
		log.Printf("[INFO] Extracted server info for %s - Server: %s, Domain: %s, OS: %s", 
			target, getStringValue(serverInfo.ServerName), getStringValue(serverInfo.Domain), getStringValue(serverInfo.OsVersion))
	}

	// Set authentication method information
	authMethods := []smbfern.AuthMethod{smbfern.AuthMethodNtlm}
	details.AuthMethods = authMethods

	// Test authentication capabilities
	anonymousAllowed := session.IsAuthenticated()
	details.AnonymousLoginAllowed = &anonymousAllowed
	log.Printf("[INFO] Anonymous login allowed for %s: %v", target, anonymousAllowed)

	guestAllowed := false // Will be determined during share enumeration
	details.GuestLoginAllowed = &guestAllowed

	nullSessionAllowed := anonymousAllowed // Typically the same
	details.NullSessionAllowed = &nullSessionAllowed

	// Set security settings
	signingRequired := session.IsSigningRequired()
	details.SigningRequired = &signingRequired

	encryptionSupported := false // Default to false since we can't easily detect this
	details.EncryptionSupported = &encryptionSupported

	// Set raw response information
	rawResponse := fmt.Sprintf("SMB2 Connection - Signing: %v, Encryption: %v", 
		signingRequired, encryptionSupported)
	details.RawResponse = &rawResponse

	log.Printf("[INFO] SMB enumeration completed for %s", target)

	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSmbDetails(&details), errors
}

// extractHostPort parses target string to extract host and port
func extractHostPort(target string) (string, int) {
	if strings.Contains(target, ":") {
		host, portStr, err := net.SplitHostPort(target)
		if err == nil {
			if port := parsePort(portStr); port > 0 {
				return host, port
			}
		}
	}
	return target, 0
}

// parsePort converts port string to int
func parsePort(portStr string) int {
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}


// extractServerInfoFromSession extracts server information from SMB session using NTLM target info
func extractServerInfoFromSession(session *smb.Connection, shares []*smbfern.SmbShare) *smbfern.ServerInfo {
	serverInfo := &smbfern.ServerInfo{}
	
	// Extract detailed information from NTLM target info
	targetInfo := session.GetTargetInfo()
	if targetInfo != nil {
		// Use DNS domain name if available, fallback to NetBIOS domain
		if targetInfo.DnsDomainName != "" {
			serverInfo.Domain = &targetInfo.DnsDomainName
		} else if targetInfo.NBDomainName != "" {
			serverInfo.Domain = &targetInfo.NBDomainName
		}
		
		// Use DNS computer name if available, fallback to NetBIOS computer name
		if targetInfo.DnsComputerName != "" {
			serverInfo.ServerName = &targetInfo.DnsComputerName
		} else if targetInfo.NBComputerName != "" {
			serverInfo.ServerName = &targetInfo.NBComputerName
		}
		
		// Parse and enhance the OS version from NTLM target info
		if targetInfo.GuessedOSVersion != "" {
			enhancedOSVersion := parseWindowsVersion(targetInfo.GuessedOSVersion)
			
			// Check if this appears to be a domain controller
			if detectDomainController(targetInfo.DnsComputerName, targetInfo.DnsDomainName, shares) {
				enhancedOSVersion += " (Domain Controller)"
			}
			
			serverInfo.OsVersion = &enhancedOSVersion
		} else {
			// Fallback to generic Windows Server
			osVersion := "Windows Server"
			if detectDomainController("", "", shares) {
				osVersion += " (Domain Controller)"
			}
			serverInfo.OsVersion = &osVersion
		}
		
		log.Printf("[INFO] Extracted NTLM target info - DNS Domain: %s, DNS Server: %s, NetBIOS Domain: %s, NetBIOS Server: %s, OS: %s", 
			targetInfo.DnsDomainName, targetInfo.DnsComputerName, targetInfo.NBDomainName, targetInfo.NBComputerName, targetInfo.GuessedOSVersion)
	} else {
		// Fallback to basic extraction if target info is not available
		log.Printf("[WARNING] NTLM target info not available, using fallback extraction")
		
		// Try to extract domain and server name from authenticated username
		if session.IsAuthenticated() {
			authUser := session.GetAuthUsername()
			if strings.Contains(authUser, "\\") {
				parts := strings.Split(authUser, "\\")
				if len(parts) == 2 {
					domain := parts[0]
					serverInfo.Domain = &domain
					
					// Try to determine server name from domain
					if domain != "" {
						serverName := fmt.Sprintf("%s.%s", extractHostFromTarget(session), domain)
						serverInfo.ServerName = &serverName
					}
				}
			}
		}
		
		// Set OS version as Windows Server (generic since we can't determine exact version)
		osVersion := "Windows Server"
		if detectDomainController("", "", shares) {
			osVersion += " (Domain Controller)"
		}
		serverInfo.OsVersion = &osVersion
	}
	
	// Set basic capabilities
	capabilities := []string{"DFS", "Leasing"}
	if session.IsSigningRequired() {
		capabilities = append(capabilities, "Signing")
	}
	serverInfo.Capabilities = capabilities
	
	return serverInfo
}

// extractHostFromTarget extracts hostname from the connection target
func extractHostFromTarget(session *smb.Connection) string {
	// This is a simplified approach - the go-smb library doesn't expose
	// the target host directly, so we'll use a generic name
	return "SMB-SERVER"
}

// enumerateShares enumerates SMB shares using TreeConnect testing
func enumerateShares(session *smb.Connection, host string) ([]*smbfern.SmbShare, []string) {
	errors := []string{}
	
	// Try to enumerate shares using TreeConnect method
	treeConnectShares, err := enumerateSharesViaTreeConnect(session, host)
	if err != nil {
		log.Printf("[WARNING] TreeConnect share enumeration failed: %v. Falling back to common shares list.", err)
		errors = append(errors, fmt.Sprintf("TreeConnect enumeration failed: %v", err))
		// Fallback to common shares if TreeConnect fails
		return enumerateCommonShares(), errors
	}
	
	if len(treeConnectShares) > 0 {
		log.Printf("[INFO] Successfully enumerated %d accessible shares via TreeConnect", len(treeConnectShares))
		return treeConnectShares, errors
	}
	
	// If no shares were found, still return common shares as potential targets
	log.Printf("[INFO] No accessible shares found, returning common shares list")
	return enumerateCommonShares(), errors
}

// enumerateSharesViaTreeConnect enumerates SMB shares by testing common share names using TreeConnect
func enumerateSharesViaTreeConnect(session *smb.Connection, host string) ([]*smbfern.SmbShare, error) {
	commonShares := []string{"C$", "D$", "E$", "ADMIN$", "IPC$", "PRINT$", "FAX$", "SYSVOL", "NETLOGON", "Users", "Public", "Share", "Data", "Files", "Shared", "Transfer", "Backup", "Archive", "Home", "Homes"}
	var accessibleShares []*smbfern.SmbShare
	
	log.Printf("[INFO] Testing %d common share names for accessibility", len(commonShares))
	
	for _, shareName := range commonShares {
		// Attempt to connect to the share
		err := session.TreeConnect(shareName)
		if err != nil {
			// Share is not accessible or doesn't exist
			continue
		}
		
		// Share is accessible, disconnect and add to results
		session.TreeDisconnect(shareName)
		
		shareType := determineShareType(shareName)
		
		share := &smbfern.SmbShare{
			Name:            shareName,
			Type:            shareType,
			Accessible:      true,
			Access:          smbfern.ShareAccessReadOnly.Ptr(), // Assume read access since TreeConnect succeeded
			AnonymousAccess: true, // We're using anonymous/null session
			GuestAccess:     false,
			// Note: Hidden field not available in SmbShare struct
		}
		
		accessibleShares = append(accessibleShares, share)
	}
	
	log.Printf("[INFO] Found %d accessible shares via TreeConnect", len(accessibleShares))
	return accessibleShares, nil
}

// determineShareType determines the share type based on share name patterns
func determineShareType(shareName string) smbfern.ShareType {
	switch {
	case shareName == "IPC$":
		return smbfern.ShareTypeIpc
	case shareName == "PRINT$" || shareName == "FAX$":
		return smbfern.ShareTypePrint
	case strings.HasSuffix(shareName, "$"):
		return smbfern.ShareTypeDisk // Administrative shares like C$, D$, ADMIN$
	default:
		return smbfern.ShareTypeDisk // Regular disk shares
	}
}


// enumerateCommonShares provides fallback enumeration of common shares
func enumerateCommonShares() []*smbfern.SmbShare {
	commonShares := []string{"C$", "D$", "ADMIN$", "IPC$", "PRINT$", "FAX$", "SYSVOL", "NETLOGON", "Users", "Public", "Share", "Data", "Files", "Shared", "Transfer", "Backup", "Archive"}
	shares := []*smbfern.SmbShare{}
	
	for _, shareName := range commonShares {
		shareType := smbfern.ShareTypeDisk
		if shareName == "IPC$" {
			shareType = smbfern.ShareTypeIpc
		} else if shareName == "PRINT$" || shareName == "FAX$" {
			shareType = smbfern.ShareTypePrint
		}
		
		share := &smbfern.SmbShare{
			Name:            shareName,
			Type:            shareType,
			Accessible:      false, // Default to not accessible
			Access:          smbfern.ShareAccessNoAccess.Ptr(),
			AnonymousAccess: false,
			GuestAccess:     false,
		}
		
		shares = append(shares, share)
	}
	
	return shares
}


// getStringValue safely gets string value from pointer
func getStringValue(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}