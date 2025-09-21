package ntlm

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/rbetts/go-ntlm/ntlm/messages"
)

// ExtractServerInfoFromChallenge extracts server information from NTLM Type 2 challenge message
func ExtractServerInfoFromChallenge(challengeMessage []byte, log svc1log.Logger) (*commonprotocolfern.NtlmServerInfo, error) {
	// Parse the NTLM Type 2 challenge message
	c, err := messages.ParseChallengeMessage(challengeMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NTLM challenge message: %v", err)
	}

	if c.TargetInfo == nil {
		return nil, fmt.Errorf("no target info in NTLM challenge message")
	}

	ti := c.TargetInfo
	result := &commonprotocolfern.NtlmServerInfo{}

	// Extract target info fields
	var nbDomain, nbComputer, dnsDomain, dnsComputer string
	if nb := ti.StringValue(messages.MsvAvNbDomainName); nb != "" {
		nbDomain = nb
	}

	if nb := ti.StringValue(messages.MsvAvNbComputerName); nb != "" {
		nbComputer = nb
	}

	if dns := ti.StringValue(messages.MsvAvDnsDomainName); dns != "" {
		dnsDomain = dns
	}

	if dns := ti.StringValue(messages.MsvAvDnsComputerName); dns != "" {
		dnsComputer = dns
	}

	// Create and populate the NtlmTargetInfo structure
	ntlmTargetInfo := &commonprotocolfern.NtlmTargetInfo{
		NetbiosDomainName:   stringToPtr(nbDomain),
		NetbiosComputerName: stringToPtr(nbComputer),
		DnsDomainName:       stringToPtr(dnsDomain),
		DnsComputerName:     stringToPtr(dnsComputer),
		DnsTreeName:         stringToPtr(dnsDomain), // Usually same as DNS domain
	}
	result.TargetInfo = ntlmTargetInfo

	// Extract OS version information from NTLM Version struct if available
	var rawOSVersion, osVersion string
	var ntlmOsInfo *commonprotocolfern.NtlmOsInfo
	if c.Version != nil {
		// Build raw OS version string from version struct
		rawOSVersion = fmt.Sprintf("Windows NT %d.%d Build %d",
			c.Version.ProductMajorVersion,
			c.Version.ProductMinorVersion,
			c.Version.ProductBuild)

		// Parse to human-readable version
		osVersion = ParseWindowsVersion(rawOSVersion)

		// Create formatted version string matching the NTLM challenge format
		majorVersion := int(c.Version.ProductMajorVersion)
		minorVersion := int(c.Version.ProductMinorVersion)
		buildNumber := int(c.Version.ProductBuild)
		ntlmRevision := int(c.Version.NTLMRevisionCurrent)
		versionString := fmt.Sprintf("Version %d.%d (Build %d); NTLM Current Revision %d",
			majorVersion, minorVersion, buildNumber, ntlmRevision)

		ntlmOsInfo = &commonprotocolfern.NtlmOsInfo{
			MajorVersion:        &majorVersion,
			MinorVersion:        &minorVersion,
			BuildNumber:         &buildNumber,
			NtlmCurrentRevision: &ntlmRevision,
			VersionString:       &versionString,
			RawVersionData:      &rawOSVersion,
		}

		result.MappedOsVersion = &osVersion
	}
	result.OsInfo = ntlmOsInfo

	// Set signing requirement based on NTLM flags
	signingRequired := (c.NegotiateFlags & 0x00040000) != 0 // NTLMSSP_NEGOTIATE_SIGN
	result.SigningRequired = &signingRequired

	// Log detailed extraction info
	log.Info("Extracted unified server info from NTLM challenge",
		svc1log.SafeParam("nbDomain", nbDomain),
		svc1log.SafeParam("nbComputer", nbComputer),
		svc1log.SafeParam("dnsDomain", dnsDomain),
		svc1log.SafeParam("dnsComputer", dnsComputer),
		svc1log.SafeParam("flags", fmt.Sprintf("0x%08x", c.NegotiateFlags)))

	return result, nil
}

// ConvertToLDAPServerInfo converts common NTLM server info to LDAP-specific format
func ConvertToLDAPServerInfo(ntlmInfo *commonprotocolfern.NtlmServerInfo) *commonprotocolfern.LdapServerInfo {
	result := &commonprotocolfern.LdapServerInfo{}

	// Copy core fields that exist in cleaned structure
	if ntlmInfo.MappedOsVersion != nil {
		result.MappedOsVersion = ntlmInfo.MappedOsVersion
	}
	if ntlmInfo.SigningRequired != nil {
		result.SigningRequired = ntlmInfo.SigningRequired
	}

	// Copy nested structures
	if ntlmInfo.TargetInfo != nil {
		result.TargetInfo = ntlmInfo.TargetInfo
	}
	if ntlmInfo.OsInfo != nil {
		result.OsInfo = ntlmInfo.OsInfo
	}

	// Generate LDAP-specific base DN from nested TargetInfo
	if ntlmInfo.TargetInfo != nil {
		if ntlmInfo.TargetInfo.DnsDomainName != nil && *ntlmInfo.TargetInfo.DnsDomainName != "" {
			baseDN := convertDNSDomainToBaseDN(*ntlmInfo.TargetInfo.DnsDomainName)
			result.BaseDn = &baseDN
		} else if ntlmInfo.TargetInfo.NetbiosDomainName != nil && *ntlmInfo.TargetInfo.NetbiosDomainName != "" {
			baseDN := fmt.Sprintf("DC=%s", *ntlmInfo.TargetInfo.NetbiosDomainName)
			result.BaseDn = &baseDN
		}
	}

	// Set LDAP-specific capabilities
	supportsTLS := false          // Default - would need more sophisticated detection
	supportsStartTLS := true      // Most modern servers support StartTLS
	supportsSASL := true          // NTLM is a SASL mechanism
	anonymousBindAllowed := false // Default for AD

	result.SupportsTls = &supportsTLS
	result.SupportsStartTls = &supportsStartTLS
	result.SupportsSasl = &supportsSASL
	result.AnonymousBindAllowed = &anonymousBindAllowed

	return result
}

// convertDNSDomainToBaseDN converts a DNS domain name to LDAP base DN format
// e.g., corp.auric-dynamics.com -> DC=corp,DC=auric-dynamics,DC=com
func convertDNSDomainToBaseDN(dnsDomain string) string {
	if dnsDomain == "" {
		return ""
	}

	parts := strings.Split(dnsDomain, ".")
	dcParts := make([]string, len(parts))
	for i, part := range parts {
		dcParts[i] = "DC=" + part
	}
	return strings.Join(dcParts, ",")
}

// ParseWindowsVersion extracts and enhances Windows version information
func ParseWindowsVersion(rawOSVersion string) string {
	if rawOSVersion == "" {
		return ""
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
	build, err := strconv.Atoi(buildNumber)
	if err != nil {
		return rawVersion
	}

	switch {
	case build >= 22000:
		return fmt.Sprintf("Windows 11 (Build %s)", buildNumber)
	case build >= 19000:
		return fmt.Sprintf("Windows 10 (Build %s)", buildNumber)
	case build >= 10000:
		return fmt.Sprintf("Windows 10 (Build %s)", buildNumber)
	case build >= 9600:
		return fmt.Sprintf("Windows 8.1 (Build %s)", buildNumber)
	case build >= 9200:
		return fmt.Sprintf("Windows 8 (Build %s)", buildNumber)
	case build >= 7600:
		return fmt.Sprintf("Windows 7 (Build %s)", buildNumber)
	case build >= 6000:
		return fmt.Sprintf("Windows Vista (Build %s)", buildNumber)
	default:
		return fmt.Sprintf("Windows (Build %s)", buildNumber)
	}
}

// stringToPtr converts a string to a pointer, returning nil for empty strings
func stringToPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// GetServerName extracts server name from server info, preferring DNS computer name
func GetServerName(serverInfo *commonprotocolfern.NtlmServerInfo) string {
	if serverInfo != nil && serverInfo.TargetInfo != nil {
		if serverInfo.TargetInfo.DnsComputerName != nil && *serverInfo.TargetInfo.DnsComputerName != "" {
			return *serverInfo.TargetInfo.DnsComputerName
		}
		if serverInfo.TargetInfo.NetbiosComputerName != nil && *serverInfo.TargetInfo.NetbiosComputerName != "" {
			return *serverInfo.TargetInfo.NetbiosComputerName
		}
	}
	return ""
}

// GetDomainName extracts domain name from server info, preferring DNS domain name
func GetDomainName(serverInfo *commonprotocolfern.NtlmServerInfo) string {
	if serverInfo != nil && serverInfo.TargetInfo != nil {
		if serverInfo.TargetInfo.DnsDomainName != nil && *serverInfo.TargetInfo.DnsDomainName != "" {
			return *serverInfo.TargetInfo.DnsDomainName
		}
		if serverInfo.TargetInfo.NetbiosDomainName != nil && *serverInfo.TargetInfo.NetbiosDomainName != "" {
			return *serverInfo.TargetInfo.NetbiosDomainName
		}
	}
	return ""
}

// GetOSVersion extracts parsed OS version from server info
func GetOSVersion(serverInfo *commonprotocolfern.NtlmServerInfo) string {
	if serverInfo != nil && serverInfo.MappedOsVersion != nil {
		return *serverInfo.MappedOsVersion
	}
	return ""
}

// GetSigningRequired extracts signing requirement from server info
func GetSigningRequired(serverInfo *commonprotocolfern.NtlmServerInfo) bool {
	if serverInfo != nil && serverInfo.SigningRequired != nil {
		return *serverInfo.SigningRequired
	}
	return false
}

// LogServerInfoDetails logs detailed server info with all available fields
func LogServerInfoDetails(serverInfo *commonprotocolfern.NtlmServerInfo, target string, log svc1log.Logger) {
	if serverInfo == nil {
		log.Debug("No server info available for logging", svc1log.SafeParam("target", target))
		return
	}

	// Extract main fields
	serverName := GetServerName(serverInfo)
	domain := GetDomainName(serverInfo)
	osVersion := GetOSVersion(serverInfo)
	signingRequired := GetSigningRequired(serverInfo)

	// Extract detailed TargetInfo fields
	var netbiosDomain, dnsDomain, dnsComputer, netbiosComputer string
	if serverInfo.TargetInfo != nil {
		if serverInfo.TargetInfo.NetbiosDomainName != nil {
			netbiosDomain = *serverInfo.TargetInfo.NetbiosDomainName
		}
		if serverInfo.TargetInfo.DnsDomainName != nil {
			dnsDomain = *serverInfo.TargetInfo.DnsDomainName
		}
		if serverInfo.TargetInfo.DnsComputerName != nil {
			dnsComputer = *serverInfo.TargetInfo.DnsComputerName
		}
		if serverInfo.TargetInfo.NetbiosComputerName != nil {
			netbiosComputer = *serverInfo.TargetInfo.NetbiosComputerName
		}
	}

	// Extract detailed OsInfo fields
	var majorVersion, minorVersion, buildNumber, ntlmRevision int
	var versionString string
	if serverInfo.OsInfo != nil {
		if serverInfo.OsInfo.MajorVersion != nil {
			majorVersion = *serverInfo.OsInfo.MajorVersion
		}
		if serverInfo.OsInfo.MinorVersion != nil {
			minorVersion = *serverInfo.OsInfo.MinorVersion
		}
		if serverInfo.OsInfo.BuildNumber != nil {
			buildNumber = *serverInfo.OsInfo.BuildNumber
		}
		if serverInfo.OsInfo.NtlmCurrentRevision != nil {
			ntlmRevision = *serverInfo.OsInfo.NtlmCurrentRevision
		}
		if serverInfo.OsInfo.VersionString != nil {
			versionString = *serverInfo.OsInfo.VersionString
		}
	}

	log.Info("Extracted detailed server info",
		svc1log.SafeParam("target", target),
		svc1log.SafeParam("serverName", serverName),
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("osVersion", osVersion),
		svc1log.SafeParam("signingRequired", signingRequired),
		// TargetInfo details
		svc1log.SafeParam("netbiosDomain", netbiosDomain),
		svc1log.SafeParam("dnsDomain", dnsDomain),
		svc1log.SafeParam("dnsComputer", dnsComputer),
		svc1log.SafeParam("netbiosComputer", netbiosComputer),
		// OsInfo details
		svc1log.SafeParam("osMajorVersion", majorVersion),
		svc1log.SafeParam("osMinorVersion", minorVersion),
		svc1log.SafeParam("osBuildNumber", buildNumber),
		svc1log.SafeParam("ntlmRevision", ntlmRevision),
		svc1log.SafeParam("osVersionString", versionString))
}

// GetSMBServerName extracts server name from SMB server info, preferring DNS computer name
func GetSMBServerName(serverInfo *commonprotocolfern.SmbServerInfo) string {
	if serverInfo != nil && serverInfo.TargetInfo != nil {
		if serverInfo.TargetInfo.DnsComputerName != nil && *serverInfo.TargetInfo.DnsComputerName != "" {
			return *serverInfo.TargetInfo.DnsComputerName
		}
		if serverInfo.TargetInfo.NetbiosComputerName != nil && *serverInfo.TargetInfo.NetbiosComputerName != "" {
			return *serverInfo.TargetInfo.NetbiosComputerName
		}
	}
	return ""
}

func GetSMBDomainName(serverInfo *commonprotocolfern.SmbServerInfo) string {
	if serverInfo != nil && serverInfo.TargetInfo != nil {
		if serverInfo.TargetInfo.DnsDomainName != nil && *serverInfo.TargetInfo.DnsDomainName != "" {
			return *serverInfo.TargetInfo.DnsDomainName
		}
		if serverInfo.TargetInfo.NetbiosDomainName != nil && *serverInfo.TargetInfo.NetbiosDomainName != "" {
			return *serverInfo.TargetInfo.NetbiosDomainName
		}
	}
	return ""
}

func GetSMBOSVersion(serverInfo *commonprotocolfern.SmbServerInfo) string {
	if serverInfo != nil && serverInfo.MappedOsVersion != nil {
		return *serverInfo.MappedOsVersion
	}
	return ""
}

func GetSMBSigningRequired(serverInfo *commonprotocolfern.SmbServerInfo) bool {
	if serverInfo != nil && serverInfo.SigningRequired != nil {
		return *serverInfo.SigningRequired
	}
	return false
}

// GetLDAPServerName extracts server name from LDAP server info, preferring DNS computer name
func GetLDAPServerName(serverInfo *commonprotocolfern.LdapServerInfo) string {
	if serverInfo != nil && serverInfo.TargetInfo != nil {
		if serverInfo.TargetInfo.DnsComputerName != nil && *serverInfo.TargetInfo.DnsComputerName != "" {
			return *serverInfo.TargetInfo.DnsComputerName
		}
		if serverInfo.TargetInfo.NetbiosComputerName != nil && *serverInfo.TargetInfo.NetbiosComputerName != "" {
			return *serverInfo.TargetInfo.NetbiosComputerName
		}
	}
	return ""
}

func GetLDAPDomainName(serverInfo *commonprotocolfern.LdapServerInfo) string {
	if serverInfo != nil && serverInfo.TargetInfo != nil {
		if serverInfo.TargetInfo.DnsDomainName != nil && *serverInfo.TargetInfo.DnsDomainName != "" {
			return *serverInfo.TargetInfo.DnsDomainName
		}
		if serverInfo.TargetInfo.NetbiosDomainName != nil && *serverInfo.TargetInfo.NetbiosDomainName != "" {
			return *serverInfo.TargetInfo.NetbiosDomainName
		}
	}
	return ""
}

// GetSMBNetbiosDomain extracts NetBIOS domain name from SMB server info
func GetSMBNetbiosDomain(serverInfo *commonprotocolfern.SmbServerInfo) string {
	if serverInfo != nil && serverInfo.TargetInfo != nil && serverInfo.TargetInfo.NetbiosDomainName != nil {
		return *serverInfo.TargetInfo.NetbiosDomainName
	}
	return ""
}

// WindowsBuildMapping maps Windows build numbers to human-readable versions
var WindowsBuildMapping = map[string]string{
	// Windows Server builds (prioritized for server environments)
	"20348": "Windows Server 2022",
	"17763": "Windows Server 2019",
	"14393": "Windows Server 2016",
	"9600":  "Windows Server 2012 R2",
	"9200":  "Windows Server 2012",
	"7601":  "Windows Server 2008 R2 SP1",
	"6002":  "Windows Server 2008 SP2",
	"6001":  "Windows Server 2008 SP1",
	"6000":  "Windows Server 2008",

	// Windows 11 builds
	"22631": "Windows 11 23H2",
	"22621": "Windows 11 22H2",
	"22000": "Windows 11 21H2",

	// Windows 10 builds (client builds that don't conflict with server)
	"19045": "Windows 10 22H2",
	"19044": "Windows 10 21H2",
	"19043": "Windows 10 21H1",
	"19042": "Windows 10 20H2",
	"19041": "Windows 10 2004",
	"18363": "Windows 10 1909",
	"18362": "Windows 10 1903",
	"17134": "Windows 10 1803",
	"16299": "Windows 10 1709",
	"15063": "Windows 10 1703",
	"10586": "Windows 10 1511",
	"10240": "Windows 10 1507",

	// Older Windows versions
	"7600": "Windows 7",
}
