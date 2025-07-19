package smb

import (
	"context"
	"fmt"
	"log"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	smb "github.com/Method-Security/networkscan/generated/go/enumerate/smb"
	smbclient "github.com/Method-Security/networkscan/internal/protocol/smb"
)

// LibraryEnumerateSMB implements NetworkApplicationLibrary for SMB enumeration using the shared protocol library.
type LibraryEnumerateSMB struct{}

// EnumerateTarget performs comprehensive SMB enumeration using the shared SMB protocol library
func (s *LibraryEnumerateSMB) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details smb.EnumerateSmbDetails
	details.Target = target
	errors := []string{}

	log.Printf("[INFO] Starting SMB enumeration for target: %s", target)

	host, port := extractHostPort(target)
	if port == 0 {
		port = 445 // Default SMB port
	}

	// Create SMB client using shared protocol library
	client := smbclient.NewClient(host, port)
	client.SetNullSession() // Use null session for enumeration

	// Attempt connection
	err := client.Connect()
	if err != nil {
		log.Printf("[ERROR] Failed to connect to %s: %v", target, err)
		errors = append(errors, fmt.Sprintf("Failed to connect to %s: %v", target, err))
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSmbDetails(&details), errors
	}
	defer func() { _ = client.Close() }()

	log.Printf("[INFO] Successfully connected to %s", target)

	// Set SMB version information - using SMB3.0.2 as default
	version := smb.SmbVersionSmb302
	details.Version = &version
	details.SupportedVersions = []smb.SmbVersion{
		smb.SmbVersionSmb302,
		smb.SmbVersionSmb30,
		smb.SmbVersionSmb21,
		smb.SmbVersionSmb20,
	}

	// Get server information from the protocol library
	serverInfo := client.GetServerInfo()
	if serverInfo != nil {
		smbServerInfo := convertToSmbServerInfo(serverInfo)
		details.ServerInfo = smbServerInfo
		log.Printf("[INFO] Extracted server info for %s - Server: %s, Domain: %s, OS: %s",
			target, serverInfo.ServerName, serverInfo.Domain, serverInfo.OSVersion)
	}

	// Enumerate shares using the protocol library
	log.Printf("[INFO] Enumerating shares for %s", target)
	shares, shareErr := client.EnumerateShares()
	if shareErr != nil {
		errors = append(errors, fmt.Sprintf("Share enumeration failed: %v", shareErr))
	}

	if len(shares) > 0 {
		smbShares := convertToSmbShares(shares)
		details.Shares = smbShares
		log.Printf("[INFO] Found %d shares for %s", len(shares), target)

		// Check if this appears to be a domain controller
		if serverInfo != nil && client.DetectDomainController(shares) {
			enhancedOSVersion := serverInfo.OSVersion + " (Domain Controller)"
			smbServerInfo := details.ServerInfo
			if smbServerInfo != nil {
				smbServerInfo.OsVersion = &enhancedOSVersion
			}
		}
	}

	// Set authentication method information
	authMethods := []smb.AuthMethod{smb.AuthMethodNtlm}
	details.AuthMethods = authMethods

	// Set authentication capabilities
	anonymousAllowed := client.IsAuthenticated()
	details.AnonymousLoginAllowed = &anonymousAllowed
	log.Printf("[INFO] Anonymous login allowed for %s: %v", target, anonymousAllowed)

	guestAllowed := false // Will be determined during share enumeration
	details.GuestLoginAllowed = &guestAllowed

	nullSessionAllowed := anonymousAllowed // Typically the same
	details.NullSessionAllowed = &nullSessionAllowed

	// Set security settings from server info
	if serverInfo != nil {
		details.SigningRequired = &serverInfo.SigningRequired
		details.EncryptionSupported = &serverInfo.EncryptionSupported
	}

	// Set raw response information
	rawResponse := fmt.Sprintf("SMB2 Connection - Signing: %v, Encryption: %v",
		serverInfo != nil && serverInfo.SigningRequired,
		serverInfo != nil && serverInfo.EncryptionSupported)
	details.RawResponse = &rawResponse

	log.Printf("[INFO] SMB enumeration completed for %s", target)

	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSmbDetails(&details), errors
}

// convertToSmbServerInfo converts protocol library ServerInfo to fern ServerInfo
func convertToSmbServerInfo(serverInfo *smbclient.ServerInfo) *smb.ServerInfo {
	if serverInfo == nil {
		return nil
	}

	return &smb.ServerInfo{
		ServerName:   &serverInfo.ServerName,
		Domain:       &serverInfo.Domain,
		OsVersion:    &serverInfo.OSVersion,
		Capabilities: serverInfo.Capabilities,
	}
}

// convertToSmbShares converts protocol library ShareInfo to fern SmbShare
func convertToSmbShares(shares []*smbclient.ShareInfo) []*smb.SmbShare {
	var smbShares []*smb.SmbShare

	for _, share := range shares {
		shareType := convertShareType(share.Type)
		shareAccess := convertShareAccess(share.Access)

		smbShare := &smb.SmbShare{
			Name:            share.Name,
			Type:            shareType,
			Accessible:      share.Accessible,
			Access:          &shareAccess,
			AnonymousAccess: share.AnonymousAccess,
			GuestAccess:     share.GuestAccess,
		}

		smbShares = append(smbShares, smbShare)
	}

	return smbShares
}

// convertShareType converts string share type to fern ShareType
func convertShareType(shareType string) smb.ShareType {
	switch shareType {
	case "IPC":
		return smb.ShareTypeIpc
	case "Print":
		return smb.ShareTypePrint
	case "Disk":
		return smb.ShareTypeDisk
	default:
		return smb.ShareTypeDisk
	}
}

// convertShareAccess converts string share access to fern ShareAccess
func convertShareAccess(access string) smb.ShareAccess {
	switch access {
	case "Read":
		return smb.ShareAccessReadOnly
	case "Write", "Full":
		return smb.ShareAccessReadWrite
	default:
		return smb.ShareAccessNoAccess
	}
}
