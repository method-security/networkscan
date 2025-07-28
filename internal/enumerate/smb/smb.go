package smb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	smbfern "github.com/Method-Security/networkscan/generated/go/common/smb"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	smb "github.com/Method-Security/networkscan/generated/go/enumerate/smb"
	smbclient "github.com/Method-Security/networkscan/internal/protocol/smb"
	"github.com/Method-Security/networkscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateSMB implements NetworkApplicationLibrary for SMB enumeration using the shared protocol library.
type LibraryEnumerateSMB struct{}

// EnumerateTarget performs comprehensive SMB enumeration using the shared SMB protocol library
func (s *LibraryEnumerateSMB) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details smb.EnumerateSmbDetails
	details.Target = target
	errors := []string{}

	log := svc1log.FromContext(ctx)
	log.Info("Starting SMB enumeration for target", svc1log.SafeParam("target", target))

	host, portStr, err := net.SplitHostPort(target)
	port := 445 // Default SMB port
	if err == nil {
		// Port was provided, try to parse it
		if p := utils.ParsePort(portStr); p > 0 {
			port = p
		}
	} else {
		// No port provided, use target as host
		host = target
	}

	// Create SMB client using shared protocol library
	client := smbclient.NewClient(host, port)

	// Try multiple connection methods and extract server info from any successful NTLM challenge
	var serverInfo *smbclient.ServerInfo
	var connectionSuccessful bool
	var authAttempts []*smbfern.AuthAttempt

	// Try null session first
	client.SetNullSession()
	err = client.ConnectWithContext(ctx)
	nullSessionAttempt := &smbfern.AuthAttempt{
		Username:  "",
		Password:  "",
		Success:   err == nil,
		Timestamp: time.Now(),
	}
	if err != nil {
		nullSessionAttempt.Message = err.Error()
		log.Debug("Null session connection failed", svc1log.SafeParam("error", err.Error()))

		// Try anonymous connection
		client.SetAnonymous()
		err = client.ConnectWithContext(ctx)
		anonymousAttempt := &smbfern.AuthAttempt{
			Username:  "anonymous",
			Password:  "",
			Success:   err == nil,
			Timestamp: time.Now(),
		}
		if err != nil {
			anonymousAttempt.Message = err.Error()
			log.Debug("Anonymous connection failed", svc1log.SafeParam("error", err.Error()))

			// Try guest connection
			client.SetCredentials("guest", "", "")
			err = client.ConnectWithContext(ctx)
			guestAttempt := &smbfern.AuthAttempt{
				Username:  "guest",
				Password:  "",
				Success:   err == nil,
				Timestamp: time.Now(),
			}
			if err != nil {
				guestAttempt.Message = err.Error()
				log.Debug("Guest connection failed", svc1log.SafeParam("error", err.Error()))

				// Try to extract server info from the failed connection attempts
				// The NTLM challenge should have occurred during the connection attempts
				if client.GetServerInfo() != nil {
					serverInfo = client.GetServerInfo()
					log.Info("Successfully extracted server info from failed connection NTLM challenge",
						svc1log.SafeParam("target", target),
						svc1log.SafeParam("server", serverInfo.ServerName),
						svc1log.SafeParam("domain", serverInfo.Domain),
						svc1log.SafeParam("os", serverInfo.OSVersion))
				}

				// Only add to main errors if this looks like a connectivity issue, not auth failure
				if isConnectivityError(err) {
					errors = append(errors, fmt.Sprintf("Failed to connect to %s: %v", target, err))
					log.Debug("Classified as connectivity error",
						svc1log.SafeParam("target", target),
						svc1log.SafeParam("error", err.Error()),
						svc1log.SafeParam("errorType", fmt.Sprintf("%T", err)))
				} else {
					log.Debug("Classified as authentication error, not adding to main errors",
						svc1log.SafeParam("target", target),
						svc1log.SafeParam("error", err.Error()),
						svc1log.SafeParam("errorType", fmt.Sprintf("%T", err)))
				}
				connectionSuccessful = false
			} else {
				guestAttempt.Message = "Guest login allowed"
				connectionSuccessful = true
				log.Info("Successfully connected with guest credentials", svc1log.SafeParam("target", target))
			}
			authAttempts = append(authAttempts, guestAttempt)
		} else {
			anonymousAttempt.Message = "Anonymous login allowed"
			connectionSuccessful = true
			log.Info("Successfully connected with anonymous credentials", svc1log.SafeParam("target", target))
		}
		authAttempts = append(authAttempts, anonymousAttempt)
	} else {
		nullSessionAttempt.Message = "Null session allowed"
		connectionSuccessful = true
		log.Info("Successfully connected with null session", svc1log.SafeParam("target", target))
	}
	authAttempts = append(authAttempts, nullSessionAttempt)

	if connectionSuccessful {
		defer func() { _ = client.Close() }()
		// Extract server info from successful connection
		serverInfo = client.GetServerInfo()
	}

	// Set SMB version information and server info
	if serverInfo != nil {
		smbServerInfo := convertToSmbServerInfo(serverInfo)
		details.ServerInfo = smbServerInfo
		log.Info("Extracted server info",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("server", serverInfo.ServerName),
			svc1log.SafeParam("domain", serverInfo.Domain),
			svc1log.SafeParam("os", serverInfo.OSVersion),
			svc1log.SafeParam("signingRequired", serverInfo.SigningRequired))

		// Set supported versions from server capabilities if available
		if len(serverInfo.SupportedVersions) > 0 {
			var smbVersions []smb.SmbVersion
			for _, version := range serverInfo.SupportedVersions {
				switch version {
				case "SMB3.0.2":
					smbVersions = append(smbVersions, smb.SmbVersionSmb302)
				case "SMB3.0":
					smbVersions = append(smbVersions, smb.SmbVersionSmb30)
				case "SMB2.1":
					smbVersions = append(smbVersions, smb.SmbVersionSmb21)
				case "SMB2.0":
					smbVersions = append(smbVersions, smb.SmbVersionSmb20)
				}
			}
			if len(smbVersions) > 0 {
				details.SupportedVersions = smbVersions
				// Use the first (highest) supported version as the primary version
				details.Version = &smbVersions[0]
			}
		}
	}

	// Set defaults if server info wasn't available or didn't have version info
	if details.Version == nil {
		version := smb.SmbVersionSmb302
		details.Version = &version
	}
	if len(details.SupportedVersions) == 0 {
		details.SupportedVersions = []smb.SmbVersion{
			smb.SmbVersionSmb302,
			smb.SmbVersionSmb30,
			smb.SmbVersionSmb21,
			smb.SmbVersionSmb20,
		}
	}

	// Enumerate shares using the protocol library (only if we have a successful connection)
	if connectionSuccessful {
		log.Info("Enumerating shares", svc1log.SafeParam("target", target))
		shares, shareErr := client.EnumerateSharesWithContext(ctx)
		if shareErr != nil {
			errors = append(errors, fmt.Sprintf("Share enumeration failed: %v", shareErr))
		}

		if len(shares) > 0 {
			smbShares := convertToSmbShares(shares)
			details.Shares = smbShares
			log.Info("Found shares",
				svc1log.SafeParam("shareCount", len(shares)),
				svc1log.SafeParam("target", target))
		}
	}

	// Set authentication method information
	authMethods := []smb.AuthMethod{smb.AuthMethodNtlm}
	details.AuthMethods = authMethods

	// Set authentication capabilities based on which connection method succeeded
	var nullSessionAllowed, anonymousAllowed, guestAllowed bool

	if connectionSuccessful {
		// Determine which authentication method worked based on client state
		if client.UseNullSession {
			nullSessionAllowed = true
			log.Info("Null session authentication allowed", svc1log.SafeParam("target", target))
		} else if client.UseAnonymous {
			anonymousAllowed = true
			log.Info("Anonymous authentication allowed", svc1log.SafeParam("target", target))
		} else if client.Username == "guest" {
			guestAllowed = true
			log.Info("Guest authentication allowed", svc1log.SafeParam("target", target))
		}
	}

	details.AnonymousLoginAllowed = &anonymousAllowed
	details.GuestLoginAllowed = &guestAllowed
	details.NullSessionAllowed = &nullSessionAllowed

	// Set authentication attempts
	details.AuthAttempts = authAttempts

	// Set security settings from server info
	if serverInfo != nil {
		details.SigningRequired = &serverInfo.SigningRequired
	}

	// Set raw response information
	rawResponse := fmt.Sprintf("SMB2 Connection - Signing: %v",
		serverInfo != nil && serverInfo.SigningRequired)
	details.RawResponse = &rawResponse

	log.Info("SMB enumeration completed", svc1log.SafeParam("target", target))

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

// isConnectivityError determines if an error is a connectivity issue vs authentication failure
// Uses Go's error handling idioms instead of string matching
func isConnectivityError(err error) bool {
	if err == nil {
		return false
	}

	// Check for network-level errors using error types
	var netErr net.Error
	if errors.As(err, &netErr) {
		// Network timeout, connection refused, etc.
		return true
	}

	// Check for syscall errors (connection refused, network unreachable, etc.)
	var syscallErr *net.OpError
	if errors.As(err, &syscallErr) {
		if errno, ok := syscallErr.Err.(syscall.Errno); ok {
			switch errno {
			case syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH,
				syscall.ECONNRESET, syscall.ETIMEDOUT, syscall.ECONNABORTED:
				return true
			}
		}
		// For other OpErrors, check if they're network-related
		return true
	}

	// Check for DNS resolution errors
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	// Check for context deadline exceeded (timeout)
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// For unknown error types, be conservative and don't add to main errors
	// Authentication errors are typically protocol-specific and won't match above patterns
	return false
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
