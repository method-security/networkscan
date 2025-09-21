// Package plugins provides SMB service fingerprinting using the existing SMB client
package plugins

import (
	"context"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	smbclient "github.com/Method-Security/networkscan/internal/protocol/smb"
)

type SMBFingerprinter struct{}

func (SMBFingerprinter) Name() string { return "smb" }

func (SMBFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Channel to receive the result or error from the goroutine
	resultChan := make(chan *discoverfern.ServiceDetails, 1)
	errorChan := make(chan error, 1)

	// Run the SMB detection in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errorChan <- context.DeadlineExceeded
			}
		}()

		result, err := detectSMBService(ctx, ip, port, host)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- result
	}()

	// Wait for either the result, error, or timeout
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	case <-time.After(10 * time.Second):
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// detectSMBService performs the actual SMB detection
func detectSMBService(ctx context.Context, ip net.IP, port int, host string) (*discoverfern.ServiceDetails, error) {
	// Use the existing SMB client for proper SMB detection
	client := smbclient.NewClient(ip.String(), port)
	client.SetChallengeOnly() // Use challenge-only mode for stealth service detection

	// Attempt to connect to test if SMB service is running
	// In challenge-only mode, this will succeed after getting the challenge
	err := client.ConnectWithContext(ctx)

	// For challenge-only mode, we need to validate that we actually got SMB-specific info
	var serverInfo *commonprotocolfern.SmbServerInfo
	if client.GetServerInfo() != nil {
		serverInfo = client.GetServerInfo()
	} else {
		// Try to extract from NTLM challenge
		challengeInfo, challengeErr := client.ExtractServerInfoFromChallenge(ctx)
		if challengeErr == nil {
			serverInfo = challengeInfo
		}
	}

	// Validate that we have actual SMB-specific server information
	if serverInfo != nil && isValidSMBServerInfo(serverInfo, err) {
		// Create successful service detection result
		result := &discoverfern.ServiceDetails{
			Host:      host,
			Ip:        ip.String(),
			Port:      port,
			Tls:       false, // SMB over 445 is not TLS by default
			Transport: common.TransportTypeTcp,
			Protocol:  common.ProtocolTypeSmb,
			Metadata:  map[string]string{"detection": "smb_challenge_only"},
		}

		// Add connection status to metadata
		if err != nil {
			result.Metadata["connection_status"] = "challenge_only_no_auth"
		} else {
			result.Metadata["connection_status"] = "challenge_only_success"
		}

		// Always false in challenge-only mode
		result.Metadata["authenticated"] = "false"

		// Add available server info to metadata and version
		if serverInfo.GetMappedOsVersion() != nil {
			version := *serverInfo.GetMappedOsVersion()
			result.Version = &version
			result.Metadata["os_version"] = version
		}

		if serverInfo.GetSmbVersion() != nil {
			result.Metadata["smb_version"] = string(*serverInfo.GetSmbVersion())
		}

		if serverInfo.GetLanManagerVersion() != nil {
			result.Metadata["lanman_version"] = *serverInfo.GetLanManagerVersion()
		}

		if serverInfo.GetSigningRequired() != nil {
			if *serverInfo.GetSigningRequired() {
				result.Metadata["signing"] = "required"
			} else {
				result.Metadata["signing"] = "not_required"
			}
		}

		// Add target info if available
		if targetInfo := serverInfo.GetTargetInfo(); targetInfo != nil {
			if targetInfo.GetNetbiosDomainName() != nil {
				result.Metadata["netbios_domain"] = *targetInfo.GetNetbiosDomainName()
			}
			if targetInfo.GetNetbiosComputerName() != nil {
				result.Metadata["netbios_computer"] = *targetInfo.GetNetbiosComputerName()
			}
			if targetInfo.GetDnsDomainName() != nil {
				result.Metadata["dns_domain"] = *targetInfo.GetDnsDomainName()
			}
			if targetInfo.GetDnsComputerName() != nil {
				result.Metadata["dns_computer"] = *targetInfo.GetDnsComputerName()
			}
		}

		// Close connection if it was established
		if client.IsConnected() {
			_ = client.Close()
		}

		return result, nil
	}

	// If we can't extract server info and the connection failed, it's likely not SMB
	if err != nil {
		return nil, err
	}

	// Connection succeeded but no server info - still report as detected SMB
	defer func() { _ = client.Close() }()

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeSmb,
		Metadata:  map[string]string{"detection": "smb_client_connection"},
	}

	if client.IsAuthenticated() {
		result.Metadata["authenticated"] = "true"
	} else {
		result.Metadata["authenticated"] = "false"
	}

	return result, nil
}

// isValidSMBServerInfo validates that the server info contains actual SMB-specific data
func isValidSMBServerInfo(serverInfo *commonprotocolfern.SmbServerInfo, connErr error) bool {
	if serverInfo == nil {
		return false
	}

	// Simple and elegant: SMB services will have DNS computer name in NTLM target info
	// Other services (like LDAP) won't provide this SMB-specific information
	if targetInfo := serverInfo.GetTargetInfo(); targetInfo != nil {
		if targetInfo.GetDnsComputerName() != nil {
			return true
		}
	}

	return false
}
