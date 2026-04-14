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

func (SMBFingerprinter) DefaultPorts() []int { return []int{445, 139} }

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
	if serverInfo != nil && isValidSMBServerInfo(serverInfo) {
		var osVersion, smbVersion, lanmanVersion *string
		var signingRequired *bool
		var netbiosDomain, netbiosComputer, dnsDomain, dnsComputer *string

		// Add available server info
		if serverInfo.GetMappedOsVersion() != nil {
			osVersion = serverInfo.GetMappedOsVersion()
		}

		if serverInfo.GetSmbVersion() != nil {
			v := string(*serverInfo.GetSmbVersion())
			smbVersion = &v
		}

		if serverInfo.GetLanManagerVersion() != nil {
			lanmanVersion = serverInfo.GetLanManagerVersion()
		}

		if serverInfo.GetSigningRequired() != nil {
			signingRequired = serverInfo.GetSigningRequired()
		}

		// Add target info if available
		if origTargetInfo := serverInfo.GetTargetInfo(); origTargetInfo != nil {
			netbiosDomain = origTargetInfo.GetNetbiosDomainName()
			netbiosComputer = origTargetInfo.GetNetbiosComputerName()
			dnsDomain = origTargetInfo.GetDnsDomainName()
			dnsComputer = origTargetInfo.GetDnsComputerName()
		}

		// Build target info for metadata if we have any domain/computer names
		var metadataTargetInfo *commonprotocolfern.NtlmTargetInfo
		if netbiosDomain != nil || netbiosComputer != nil || dnsDomain != nil || dnsComputer != nil {
			metadataTargetInfo = &commonprotocolfern.NtlmTargetInfo{
				NetbiosDomainName:   netbiosDomain,
				NetbiosComputerName: netbiosComputer,
				DnsDomainName:       dnsDomain,
				DnsComputerName:     dnsComputer,
			}
		}

		metadata := &commonprotocolfern.SmbServerInfo{
			MappedOsVersion:   osVersion,
			LanManagerVersion: lanmanVersion,
			SigningRequired:   signingRequired,
			TargetInfo:        metadataTargetInfo,
			OsInfo:            serverInfo.GetOsInfo(),
		}

		// Set SMB version if available
		if smbVersion != nil {
			// Parse the string into SmbVersion enum
			// Map generic versions to most common specific versions
			switch *smbVersion {
			case "SMB1":
				v := commonprotocolfern.SmbVersionSmb1
				metadata.SmbVersion = &v
			case "SMB2":
				// Default to SMB 2.1 as it's the most common SMB2 version
				v := commonprotocolfern.SmbVersionSmb21
				metadata.SmbVersion = &v
			case "SMB2_0", "SMB2.0":
				v := commonprotocolfern.SmbVersionSmb20
				metadata.SmbVersion = &v
			case "SMB2_1", "SMB2.1":
				v := commonprotocolfern.SmbVersionSmb21
				metadata.SmbVersion = &v
			case "SMB3":
				// Default to SMB 3.0 as it's the base SMB3 version
				v := commonprotocolfern.SmbVersionSmb30
				metadata.SmbVersion = &v
			case "SMB3_0", "SMB3.0":
				v := commonprotocolfern.SmbVersionSmb30
				metadata.SmbVersion = &v
			case "SMB3_0_2", "SMB3.0.2":
				v := commonprotocolfern.SmbVersionSmb302
				metadata.SmbVersion = &v
			case "SMB3_1_1", "SMB3.1.1":
				v := commonprotocolfern.SmbVersionSmb311
				metadata.SmbVersion = &v
			}
		}

		result := &discoverfern.ServiceDetails{
			Host:      host,
			Ip:        ip.String(),
			Port:      port,
			Tls:       false,
			Transport: common.TransportTypeTcp,
			Protocol:  common.ProtocolTypeSmb,
			Version:   osVersion,
			Metadata:  &discoverfern.ServiceMetadata{Smb: metadata},
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

	// Create empty metadata since we don't have detailed server info
	metadata := &commonprotocolfern.SmbServerInfo{}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeSmb,
		Metadata:  &discoverfern.ServiceMetadata{Smb: metadata},
	}

	return result, nil
}

// isValidSMBServerInfo validates that the server info contains actual SMB-specific data
func isValidSMBServerInfo(serverInfo *commonprotocolfern.SmbServerInfo) bool {
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
