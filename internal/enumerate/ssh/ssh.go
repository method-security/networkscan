package ssh

import (
	"context"
	"net"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	ssh "github.com/Method-Security/networkscan/generated/go/enumerate/ssh"
)

// LibraryEnumerateSSH implements NetworkApplicationLibrary for SSH enumeration.
type LibraryEnumerateSSH struct{}

// EnumerateTarget Overview:
// 1. Connect to the target
//   a. Exit if connection isnt established
// 2. Check if service supports SSH + Grab the SSH version
//   a. Exit if no version is returned (assume SSH is not implemented)
// 3. Grab the SSH algorithms from returned data
//   a. Key Exchange Algorithms
//   b. Host Key Algorithms
//   c. Ciphers
//   d. MACs
// 4. Check if password authentication is supported via x/crypto/ssh library
//   a. Send a simple command with test:test username and password
//   b. Analyse errors to check if password authentication is supported
// 5. Return the details
//   a. Version
//   b. Key Exchange Algorithms
//   c. Host Key Algorithms
//   d. Ciphers
//   e. MACs
//   f. Auth Methods (Public Key, Password)

func (s *LibraryEnumerateSSH) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details ssh.EnumerateSshDetails
	var serverInfo commonprotocolfern.SshServerInfo
	serverInfo.Target = &target
	errors := []string{}

	// Create dialer with context
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		errors = append(errors, err.Error())
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSshDetails(&details), errors
	}
	defer func() { _ = conn.Close() }()

	// Get SSH Banner
	version, versionASCII, err := getSSHVersion(ctx, conn)
	if err != nil {
		errors = append(errors, err.Error())
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSshDetails(&details), errors
	}
	if version == nil {
		errors = append(errors, "SSH version is nil")
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSshDetails(&details), errors
	}
	serverInfo.ServerVersion = version

	// Perform SSH handshake to extract KEX data
	rawASCII, err := getSSHAlgorithms(ctx, conn)
	if err != nil {
		errors = append(errors, err.Error())
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSshDetails(&details), errors
	}

	fullASCII := rawASCII
	if versionASCII != nil {
		fullASCII = *versionASCII + fullASCII
	}
	serverInfo.RawAscii = &fullASCII
	serverInfo.SupportedKex = extractAlgorithms(fullASCII, commonKeyExchangeAlgos)
	serverInfo.HostKeyAlgos = extractAlgorithms(fullASCII, commonHostKeyAlgos)
	serverInfo.SupportedCiphers = extractAlgorithms(fullASCII, commonCiphers)
	serverInfo.SupportedMacs = extractAlgorithms(fullASCII, commonMACs)
	if len(serverInfo.HostKeyAlgos) > 0 {
		serverInfo.SupportedAuthMethods = []commonprotocolfern.SshAuthMethod{commonprotocolfern.SshAuthMethodPublicKey}
	}

	// Check if password authentication is supported
	passwordSupported, err := passwordAuthSupported(ctx, target)
	if err != nil {
		errors = append(errors, err.Error())
	}
	if passwordSupported != nil && *passwordSupported {
		serverInfo.SupportedAuthMethods = append(serverInfo.SupportedAuthMethods, commonprotocolfern.SshAuthMethodPassword)
	}

	// Set the server info in the details
	details.ServerInfo = &serverInfo

	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSshDetails(&details), errors
}
