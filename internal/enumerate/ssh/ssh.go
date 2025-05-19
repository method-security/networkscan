package ssh

import (
	"context"
	"net"

	enumerateFern "github.com/Method-Security/networkscan/generated/go/enumerate"
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

func (s *LibraryEnumerateSSH) EnumerateTarget(ctx context.Context, target string) (*enumerateFern.NetworkApplicationEnumerateDetails, []string) {
	var details ssh.EnumerateSshDetails
	details.Target = target
	errors := []string{}

	// Create dialer with context
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		errors = append(errors, err.Error())
		return enumerateFern.NewNetworkApplicationEnumerateDetailsFromEnumerateSshDetails(&details), errors
	}

	// Get SSH Banner
	version, versionASCII, err := getSSHVersion(conn)
	if err != nil || version == nil {
		errors = append(errors, err.Error())
		return enumerateFern.NewNetworkApplicationEnumerateDetailsFromEnumerateSshDetails(&details), errors
	}
	details.Version = version

	// Perform SSH handshake to extract KEX data
	rawASCII, err := getSSHAlgorithms(conn)
	if err != nil {
		errors = append(errors, err.Error())
		return enumerateFern.NewNetworkApplicationEnumerateDetailsFromEnumerateSshDetails(&details), errors
	}

	fullASCII := rawASCII
	if versionASCII != nil {
		fullASCII = *versionASCII + fullASCII
	}
	details.RawAscii = &fullASCII
	details.KeyExchangeAlgos = extractAlgorithms(fullASCII, commonKeyExchangeAlgos)
	details.HostKeyAlgos = extractAlgorithms(fullASCII, commonHostKeyAlgos)
	details.Ciphers = extractAlgorithms(fullASCII, commonCiphers)
	details.Macs = extractAlgorithms(fullASCII, commonMACs)
	if len(details.HostKeyAlgos) >= 0 {
		details.AuthMethods = []ssh.AuthMethod{ssh.AuthMethodPublickey}
	}

	// Check if password authentication is supported
	passwordSupported, err := passwordAuthSupported(target)
	if err != nil {
		errors = append(errors, err.Error())
	}
	if passwordSupported != nil && *passwordSupported {
		details.AuthMethods = append(details.AuthMethods, ssh.AuthMethodPassword)
	}

	err = conn.Close()
	if err != nil {
		errors = append(errors, err.Error())
	}

	return enumerateFern.NewNetworkApplicationEnumerateDetailsFromEnumerateSshDetails(&details), errors
}
