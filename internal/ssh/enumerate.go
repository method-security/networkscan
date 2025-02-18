package ssh

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
	"unicode"

	sshFern "github.com/Method-Security/networkscan/generated/go/ssh"
	"golang.org/x/crypto/ssh"
)

var (
	// Key Exchange Algorithms mapped to their enum values
	commonKeyExchangeAlgos = map[string]sshFern.KeyExchangeAlgorithm{
		"sntrup761x25519-sha512@openssh.com":   sshFern.KeyExchangeAlgorithmSntrup761X25519Sha512Openssh,
		"curve25519-sha256":                    sshFern.KeyExchangeAlgorithmCurve25519Sha256,
		"curve25519-sha256@libssh.org":         sshFern.KeyExchangeAlgorithmCurve25519Sha256Libssh,
		"ecdh-sha2-nistp256":                   sshFern.KeyExchangeAlgorithmEcdhsha2Nistp256,
		"ecdh-sha2-nistp384":                   sshFern.KeyExchangeAlgorithmEcdhsha2Nistp384,
		"ecdh-sha2-nistp521":                   sshFern.KeyExchangeAlgorithmEcdhsha2Nistp521,
		"ecdh-sha2-nistp224":                   sshFern.KeyExchangeAlgorithmEcdhsha2Nistp224,
		"diffie-hellman-group-exchange-sha256": sshFern.KeyExchangeAlgorithmDiffiehellmangroupexchangesha256,
		"diffie-hellman-group-exchange-sha512": sshFern.KeyExchangeAlgorithmDiffiehellmangroupexchangesha512,
		"diffie-hellman-group16-sha512":        sshFern.KeyExchangeAlgorithmDiffiehellmangroup16Sha512,
		"diffie-hellman-group18-sha512":        sshFern.KeyExchangeAlgorithmDiffiehellmangroup18Sha512,
		"diffie-hellman-group14-sha256":        sshFern.KeyExchangeAlgorithmDiffiehellmangroup14Sha256,
		"diffie-hellman-group14-sha512":        sshFern.KeyExchangeAlgorithmDiffiehellmangroup14Sha512,
		"diffie-hellman-group1-sha1":           sshFern.KeyExchangeAlgorithmDiffiehellmangroup1Sha1, // Deprecated
		"diffie-hellman-group1-sha256":         sshFern.KeyExchangeAlgorithmDiffiehellmangroup1Sha256,
		"kex-strict-s-v00@openssh.com":         sshFern.KeyExchangeAlgorithmKexstrictsv00Openssh,
		"x25519-sha256@libssh.org":             sshFern.KeyExchangeAlgorithmX25519Sha256Libssh,
		"x448-sha512@openssh.com":              sshFern.KeyExchangeAlgorithmX448Sha512Openssh,
		"curve25519-sha512@openssh.com":        sshFern.KeyExchangeAlgorithmCurve25519Sha512Openssh,
	}

	// Host Key Algorithms mapped to their enum values
	commonHostKeyAlgos = map[string]sshFern.HostKeyAlgorithm{
		"ssh-dss":             sshFern.HostKeyAlgorithmSshdss, // Deprecated
		"ssh-rsa":             sshFern.HostKeyAlgorithmSshrsa, // Deprecated (SHA-1)
		"rsa-sha2-256":        sshFern.HostKeyAlgorithmRsasha2256,
		"rsa-sha2-512":        sshFern.HostKeyAlgorithmRsasha2512,
		"ecdsa-sha2-nistp256": sshFern.HostKeyAlgorithmEcdsasha2Nistp256,
		"ecdsa-sha2-nistp384": sshFern.HostKeyAlgorithmEcdsasha2Nistp384,
		"ecdsa-sha2-nistp521": sshFern.HostKeyAlgorithmEcdsasha2Nistp521,
		"ecdsa-sha2-nistp224": sshFern.HostKeyAlgorithmEcdsasha2Nistp224,
		"ed25519-sha256":      sshFern.HostKeyAlgorithmEd25519Sha256,
	}

	// Cipher Algorithms mapped to their enum values
	commonCiphers = map[string]sshFern.CipherAlgorithm{
		"chacha20-poly1305@openssh.com": sshFern.CipherAlgorithmChacha20Poly1305Openssh,
		"aes128-ctr":                    sshFern.CipherAlgorithmAes128Ctr,
		"aes192-ctr":                    sshFern.CipherAlgorithmAes192Ctr,
		"aes256-ctr":                    sshFern.CipherAlgorithmAes256Ctr,
		"aes128-gcm@openssh.com":        sshFern.CipherAlgorithmAes128Gcmopenssh,
		"aes256-gcm@openssh.com":        sshFern.CipherAlgorithmAes256Gcmopenssh,
		"3des-ede3-cbc":                 sshFern.CipherAlgorithmThreedescbc,
		"aes128-cbc":                    sshFern.CipherAlgorithmAes128Cbc,
		"aes192-cbc":                    sshFern.CipherAlgorithmAes192Cbc,
		"aes256-cbc":                    sshFern.CipherAlgorithmAes256Cbc,
		"blowfish-cbc":                  sshFern.CipherAlgorithmBlowfishcbc,
		"aes128-cbc@openssl.com":        sshFern.CipherAlgorithmAes128Cbcopenssl,
	}

	// MAC Algorithms mapped to their enum values
	commonMACs = map[string]sshFern.MacAlgorithm{
		"umac-1":                        sshFern.MacAlgorithmUmac1,
		"umac-64-etm@openssh.com":       sshFern.MacAlgorithmUmac64Etmopenssh,
		"umac-128-etm@openssh.com":      sshFern.MacAlgorithmUmac128Etmopenssh,
		"hmac-sha2-256-etm@openssh.com": sshFern.MacAlgorithmHmacsha2256Etmopenssh,
		"hmac-sha2-512-etm@openssh.com": sshFern.MacAlgorithmHmacsha2512Etmopenssh,
		"hmac-sha1-etm@openssh.com":     sshFern.MacAlgorithmHmacsha1Etmopenssh,
		"umac-64@openssh.com":           sshFern.MacAlgorithmUmac64Openssh,
		"umac-128@openssh.com":          sshFern.MacAlgorithmUmac128Openssh,
		"hmac-sha2-256":                 sshFern.MacAlgorithmHmacsha2256,
		"hmac-sha2-512":                 sshFern.MacAlgorithmHmacsha2512,
		"hmac-sha1":                     sshFern.MacAlgorithmHmacsha1,
		"hmac-md5":                      sshFern.MacAlgorithmHmacmd5,
		"hmac-ripemd160":                sshFern.MacAlgorithmHmacripemd160,
		"hmac-sha3-256":                 sshFern.MacAlgorithmHmacsha3256,
		"hmac-sha3-512":                 sshFern.MacAlgorithmHmacsha3512,
	}
)

func RunSSHEnumerate(ctx context.Context, targets []string, connectionTimeout int) (sshFern.SshEnumerateReport, error) {
	resource := sshFern.SshEnumerateReport{Targets: targets}
	errors := []string{}

	details := []*sshFern.SshEnumerateDetails{}
	for i, target := range targets {
		log.Printf("[INFO] [%d/%d] Processing target: %s", i+1, len(targets), target)

		// Set a new clock for each target
		targetCtx, targetCancel := context.WithTimeout(ctx, time.Duration(connectionTimeout)*time.Second)
		defer targetCancel()

		detail, err := enumerateTarget(targetCtx, target, connectionTimeout)
		if err != nil {
			if targetCtx.Err() == context.DeadlineExceeded {
				fmt.Printf("[ERROR] Parameter timeout while enumerating %s\n", target)
				errors = append(errors, fmt.Sprintf("Parameter timeout while enumerating %s", target))
			} else {
				fmt.Printf("[ERROR] Error enumerating %s: %v\n", target, err)
				errors = append(errors, err...)
			}
		}
		if detail != nil {
			details = append(details, detail)
		}

		// Check if the context for the current target has been canceled
		if targetCtx.Err() != nil {
			continue
		}
	}

	resource.SshDetails = details
	resource.Errors = errors
	return resource, nil
}

// enumerateTarget connects to the target and extracts SSH details.
func enumerateTarget(ctx context.Context, target string, timeout int) (*sshFern.SshEnumerateDetails, []string) {
	var details sshFern.SshEnumerateDetails
	details.Target = target
	errors := []string{}

	// Create dialer with context
	// Use lower level package to gather a complete set of data across a range of SSH instances
	dialer := net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Get SSH Banner
	version, versionASCII, err := getSSHVersion(conn)
	if err != nil {
		errors = append(errors, err.Error())
	}
	details.Version = version

	// Perform SSH handshake to extract KEX data
	rawASCII, err := getSSHAlgorithms(conn)
	if err != nil {
		errors = append(errors, err.Error())
	} else {
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
			details.AuthMethods = []sshFern.AuthMethod{sshFern.AuthMethodPublickey}
		}
	}

	// Check if password authentication is supported
	// Use x/crypto/ssh library to check if password authentication is supported
	passwordSupported, err := passwordAuthSupported(target, timeout)
	if err != nil {
		errors = append(errors, err.Error())
	}
	if passwordSupported != nil && *passwordSupported {
		details.AuthMethods = append(details.AuthMethods, sshFern.AuthMethodPassword)
	}

	err = conn.Close()
	if err != nil {
		errors = append(errors, err.Error())
	}

	return &details, errors
}

// getSSHVersion retrieves the SSH version string from the server.
func getSSHVersion(conn net.Conn) (*string, *string, error) {
	clientVersion := "SSH-2.0-GoSSHScanner\r\n"
	_, err := conn.Write([]byte(clientVersion))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send SSH version string: %w", err)
	}

	buf := make([]byte, 255)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read SSH version string: %w", err)
	}

	returnedASCII := strings.TrimSpace(string(buf[:n]))
	fmt.Printf("[INFO] SSH Server Version: %s\n", returnedASCII)

	version := extractSSHVersion(returnedASCII)

	return version, &returnedASCII, nil
}

func extractSSHVersion(handshake string) *string {
	start := strings.Index(handshake, "SSH-")
	if start == -1 {
		return nil
	}
	version := handshake[start:]

	// Clean up version string
	version = strings.TrimRight(version, "\r\n\u0000")
	return &version
}

// getSSHAlgorithms performs a partial SSH handshake and extracts the raw ASCII response.
func getSSHAlgorithms(conn net.Conn) (string, error) {
	// Key Exchange Init Handshake
	kexinitPayload := []byte{
		0x14, 0x00, 0x00, 0x00, 0x0C, 's', 's', 'h', '-', '2', '.', '0', '-', 'G', 'o',
	}
	_, err := conn.Write(kexinitPayload)
	if err != nil {
		return "", fmt.Errorf("failed to send SSH KEXINIT: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read KEX response: %w", err)
	}

	rawASCII := bytesToASCII(buf[:n])
	fmt.Printf("[DEBUG] Raw SSH Handshake Response (ASCII):\n%s\n", rawASCII)

	return rawASCII, nil
}

func bytesToASCII(data []byte) string {
	var asciiStr strings.Builder
	for _, b := range data {
		if unicode.IsPrint(rune(b)) {
			asciiStr.WriteByte(b)
		} else {
			asciiStr.WriteString(".")
		}
	}
	return asciiStr.String()
}

// extractAlgorithms scans raw SSH data and extracts known algorithms using a dictionary.
func extractAlgorithms[T any](rawData string, knownAlgos map[string]T) []T {
	var foundAlgos []T
	for key, algo := range knownAlgos {
		// Dont want to return keys that are subset of other keys
		// ie. "diffie-hellman-group14-sha1" is a subset of "diffie-hellman-group14-sha128")
		if strings.Contains(rawData, key+",") {
			foundAlgos = append(foundAlgos, algo)
		} else if strings.Contains(rawData, key+".") {
			foundAlgos = append(foundAlgos, algo)
		}
	}
	return foundAlgos
}

// passwordAuthSupported performs a password fallback check on the target.
func passwordAuthSupported(target string, timeout int) (*bool, error) {
	log.Printf("[INFO] Starting passwordAuthSupported check for target: %s", target)

	// SSH client configuration
	config := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
	}

	// Attempt to dial the target
	log.Printf("[INFO] Attempting to connect to %s", target)
	client, err := ssh.Dial("tcp", target, config)
	if err != nil {
		// Check if the error contains "no supported methods remain"
		if strings.Contains(err.Error(), "no supported methods remain") && strings.Contains(err.Error(), "password") {
			log.Printf("[ERROR] %s", err.Error()) // Log the error message for debugging
			fallback := true
			return &fallback, fmt.Errorf("password support but username/password not correct for %s: %w", target, err)
		}
		log.Printf("[ERROR] %s", err.Error()) // Log other errors
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}

	// Create a new session
	session, err := client.NewSession()
	if err != nil {
		log.Printf("[ERROR] Error creating session for %s: %s", target, err.Error())
		return nil, fmt.Errorf("failed to create session for %s: %w", target, err)
	}

	// Run a simple command to test password authentication
	log.Printf("[INFO] Running a simple command on %s to test password authentication", target)
	err = session.Run("true")
	if err != nil {
		log.Printf("[ERROR] Password authentication failed for %s: %s", target, err.Error())
		return nil, fmt.Errorf("password authentication failed for %s: %w", target, err)
	}

	// Close the session and client
	err = client.Close()
	if err != nil {
		log.Printf("[ERROR] Failed to close client for %s: %s", target, err.Error())
		return nil, fmt.Errorf("failed to close client for %s: %w", target, err)
	}

	err = session.Close()
	if err != nil {
		log.Printf("[ERROR] Failed to close session for %s: %s", target, err.Error())
		return nil, fmt.Errorf("failed to close session for %s: %w", target, err)
	}

	// If no errors, it means password authentication is supported
	fallback := true
	log.Printf("[INFO] Password authentication supported for %s", target)
	return &fallback, nil
}
