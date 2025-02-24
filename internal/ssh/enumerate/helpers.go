package ssh

import (
	"fmt"
	"log"
	"net"
	"strings"
	"unicode"

	ssh "golang.org/x/crypto/ssh"
)

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
		if strings.Contains(rawData, key+",") {
			foundAlgos = append(foundAlgos, algo)
		} else if strings.Contains(rawData, key+".") {
			foundAlgos = append(foundAlgos, algo)
		}
	}
	return foundAlgos
}

// passwordAuthSupported performs a password fallback check on the target.
func passwordAuthSupported(target string) (*bool, error) {
	log.Printf("[INFO] Starting passwordAuthSupported check for target: %s", target)

	config := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	log.Printf("[INFO] Attempting to connect to %s", target)
	client, err := ssh.Dial("tcp", target, config)
	if err != nil {
		if strings.Contains(err.Error(), "no supported methods remain") && strings.Contains(err.Error(), "password") {
			log.Printf("[ERROR] %s", err.Error())
			fallback := true
			return &fallback, fmt.Errorf("password support but username/password not correct for %s: %w", target, err)
		}
		log.Printf("[ERROR] %s", err.Error())
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}

	session, err := client.NewSession()
	if err != nil {
		log.Printf("[ERROR] Error creating session for %s: %s", target, err.Error())
		return nil, fmt.Errorf("failed to create session for %s: %w", target, err)
	}

	log.Printf("[INFO] Running a simple command on %s to test password authentication", target)
	err = session.Run("true")
	if err != nil {
		log.Printf("[ERROR] Password authentication failed for %s: %s", target, err.Error())
		return nil, fmt.Errorf("password authentication failed for %s: %w", target, err)
	}

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

	fallback := true
	log.Printf("[INFO] Password authentication supported for %s", target)
	return &fallback, nil
}
