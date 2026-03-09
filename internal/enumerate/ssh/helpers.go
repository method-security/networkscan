package ssh

import (
	// Standard
	"context"
	"fmt"
	"net"
	"strings"
	"unicode"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	ssh "golang.org/x/crypto/ssh"
)

// getSSHVersion retrieves the SSH version string from the server.
func getSSHVersion(ctx context.Context, conn net.Conn) (*string, *string, error) {
	// Initialize
	log := svc1log.FromContext(ctx)

	clientVersion := "SSH-2.0-GoSSHScanner\r\n"
	_, err := conn.Write([]byte(clientVersion))
	if err != nil {
		log.Error("Failed to send SSH version string", svc1log.SafeParam("error", err))
		return nil, nil, fmt.Errorf("failed to send SSH version string: %w", err)
	}

	buf := make([]byte, 255)
	n, err := conn.Read(buf)
	if err != nil {
		log.Error("Failed to read SSH version string", svc1log.SafeParam("error", err))
		return nil, nil, fmt.Errorf("failed to read SSH version string: %w", err)
	}

	returnedASCII := strings.TrimSpace(string(buf[:n]))
	log.Info("SSH Server Version", svc1log.SafeParam("version", returnedASCII))

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
func getSSHAlgorithms(ctx context.Context, conn net.Conn) (string, error) {
	// Initialize
	log := svc1log.FromContext(ctx)

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
	log.Debug("Raw SSH Handshake Response (ASCII)", svc1log.SafeParam("rawASCII", rawASCII))

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
func passwordAuthSupported(ctx context.Context, target string) (*bool, error) {
	// Initialize
	log := svc1log.FromContext(ctx)

	config := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	log.Debug("Attempting to connect to %s", svc1log.SafeParam("target", target))
	client, err := ssh.Dial("tcp", target, config)
	if err != nil {
		if strings.Contains(err.Error(), "no supported methods remain") && strings.Contains(err.Error(), "password") {
			log.Error("Password support but username/password not correct for %s", svc1log.SafeParam("error", err.Error()))
			fallback := true
			return &fallback, fmt.Errorf("password support but username/password not correct for %s: %w", target, err)
		}
		log.Error("Failed to connect to %s", svc1log.SafeParam("error", err.Error()))
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}

	session, err := client.NewSession()
	if err != nil {
		log.Error("Failed to create session for %s", svc1log.SafeParam("error", err.Error()))
		return nil, fmt.Errorf("failed to create session for %s: %w", target, err)
	}

	log.Debug("Running a simple command on %s to test password authentication", svc1log.SafeParam("target", target))
	err = session.Run("true")
	if err != nil {
		log.Error("Password authentication failed for %s", svc1log.SafeParam("error", err.Error()))
		return nil, fmt.Errorf("password authentication failed for %s: %w", target, err)
	}

	err = session.Close()
	if err != nil {
		log.Error("Failed to close session for %s", svc1log.SafeParam("error", err.Error()))
		return nil, fmt.Errorf("failed to close session for %s: %w", target, err)
	}

	err = client.Close()
	if err != nil {
		log.Error("Failed to close client for %s", svc1log.SafeParam("error", err.Error()))
		return nil, fmt.Errorf("failed to close client for %s: %w", target, err)
	}

	fallback := true
	log.Debug("Password authentication supported for %s", svc1log.SafeParam("target", target))
	return &fallback, nil
}
