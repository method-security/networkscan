// Package plugins provides SSH service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/utils"
	"golang.org/x/crypto/ssh"
)

type SSHFingerprinter struct{}

func (SSHFingerprinter) Name() string { return "ssh" }

func (SSHFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Create a context with 10-second timeout
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	addr := fmt.Sprintf("%s:%d", ip, port)

	// Create SSH client config with no auth methods (connection-only)
	config := &ssh.ClientConfig{
		User:            "probe",            // Username for connection (not used for auth)
		Auth:            []ssh.AuthMethod{}, // Empty auth methods - no authentication
		Timeout:         10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Only for service detection
	}

	// Attempt connection to get server info without authentication
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		// Expected - connection will fail due to no auth methods, but we can extract server info
		// Check if the error indicates SSH protocol was detected
		errStr := err.Error()

		// Look for SSH-specific errors that indicate the service is running
		// Be more specific to avoid false positives
		if strings.Contains(errStr, "no supported authentication methods") ||
			strings.Contains(errStr, "unable to authenticate") ||
			strings.Contains(errStr, "attempted methods [none]") ||
			(strings.Contains(errStr, "ssh:") && strings.Contains(errStr, "protocol version")) {

			// SSH service detected - extract any version info from error
			result := &discoverfern.ServiceDetails{
				Host:      host,
				Ip:        ip.String(),
				Port:      port,
				Tls:       false,
				Transport: utils.GetTransportTypeEnum("TCP"),
				Protocol:  utils.GetProtocolTypeEnum("SSH"),
				Metadata: map[string]string{
					"detection":     "ssh_no_auth_handshake",
					"auth_required": "true",
					"error":         errStr,
				},
			}

			return result, nil
		}

		// Not an SSH service or connection failed
		return nil, err
	}

	// If we somehow connected without auth (unusual), SSH is definitely running
	defer func() { _ = client.Close() }()

	// Get server version from successful connection
	serverVersionBytes := client.ServerVersion()
	serverVersion := string(serverVersionBytes)

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: utils.GetTransportTypeEnum("TCP"),
		Protocol:  utils.GetProtocolTypeEnum("SSH"),
		Version:   &serverVersion,
		Metadata: map[string]string{
			"detection":      "ssh_no_auth_success",
			"server_version": serverVersion,
			"authenticated":  "false",
		},
	}

	return result, nil
}
