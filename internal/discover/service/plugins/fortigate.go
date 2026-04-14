// Package plugins provides FortiGate FGFM service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type FortiGateFingerprinter struct{}

func (FortiGateFingerprinter) Name() string { return "fortigate-fgfm" }

// DefaultPorts returns port 541 (FGFM - FortiGate to FortiManager protocol)
func (FortiGateFingerprinter) DefaultPorts() []int { return []int{541} }

func (FortiGateFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Channel to receive the result or error from the goroutine
	resultChan := make(chan *discoverfern.ServiceDetails, 1)
	errorChan := make(chan error, 1)

	// Run the FortiGate detection in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errorChan <- context.DeadlineExceeded
			}
		}()

		result, err := detectFortiGateService(ctx, ip, port, host, timeout)
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
	case <-time.After(time.Duration(timeout) * time.Second):
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// detectFortiGateService performs the actual FortiGate FGFM detection
// FGFM runs over SSL/TLS and responds immediately upon connection with handshake data
// containing Fortinet identifiers in the certificate information
func detectFortiGateService(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Create a dialer with timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Connect to the target
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read deadline
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	// FGFM service responds immediately with SSL/TLS handshake upon connection
	// No need to send any data - just read the response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}

	// Convert response to string for pattern matching
	response := string(buf[:n])

	// Check for Fortinet/FortiGate identifiers in the response
	// These appear in SSL/TLS handshake data or certificate information
	if strings.Contains(strings.ToLower(response), "fortinet") ||
		strings.Contains(strings.ToLower(response), "fortigate") {

		// Build metadata
		vendor := "Fortinet"
		product := "FortiGate"
		managementEnabled := true
		metadata := &protocol.FgfmServerInfo{
			Vendor:            &vendor,
			Product:           &product,
			ManagementEnabled: &managementEnabled,
			Port:              &port,
		}

		// Try to extract additional information from the response
		if strings.Contains(response, "fortinet-ca") {
			ca := "fortinet-ca"
			metadata.CertificateAuthority = &ca
		}
		if strings.Contains(response, "support.fortinet.com") {
			supportDomain := "support.fortinet.com"
			metadata.SupportDomain = &supportDomain
		}

		version := "FortiGate Management Service"
		result := &discoverfern.ServiceDetails{
			Host:      host,
			Ip:        ip.String(),
			Port:      port,
			Tls:       true, // FGFM runs over SSL/TLS
			Transport: common.TransportTypeTcp,
			Protocol:  common.ProtocolTypeFgfm,
			Version:   &version,
			Metadata:  &discoverfern.ServiceMetadata{Fgfm: metadata},
		}

		return result, nil
	}

	// Not a FortiGate FGFM service
	return nil, fmt.Errorf("no FortiGate FGFM service detected")
}
